# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""The real threaded HTTP server (MCPServer / _MCPHTTPServer on 127.0.0.1:<ephemeral>) with fake views.

Lock modes (for the legacy /decompile route AND the routes behind the bn_* tools that MCP clients call concurrently:
GET /x/decompile, GET /x/handlerSlice, POST /x/batch, and a mixed explicit + legacy request list), lock order, bounded
waits (503 BUSY), legacy unbounded queueing, health paths, bind policy, POST routes, non-ASCII headers and 410 GONE
behind a close.

What the lock-mode tests can see: the fake's ACTIVITY counter sees only Function.hlil work. _BnProbe (test-local; the
fake module is unchanged) adds the analysis_state / analysis_progress reads and a FileMetadata.raw stand-in, and
records for each of them whether the reading request held its lock. http_server._dispatch LOCATES the binary
(registry facts only), takes the lock, and only then describes it (describe_view: the analysis state and the
FileMetadata.raw hash), so every probed touchpoint must run with the request lock held: check_probe allows none
outside it, and test_every_instrumented_bn_read_holds_the_request_lock is the full-serialization contract on the
probed touchpoints (an earlier version resolved the binary before taking the lock; a regression FAILS here, it is
never skipped). BinaryView.start (the 409 AMBIGUOUS candidates) is probed only by
test_ambiguous_candidates_read_their_start_under_each_view_lock. What no probe sees (FileMetadata.filename and the
other plain fake attributes the registry reads) is not shown.
"""

import collections
import concurrent.futures
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

import run_tests as H

# One concurrent request of the lock-mode tests: the view it must be answered from (for a request without `binary`,
# the global view the server falls back to), the HTTP method, the path, the query parameters and an optional JSON body.
_Job = collections.namedtuple('_Job', 'view method path params body')

# The route shapes the lock-mode tests drive, with the query parameters each one gets besides `binary`.
_ROUTE_PARAMS = {'/decompile': {'name': 'main'},
                 '/x/decompile': {'function': 'main', 'il': 'hlil'},
                 '/x/handlerSlice': {'function': 'main', 'depth': '1'},
                 '/x/batch': {}}
_X_VERBS = {'/x/decompile': 'decompile', '/x/handlerSlice': 'handler_slice', '/x/batch': 'batch'}
_BATCH_ITEMS = [{'verb': 'decompile', 'params': {'function': 'main'}},
                {'verb': 'decompile', 'params': {'function': 'leaf'}}]
# The fewest fake Binary Ninja work entries (Function.hlil -> ACTIVITY) one request of the route makes.
_MIN_ENTRIES = {'/decompile': 1, '/x/decompile': 1, '/x/handlerSlice': 1, '/x/batch': len(_BATCH_ITEMS)}


def _job(view, path, explicit=True):
    """A request of route `path` for `view`; explicit=False omits `binary` (a legacy request: the global view)."""
    params = dict(_ROUTE_PARAMS[path])
    if explicit:
        params['binary'] = view.file.filename
    if path == '/x/batch':
        return _Job(view, 'POST', path, params, {'items': _BATCH_ITEMS})
    return _Job(view, 'GET', path, params, None)


# _BnProbe vocabulary. A request runs in a frame named _dispatch (http_server.MCPRequestHandler: it locates the binary,
# takes the lock, describes the binary, then runs the impl); its impl runs in one of _IMPL_FRAMES. _METADATA_READS are
# the probed reads describe_view makes before the impl (analysis_summary and the view_sha256 -> _loaded_content_sha
# raw hash).
_DISPATCH_FRAME = '_dispatch'
_IMPL_FRAMES = frozenset({'_do_GET_impl', '_do_POST_impl'})
_FUNCTION_WORK = 'Function work'
_METADATA_READS = frozenset({'BinaryView.analysis_state', 'BinaryView.analysis_progress', 'FileMetadata.raw',
                             'FileMetadata.raw.length', 'FileMetadata.raw.start', 'FileMetadata.raw.read'})
# One probed touchpoint reached from a request: what, the view's ACTIVITY key, whether the reading thread held the
# view's request lock, and whether it ran inside the request's impl.
_Op = collections.namedtuple('_Op', 'what key locked in_impl')


def _outside_lock(ops):
    """The recorded ops that ran WITHOUT the request lock (none is allowed: not Function work, not an impl read, and
    not one of the _METADATA_READS describe_view makes before the impl)."""
    return [o for o in ops if not o.locked]


def _what_counts(ops):
    return dict(sorted(collections.Counter(o.what for o in ops).items()))


class _ProbedRaw(object):
    """FileMetadata.raw stand-in (Binary Ninja: the file's Raw view): the on-disk bytes; every access is probed."""

    def __init__(self, probe, view, data):
        self._p, self._v, self._data = probe, view, bytes(data)

    @property
    def length(self):
        return self._p.op(self._v, 'FileMetadata.raw.length', lambda: len(self._data), 0.0)

    @property
    def start(self):
        return self._p.op(self._v, 'FileMetadata.raw.start', lambda: 0, 0.0)

    def read(self, addr, length):
        a, n = int(addr), int(length)
        return self._p.op(self._v, 'FileMetadata.raw.read', lambda: self._data[a:a + n] if (a >= 0 and n > 0) else b'')


class _BnProbe(object):
    """Test-local instrumentation of fake views' Binary Ninja touchpoints (the fake module itself is unchanged).

    Probed: Function work (BinaryView._tick, which Function.hlil enters), the BinaryView.analysis_state and
    analysis_progress reads, and FileMetadata.raw (a _ProbedRaw of the file's bytes: the raw property, its length /
    start and read()), whose presence also makes the plugin hash the loaded bytes in _loaded_content_sha as it does
    with real Binary Ninja (once per file session, so the first requests hash).
    NOT probed (plain attributes in the fake): FileMetadata.filename / original_filename, BinaryView.start and the
    other view attributes the plugin reads. A claim built on this probe covers only the touchpoints above.

    A touchpoint reached from a request (a _dispatch frame on the stack) is recorded as an _Op: locked = the reading
    thread holds the lock _dispatch takes for that view (ops.view_lock(view id): the one global RLock in global mode,
    the view's own RLock in per-view mode); in_impl = it runs inside the impl. It also enters self.activity (a fresh
    fake Activity, never the module ACTIVITY) for its duration, dwell_s longer for analysis_state, analysis_progress
    and raw.read so overlaps are observable. Touchpoints reached outside a request (the test thread's own
    describe_view in check_echo) are neither recorded nor entered; self.ticks counts EVERY Function work tick, in a
    request or not, so a test can check that the probe saw every tick the module ACTIVITY counted.
    """

    def __init__(self, activity, dwell_s=0.0):
        self.activity = activity
        self.dwell_s = float(dwell_s)
        self._mu = threading.Lock()
        self._ops = []
        self.ticks = 0
        self._lock_of = {}
        self._orig = {}

    def reset(self):
        self.activity.reset()
        with self._mu:
            del self._ops[:]
            self.ticks = 0

    def records(self):
        with self._mu:
            return list(self._ops)

    def op(self, view, what, inner, dwell_s=None):
        names = set()
        f = sys._getframe(1)
        while f is not None:
            names.add(f.f_code.co_name)
            f = f.f_back
        if what == _FUNCTION_WORK:
            with self._mu:
                self.ticks += 1
        if _DISPATCH_FRAME not in names:
            return inner()
        rec = _Op(what, view.key, bool(self._lock_of[view.key]._is_owned()), bool(names & _IMPL_FRAMES))
        with self._mu:
            self._ops.append(rec)
        d = self.dwell_s if dwell_s is None else float(dwell_s)
        self.activity.enter(view.key)
        try:
            out = inner()
            if d > 0:
                time.sleep(d)
            return out
        finally:
            self.activity.leave(view.key)

    def attach(self, view, lock):
        """Probe `view` (its class and its FileMetadata's class become probing subclasses); `lock` is the RLock its
        requests must hold."""
        probe = self
        vcls, fcls = type(view), type(view.file)
        with open(view.file.filename, 'rb') as fh:
            raw = _ProbedRaw(self, view, fh.read())

        def _attr(name):
            def get(self_):
                return probe.op(self_, 'BinaryView.' + name, lambda: self_.__dict__[name])

            def put(self_, value):
                self_.__dict__[name] = value
            return property(get, put)

        def _tick(self_):
            return probe.op(self_, _FUNCTION_WORK, lambda: vcls._tick(self_), 0.0)

        self._lock_of[view.key] = lock
        self._orig[view.key] = (vcls, fcls)
        view.__class__ = type(vcls.__name__, (vcls,), {
            '__module__': vcls.__module__, '_tick': _tick,
            'analysis_state': _attr('analysis_state'), 'analysis_progress': _attr('analysis_progress')})
        view.file.__class__ = type(fcls.__name__, (fcls,), {
            '__module__': fcls.__module__,
            'raw': property(lambda _f: probe.op(view, 'FileMetadata.raw', lambda: raw, 0.0))})

    def detach(self, view):
        vcls, fcls = self._orig.pop(view.key, (None, None))
        if vcls is not None:
            view.__class__ = vcls
        if fcls is not None:
            view.file.__class__ = fcls


class _HttpBase(unittest.TestCase):
    def setUp(self):
        self.m = H.plugin_modules()
        H.reset_plugin_state(self.m)
        self.fb = H.fake_bv()
        self.td = tempfile.TemporaryDirectory(prefix='bnmcp-http-')
        self.addCleanup(self.td.cleanup)
        self.views = []

    def view(self, sub, basename='foo.dll', tag='A', delay_s=0.0):
        v = H.make_view(os.path.join(self.td.name, sub), basename, tag, delay_s)
        self.views.append(v)
        return v

    def server(self, **cfg):
        s = H.Server(self.m, **cfg)
        s.start()
        self.addCleanup(s.stop)
        return s

    def two_view_server(self, delay_s, prefix='', **cfg):
        a = self.view(prefix + 'a', 'foo.dll', 'A', delay_s)
        b = self.view(prefix + 'b', 'foo.dll', 'B', delay_s)
        s = self.server(**cfg)
        s.ops.register_view(a)
        s.ops.register_view(b)
        s.ops.current_view = a
        return s, a, b

    def instrument(self, srv, views, dwell_s=0.0):
        """A _BnProbe on `views` (their classes are restored at cleanup). Call it after the views are registered and
        BEFORE their first scoped request, so the first request of each file session hashes FileMetadata.raw."""
        probe = _BnProbe(self.fb.Activity(), dwell_s)
        for v in views:
            lock = srv.ops.view_lock(srv.ops.describe_view(v, 'explicit')['view_id'])
            self.assertTrue(callable(getattr(lock, '_is_owned', None)),
                            'the view lock %r has no _is_owned(); _BnProbe cannot tell locked reads' % (lock,))
            probe.attach(v, lock)
            self.addCleanup(probe.detach, v)
        return probe

    def check_probe(self, probe, jobs, act_snap):
        """Probe facts every lock mode must meet: no probed touchpoint ran outside the request lock (_outside_lock:
        neither the impl's work nor describe_view's metadata reads before it), the probe saw every Function.hlil tick
        ACTIVITY counted, and every request sampled analysis_state under its lock. Returns the probe's records."""
        ops = probe.records()
        bad = collections.Counter('%s (%s)' % (o.what, 'impl' if o.in_impl else 'before the impl')
                                  for o in _outside_lock(ops))
        self.assertEqual(dict(bad), {}, 'Binary Ninja work outside the request lock')
        self.assertEqual(probe.ticks, act_snap['entries'], _what_counts(ops))
        self.assertGreaterEqual(sum(1 for o in ops if o.what == 'BinaryView.analysis_state' and o.locked), len(jobs),
                                _what_counts(ops))
        return ops

    def fire_jobs(self, srv, jobs, workers=40, timeout=60.0):
        """jobs: [_Job] -> [(_Job, Resp)] in job order, all sent concurrently."""
        def one(job):
            return job, H.http_request(srv.port, job.method, job.path, job.params, json_body=job.body,
                                       timeout=timeout)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            return list(ex.map(one, jobs))

    def fire(self, srv, jobs, workers=40, timeout=60.0):
        """jobs: [(view, params)] -> [(view, Resp)] in job order: concurrent GET /decompile requests."""
        out = self.fire_jobs(srv, [_Job(v, 'GET', '/decompile', params, None) for v, params in jobs],
                             workers, timeout)
        return [(job.view, r) for job, r in out]

    def route_cases(self, a, b, n=40):
        """[(name, [_Job])]: n concurrent requests per route shape, alternating views A and B; then the mixed list."""
        def alt(k):
            return a if k % 2 == 0 else b
        cases = [('%s %s' % ('POST' if p == '/x/batch' else 'GET', p), [_job(alt(k), p) for k in range(n)])
                 for p in ('/decompile', '/x/decompile', '/x/handlerSlice', '/x/batch')]
        cases.append(('mixed explicit + legacy', self.mixed_jobs(a, b, n)))
        return cases

    def mixed_jobs(self, a, b, n=40):
        """n interleaved requests: explicit ones on A and B over every route shape, and legacy ones (no `binary`) on
        /decompile and /x/decompile, which the server answers from the global view A."""
        kinds = (('/x/decompile', True), ('/decompile', False), ('/x/batch', True), ('/x/decompile', False),
                 ('/x/handlerSlice', True), ('/decompile', True))
        out = []
        for k in range(n):
            path, explicit = kinds[k % len(kinds)]
            v = (a if (k // len(kinds)) % 2 == 0 else b) if explicit else a
            out.append(_job(v, path, explicit))
        return out

    def tagged_text(self, job, js):
        """The decompiled text of `main` in an answer (where the fake's tagcheck("<tag>") marker lives)."""
        if job.path == '/decompile':
            return js['decompiled']
        res = js['result']
        if job.path == '/x/decompile':
            return res['text']
        if job.path == '/x/handlerSlice':
            return res['pack_text']
        if job.path == '/x/batch':                          # every item ran, in order, and answered ok
            items = res['items']
            self.assertEqual([(it.get('index'), it.get('ok')) for it in items],
                             [(i, True) for i in range(len(_BATCH_ITEMS))], items)
            return '\n'.join(it['result']['text'] for it in items)
        self.fail('no text extractor for %s' % job.path)

    def check_echo(self, v, r, srv, job=None):
        """r is a 200 answer from view v: the _binary echo and the X-BN-Binary header name v, and the text is v's."""
        job = job or _Job(v, 'GET', '/decompile', {'binary': v.file.filename}, None)
        explicit = 'binary' in job.params
        self.assertEqual(r.status, 200, r.raw[:400])
        echo = r.json['_binary']
        self.assertEqual(echo['filename'], v.file.filename)
        self.assertEqual(echo['view_id'], srv.ops.describe_view(v, 'explicit')['view_id'])
        self.assertEqual(echo['resolved_by'], 'explicit' if explicit else 'global')
        self.assertEqual(echo['analysis_state'], 'IdleState')
        self.assertEqual(bool(r.json.get('binary_defaulted')), (not explicit) and srv.ops.open_view_count() > 1,
                         r.raw[:400])
        if job.path in _X_VERBS:
            self.assertEqual((r.json.get('ok'), r.json.get('verb')), (True, _X_VERBS[job.path]), r.raw[:400])
        text = self.tagged_text(job, r.json)
        self.assertIn('tagcheck("%s")' % v.tag, text)
        other = 'B' if v.tag == 'A' else 'A'
        self.assertNotIn('tagcheck("%s")' % other, text)
        self.assertEqual(r.headers.get('x-bn-binary', ''),
                         '%s;%s;%s' % (echo['view_id'], urllib.parse.quote(echo['basename'], safe=''),
                                       echo['binary_id']), r.headers)


class LockModeTests(_HttpBase):
    def test_default_global_mode_serializes_the_locked_request_work(self):
        """Default global mode, per route shape: 40 concurrent requests on views A and B each echo their own binary,
        their Function work (Function.hlil -> ACTIVITY) never overlaps at all (max_total 1, no cross-view overlap),
        and that work and every probed read (inside the impl and describe_view's before it) run with the global lock
        held (check_probe). The shapes are the legacy /decompile route, the routes behind the bn_* tools (GET
        /x/decompile, GET /x/handlerSlice, POST /x/batch) and a mixed explicit + legacy list.
        test_every_instrumented_bn_read_holds_the_request_lock checks that every probed read holds the lock."""
        srv, a, b = self.two_view_server(0.02)
        self.assertEqual(srv.cfg.server.lock_mode, 'global')
        self.assertEqual(srv.ops.lock_mode, 'global')
        st = srv.get('/status').json['server']
        self.assertEqual((st['lock_mode'], st['threaded']), ('global', True))
        self.assertNotIn('threaded_per_view', st['capabilities'])
        self.assertIs(srv.ops.global_view(), a)             # legacy requests (no `binary`) are answered from A
        probe = self.instrument(srv, (a, b))
        for name, jobs in self.route_cases(a, b):
            with self.subTest(route=name):
                self.fb.ACTIVITY.reset()
                probe.reset()
                for job, r in self.fire_jobs(srv, jobs):
                    self.check_echo(job.view, r, srv, job)
                snap = self.fb.ACTIVITY.snapshot()
                self.assertGreaterEqual(snap['entries'], sum(_MIN_ENTRIES[j.path] for j in jobs), snap)
                self.assertEqual(snap['max_total'], 1, snap)
                self.assertEqual(snap['cross_overlap'], [], snap)
                self.check_probe(probe, jobs, snap)

    def test_per_view_mode_no_same_view_overlap_of_locked_work_but_cross_view_overlap(self):
        """per-view mode: Function work (Function.hlil -> ACTIVITY) never overlaps on one view but does overlap across
        A and B, and that work and every probed read (inside the impl and describe_view's before it) run with that
        view's lock held (check_probe; the overlap contract of all probed touchpoints is
        test_every_instrumented_bn_read_holds_the_request_lock)."""
        srv, a, b = self.two_view_server(0.05, lock_mode='per-view', max_inflight=8)
        st = srv.get('/status').json['server']
        self.assertEqual(st['lock_mode'], 'per-view')
        self.assertIn('threaded_per_view', st['capabilities'])
        self.assertIsNot(srv.ops.view_lock('1'), srv.ops.view_lock('2'))
        probe = self.instrument(srv, (a, b))
        self.fb.ACTIVITY.reset()
        jobs = [((a if k % 2 == 0 else b), {'binary': (a if k % 2 == 0 else b).file.filename, 'name': 'main'})
                for k in range(40)]
        for v, r in self.fire(srv, jobs):
            self.check_echo(v, r, srv)
        snap = self.fb.ACTIVITY.snapshot()
        self.assertEqual(snap['max_same'].get(a.key), 1, snap)
        self.assertEqual(snap['max_same'].get(b.key), 1, snap)
        self.assertEqual(snap['cross_overlap'], [tuple(sorted((a.key, b.key)))], snap)
        self.check_probe(probe, jobs, snap)
        # Same-view serialization also holds for the expert routes and for legacy requests on the global view A.
        self.assertIs(srv.ops.global_view(), a)
        self.fb.ACTIVITY.reset()
        probe.reset()
        jobs = self.mixed_jobs(a, b)
        for job, r in self.fire_jobs(srv, jobs):
            self.check_echo(job.view, r, srv, job)
        snap = self.fb.ACTIVITY.snapshot()
        self.assertGreaterEqual(snap['entries'], sum(_MIN_ENTRIES[j.path] for j in jobs), snap)
        self.assertEqual(snap['max_same'].get(a.key), 1, snap)
        self.assertEqual(snap['max_same'].get(b.key), 1, snap)
        self.check_probe(probe, jobs, snap)

    def test_every_instrumented_bn_read_holds_the_request_lock(self):
        """Contract (thread-safe HTTP server): in the default global mode one lock
        serializes ALL Binary Ninja work, and in per-view mode a view's lock covers all Binary Ninja work on that view.
        Measured on the _BnProbe touchpoints from a fresh server, so the first requests also hash FileMetadata.raw:
        40 mixed explicit + legacy requests; every probed touchpoint must run with its request lock held, and none
        may overlap another (global: none at all; per-view: none on the same view).
        Regression guard: an earlier http_server._dispatch resolved the binary
        (ops.resolve_binary / ops.describe_view: analysis_state, analysis_progress and, on a file session's first
        request, the FileMetadata.raw hash) BEFORE it acquired the lock; the suite used to SKIP here with the counts
        (92-112 unlocked reads, up to 19 probed touchpoints at once). _dispatch now locates the binary, locks, then
        describes it: any probed read outside the lock FAILS this test (it is never skipped)."""
        for mode, cfg in (('global', {}), ('per-view', {'lock_mode': 'per-view', 'max_inflight': 8})):
            with self.subTest(lock_mode=mode):
                srv, a, b = self.two_view_server(0.02, prefix=mode + '-', **cfg)
                self.assertEqual(srv.ops.lock_mode, mode)
                probe = self.instrument(srv, (a, b), dwell_s=0.003)
                self.fb.ACTIVITY.reset()
                jobs = self.mixed_jobs(a, b)
                for job, r in self.fire_jobs(srv, jobs):
                    self.check_echo(job.view, r, srv, job)
                ops = self.check_probe(probe, jobs, self.fb.ACTIVITY.snapshot())
                self.assertEqual({o.key for o in ops if o.what == 'FileMetadata.raw.read'}, {a.key, b.key},
                                 'the first requests did not hash FileMetadata.raw: %r' % (_what_counts(ops),))
                snap = probe.activity.snapshot()
                outside = _outside_lock(ops)
                self.assertEqual(outside, [], '%d probed Binary Ninja reads ran outside the request lock %r; overlap '
                                 'of all probed touchpoints max_total=%d max_same=%r: the %s-mode serialization '
                                 'contract is broken' % (len(outside), _what_counts(outside), snap['max_total'],
                                                         sorted(snap['max_same'].values(), reverse=True), mode))
                self.assertGreaterEqual(sum(1 for o in ops if o.what in _METADATA_READS and not o.in_impl), len(jobs),
                                        'apparatus: describe_view made no probed read before the impl: %r'
                                        % (_what_counts(ops),))
                if mode == 'global':
                    self.assertEqual(snap['max_total'], 1, snap)
                    self.assertEqual(snap['cross_overlap'], [], snap)
                else:
                    self.assertEqual(snap['max_same'].get(a.key), 1, snap)
                    self.assertEqual(snap['max_same'].get(b.key), 1, snap)

    def test_lock_order_waiters_on_one_view_do_not_starve_another_view(self):
        """per-view: while one request holds view A (blocked inside Binary Ninja work) and 8 more queue on A, a request
        on view B must still be served: the view lock is taken BEFORE the in-flight slot (8 slots), so requests queued
        on A hold no slot. With the opposite order the 9 A requests would hold all 8 slots and B would wait."""
        a = self.view('a', 'foo.dll', 'A')
        b = self.view('b', 'bar.dll', 'B')
        a.gate = threading.Event()
        self.addCleanup(a.gate.set)
        srv = self.server(lock_mode='per-view', max_inflight=8, lock_wait_s=60.0, inflight_wait_s=60.0)
        srv.ops.register_view(a)
        srv.ops.register_view(b)
        with concurrent.futures.ThreadPoolExecutor(max_workers=9) as ex:
            futs = [ex.submit(srv.get, '/decompile', {'binary': a.file.filename, 'name': 'main'}, timeout=90)
                    for _ in range(9)]
            time.sleep(0.6)                                 # one A request is inside the gate, eight wait for A
            self.assertFalse(any(f.done() for f in futs))
            try:
                rb = srv.get('/decompile', {'binary': b.file.filename, 'name': 'main'}, timeout=5)
                b_error = None
            except OSError as e:                            # socket.timeout included
                rb, b_error = None, e
            gate_was_closed = not a.gate.is_set()
            a.gate.set()
            a_results = [f.result(90) for f in futs]
        self.assertIsNone(b_error, 'B was starved behind the A queue: %r' % (b_error,))
        self.assertTrue(gate_was_closed)
        self.assertEqual(rb.status, 200, rb.raw[:300])
        self.assertIn('tagcheck("B")', rb.json['decompiled'])
        self.assertLess(rb.elapsed, 3.0)
        self.assertTrue(all(r.status == 200 for r in a_results), [r.status for r in a_results])
        self.assertTrue(all('tagcheck("A")' in r.json['decompiled'] for r in a_results))
        snap = self.fb.ACTIVITY.snapshot()
        self.assertEqual(snap['max_same'].get(a.key), 1, snap)

    def probe_start(self, view, lock, seen):
        """Record every BinaryView.start read of `view` from a server thread as (view key, `lock` held?) in `seen`
        (the class is restored at cleanup)."""
        me = threading.current_thread()
        cls = type(view)

        def get(self_):
            if threading.current_thread() is not me:
                seen.append((view.key, bool(lock._is_owned())))
            return self_.__dict__['start']

        def put(self_, value):
            self_.__dict__['start'] = value
        view.__class__ = type(cls.__name__, (cls,), {'__module__': cls.__module__, 'start': property(get, put)})
        self.addCleanup(setattr, view, '__class__', cls)

    def test_ambiguous_candidates_read_their_start_under_each_view_lock(self):
        """A 409 AMBIGUOUS over HTTP (two views named foo.dll): each candidate's start address (BinaryView.start, the
        one Binary Ninja read the locating phase makes) is read with THAT view's request lock held (global: the one
        lock; per-view: the view's own). A candidate whose lock another holder keeps past lock_wait_s is listed with
        start None within that ONE budget (the request neither waits longer nor reads it unlocked)."""
        for mode, cfg in (('global', {}), ('per-view', {'lock_mode': 'per-view'})):
            with self.subTest(lock_mode=mode):
                srv, a, b = self.two_view_server(0.0, prefix=mode + '-', lock_wait_s=0.5, **cfg)
                vids = {v.key: srv.ops.describe_view(v, 'explicit')['view_id'] for v in (a, b)}
                locks = {k: srv.ops.view_lock(vid) for k, vid in vids.items()}
                seen = []
                for v in (a, b):
                    self.probe_start(v, locks[v.key], seen)
                r = srv.get('/decompile', {'binary': 'foo.dll', 'name': 'main'}, timeout=10)
                self.assertEqual(r.status, 409, r.raw[:400])
                self.assertEqual(r.json['error_code'], 'AMBIGUOUS')
                starts = {c['view_id']: c['start'] for c in r.json['candidates']}
                self.assertEqual(sorted(starts), sorted(vids.values()), r.raw[:400])
                self.assertTrue(all(str(x).startswith('0x') for x in starts.values()), starts)
                self.assertEqual(sorted(seen), sorted([(a.key, True), (b.key, True)]), seen)
                del seen[:]
                held = locks[b.key]                         # global mode: the one lock, so A is blocked too
                self.assertTrue(held.acquire(timeout=5))
                try:
                    r = srv.get('/decompile', {'binary': 'foo.dll', 'name': 'main'}, timeout=10)
                finally:
                    held.release()
                self.assertEqual(r.status, 409, r.raw[:400])
                self.assertGreaterEqual(r.elapsed, 0.45)
                self.assertLess(r.elapsed, 3.0)
                starts = {c['view_id']: c['start'] for c in r.json['candidates']}
                self.assertIsNone(starts[vids[b.key]], starts)
                if mode == 'global':
                    self.assertIsNone(starts[vids[a.key]], starts)
                    self.assertEqual(seen, [])
                else:
                    self.assertTrue(str(starts[vids[a.key]]).startswith('0x'), starts)
                    self.assertEqual(seen, [(a.key, True)])

    def test_scope_exempt_select_binary_makes_no_probed_bn_read(self):
        """/selectBinary takes no view lock (SCOPE_EXEMPT), so it must not read Binary Ninja analysis state or the
        loaded bytes either: a strict 'view:<id>' / '#<n>' selection only LOCATES the view. The scoped request after
        it still hashes FileMetadata.raw under its lock (the selection did not take the file session's first hash)."""
        for mode, cfg in (('global', {}), ('per-view', {'lock_mode': 'per-view'})):
            with self.subTest(lock_mode=mode):
                srv, a, b = self.two_view_server(0.0, prefix=mode + '-', **cfg)
                vid_b = srv.ops.describe_view(b, 'explicit')['view_id']
                probe = self.instrument(srv, (a, b))
                for sel in ('view:' + vid_b, '#2'):            # '#2': the sorted listing is <prefix>a, <prefix>b
                    srv.ops.current_view = a
                    r = srv.get('/selectBinary', {'view': sel})
                    self.assertEqual(r.status, 200, r.raw[:400])
                    self.assertEqual((r.json.get('status'), r.json['selected']['view_id']), ('ok', vid_b), r.raw[:400])
                    self.assertIs(srv.ops.global_view(), b, sel)
                self.assertEqual(probe.records(), [], _what_counts(probe.records()))
                r = srv.get('/decompile', {'binary': 'view:' + vid_b, 'name': 'main'})
                self.check_echo(b, r, srv, _Job(b, 'GET', '/decompile', {'binary': 'view:' + vid_b}, None))
                ops = probe.records()
                self.assertEqual(_outside_lock(ops), [], _what_counts(ops))
                self.assertIn('FileMetadata.raw.read', {o.what for o in ops}, _what_counts(ops))


class WaitPolicyTests(_HttpBase):
    def test_explicit_request_gets_503_busy_and_legacy_request_waits(self):
        a = self.view('a')
        srv = self.server(lock_wait_s=0.5)
        srv.ops.register_view(a)
        srv.ops.current_view = a
        lk = srv.ops.view_lock('1')
        self.assertTrue(lk.acquire(timeout=5))
        released = False
        try:
            r = srv.get('/decompile', {'binary': a.file.filename, 'name': 'main'}, timeout=10)
            self.assertEqual(r.status, 503, r.raw[:300])
            self.assertEqual(r.json['error_code'], 'BUSY')
            self.assertEqual(r.json['retry_after_s'], 5)
            self.assertGreaterEqual(r.elapsed, 0.45)
            self.assertLess(r.elapsed, 5.0)
            box = {}

            def legacy():
                box['r'] = srv.get('/decompile', {'name': 'main'}, timeout=30)
            t = threading.Thread(target=legacy)
            t0 = time.monotonic()
            t.start()
            time.sleep(1.2)
            self.assertNotIn('r', box, 'the legacy request did not wait for the view lock')
            lk.release()
            released = True
            t.join(30)
        finally:
            if not released:
                lk.release()
        self.assertIn('r', box)
        self.assertEqual(box['r'].status, 200, box['r'].raw[:300])
        self.assertGreaterEqual(time.monotonic() - t0, 1.2)
        self.assertEqual(box['r'].json['_binary']['resolved_by'], 'global')
        self.assertIn('tagcheck("A")', box['r'].json['decompiled'])

    def test_health_paths_answer_while_the_view_lock_is_held(self):
        a = self.view('a')
        srv = self.server()
        srv.ops.register_view(a)
        srv.ops.current_view = a
        lk = srv.ops.view_lock('1')
        self.assertTrue(lk.acquire(timeout=5))
        try:
            for method, path, kw in (('GET', '/status', {}), ('GET', '/x/serverInfo', {}), ('GET', '/binaries', {}),
                                     ('POST', '/x/compute', {'json_body': {'expr': '1+2'}})):
                with self.subTest(path=path):
                    r = H.http_request(srv.port, method, path, timeout=5, **kw)
                    self.assertEqual(r.status, 200, r.raw[:300])
                    self.assertLess(r.elapsed, 3.0)
            st = srv.get('/status', timeout=5).json
            self.assertEqual(st['server']['contract'], H.CONTRACT)
            self.assertNotIn('_binary', st)                # unscoped
        finally:
            lk.release()


class BindTests(_HttpBase):
    def check_bind_options(self, srv):
        """The default bind options: SO_REUSEADDR off on Windows (there it lets a second socket bind a listening port)
        and on elsewhere (there it only lets a restart bind over TIME_WAIT connections); SO_REUSEPORT never. macOS
        reports a set option as its flag value, not 1."""
        self.assertFalse(type(srv).allow_reuse_address)
        self.assertFalse(type(srv).allow_reuse_port)
        reuse = srv.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
        if sys.platform == 'win32':
            self.assertEqual(reuse, 0, 'SO_REUSEADDR is set on Windows')
        else:
            self.assertNotEqual(reuse, 0, 'SO_REUSEADDR is not set')
        if hasattr(socket, 'SO_REUSEPORT'):
            self.assertEqual(srv.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT), 0, 'SO_REUSEPORT is set')

    def test_default_bind_policy_refuses_a_second_listener(self):
        """A second bind of a LISTENING port must fail on every platform (check_bind_options shows the options it
        relies on). If this ever stops raising, report it; do not weaken the policy."""
        s1 = self.server()
        self.check_bind_options(s1.mcp.server)
        s2 = H.Server(self.m, port=s1.port)
        with self.assertRaises(OSError, msg='a second MCP server bound the LISTENING port %d' % s1.port):
            s2.start()
        s2.stop()
        self.assertIsNone(s2.mcp.server)
        self.assertEqual(s1.get('/status', timeout=5).status, 200)

    def test_stop_start_rebind_on_the_same_port_within_two_seconds(self):
        """The server closes each connection first, so the closed connections wait in TIME_WAIT on the server's port.
        A restart must still bind at once (on Linux and macOS this needs SO_REUSEADDR)."""
        a = self.view('a')
        s1 = H.Server(self.m).start()
        s1.ops.register_view(a)
        s1.ops.current_view = a
        port = s1.port
        for _ in range(3):                                  # leave closed connections (TIME_WAIT) behind
            self.assertEqual(s1.get('/decompile', {'name': 'main'}, timeout=10).status, 200)
        s1.stop()
        t0 = time.monotonic()
        s2 = None
        last = None
        while time.monotonic() - t0 < 2.0:
            try:
                s2 = H.Server(self.m, port=port).start()
                break
            except OSError as e:
                last = e
                time.sleep(0.1)
        self.assertIsNotNone(s2, 'rebind of port %d failed for 2 s: %r' % (port, last))
        self.addCleanup(s2.stop)
        self.assertLess(time.monotonic() - t0, 2.0)
        self.assertEqual(s2.get('/status', timeout=5).status, 200)

    def test_serial_mode_uses_the_same_bind_policy(self):
        s = self.server(threaded=False)
        self.assertIsInstance(s.mcp.server, self.m.http_server._MCPSerialHTTPServer)
        self.check_bind_options(s.mcp.server)
        self.assertEqual(s.get('/status', timeout=5).json['server']['threaded'], False)


class RouteTests(_HttpBase):
    def test_post_method_delete_on_comment_deletes(self):
        a = self.view('a')
        srv = self.server()
        srv.ops.register_view(a)
        srv.ops.current_view = a
        r = srv.post('/comment', json_body={'address': '0x140001000', 'comment': 'hello'})
        self.assertEqual(r.status, 200, r.raw[:300])
        self.assertEqual(a.get_comment_at(0x140001000), 'hello')
        r = srv.post('/comment', json_body={'_method': 'DELETE', 'address': '0x140001000'})
        self.assertEqual(r.status, 200, r.raw[:300])
        self.assertIn('deleted', r.json.get('message', '').lower())
        self.assertEqual(a.get_comment_at(0x140001000), '')
        srv.post('/comment', json_body={'address': '0x140001004', 'comment': 'two'})
        r = srv.post('/comment', params={'_method': 'DELETE', 'address': '0x140001004'}, json_body={})
        self.assertEqual(r.status, 200, r.raw[:300])
        self.assertEqual(a.get_comment_at(0x140001004), '')
        r = H.http_request(srv.port, 'DELETE', '/comment', params={'address': '0x140001000'})
        self.assertNotEqual(r.status, 404)

    def test_post_define_types_is_accepted(self):
        a = self.view('a')
        srv = self.server()
        srv.ops.register_view(a)
        srv.ops.current_view = a
        r = srv.post('/defineTypes', json_body={'cCode': 'struct PostedType { int a; char b[300]; };'})
        self.assertEqual(r.status, 200, r.raw[:300])
        self.assertIn('PostedType', r.json)
        self.assertIn('PostedType', a.types)
        r = srv.post('/defineTypes', params={'binary': a.file.filename},
                     json_body={'cCode': 'struct Second { int x; };'})
        self.assertEqual(r.status, 200, r.raw[:300])
        self.assertEqual(r.json['_binary']['filename'], a.file.filename)
        for path in ('/declareCType', '/setFunctionPrototype'):
            r = srv.post(path, json_body={})
            self.assertNotIn(r.status, (404, 405), (path, r.raw[:200]))

    def test_post_load_and_compute_work_with_no_view_open(self):
        srv = self.server()
        self.assertIsNone(srv.ops.global_view())
        r = srv.post('/x/compute', json_body={'expr': '0x10<<4'})
        self.assertEqual(r.status, 200, r.raw[:300])
        self.assertTrue(r.json['ok'])
        self.assertEqual(r.json['result']['dec'], '256')
        r = srv.get('/decompile', {'name': 'main'})
        self.assertEqual(r.status, 400)
        self.assertEqual(r.json['error'], 'No binary loaded')
        path = self.fb.make_standard_file(os.path.join(self.td.name, 'ld'), 'loaded.dll', 'L')
        r = srv.post('/load', json_body={'filepath': path})
        self.assertEqual(r.status, 200, r.raw[:300])
        self.assertTrue(r.json['success'])
        gv = srv.ops.global_view()
        self.assertIsNotNone(gv)
        self.assertEqual(gv.file.filename, path)
        info = srv.ops.describe_view(gv)
        self.assertTrue(info['owned'])
        r = srv.get('/decompile', {'binary': 'loaded.dll', 'name': 'main'})
        self.assertEqual(r.status, 200, r.raw[:300])
        self.assertIn('tagcheck("L")', r.json['decompiled'])

    def test_non_ascii_basename_answers_with_a_percent_encoded_header(self):
        name = 'üδοκιμή.dll'
        a = self.view('u', name, 'U')
        srv = self.server()
        vid = srv.ops.register_view(a)
        r = srv.get('/decompile', {'binary': a.file.filename, 'name': 'main'})
        self.assertEqual(r.status, 200, r.raw[:300])
        self.assertEqual(r.json['_binary']['basename'], name)
        hdr = r.headers.get('x-bn-binary', '')
        self.assertTrue(hdr.startswith(vid + ';' + urllib.parse.quote(name, safe='') + ';'), hdr)
        hdr.encode('ascii')
        r = srv.get('/hexdump', {'binary': name, 'address': '0x140002000', 'length': '16'})
        self.assertEqual(r.status, 200)
        self.assertIn(b'config.ini', r.raw)
        self.assertIn('x-bn-binary', r.headers)

    def test_request_queued_behind_a_close_gets_410_gone(self):
        srv = self.server()
        path = self.fb.make_standard_file(os.path.join(self.td.name, 'cl'), 'closing.dll', 'C')
        r = srv.post('/load', json_body={'filepath': path})
        self.assertEqual(r.status, 200, r.raw[:300])
        gv = srv.ops.global_view()
        vid = srv.ops.describe_view(gv)['view_id']
        me = threading.current_thread()
        asked = threading.Event()
        real = srv.ops.view_lock

        def spy(view_id):
            if threading.current_thread() is not me:
                asked.set()
            return real(view_id)
        srv.ops.view_lock = spy
        lk = real(vid)
        self.assertTrue(lk.acquire(timeout=5))
        box = {}
        try:
            t = threading.Thread(target=lambda: box.setdefault(
                'r', srv.get('/decompile', {'binary': 'view:' + vid, 'name': 'main'}, timeout=30)))
            t.start()
            self.assertTrue(asked.wait(10), 'the request never reached the view lock')
            time.sleep(0.3)
            out = srv.ops.close_owned_view(vid)             # re-entrant: this thread holds the (global) lock
            self.assertTrue(out['closed'])
        finally:
            lk.release()
        t.join(30)
        self.assertEqual(box['r'].status, 410, box['r'].raw[:300])
        self.assertEqual(box['r'].json['error_code'], 'GONE')
        self.assertTrue(gv.file.closed)
        self.assertIsNone(srv.ops.global_view())
        r = srv.get('/decompile', {'binary': 'view:' + vid, 'name': 'main'})
        self.assertEqual(r.status, 404)


if __name__ == '__main__':
    unittest.main()
