# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""Strict per-call binary resolution (the `binary` selector grammar) and the per-request scope.

Runs the plugin's real BinaryOperations / request_context against the offline fake binaryninja.
"""

import os
import random
import sys
import tempfile
import threading
import time
import unittest

import run_tests as H


class _Base(unittest.TestCase):
    def setUp(self):
        self.m = H.plugin_modules()
        H.reset_plugin_state(self.m)
        self.rc = self.m.rc
        self.td = tempfile.TemporaryDirectory(prefix='bnmcp-res-')
        self.addCleanup(self.td.cleanup)
        self.views = []

    def view(self, sub, basename, tag):
        v = H.make_view(os.path.join(self.td.name, sub), basename, tag)
        self.views.append(v)
        return v


class PathRuleTests(_Base):
    """Paths and names compare without case on Windows only: on a case-sensitive file system /x/a.bin and /x/A.bin
    are two files, and a selector for one must never answer from the other."""

    def test_the_helpers_on_both_platforms(self):
        bo = self.m.bo
        self.assertNotEqual(bo._norm_path('/x/A.bin', win=False), bo._norm_path('/x/a.bin', win=False))
        self.assertEqual(bo._norm_path('/x//y/../a.bin', win=False), '/x/a.bin')
        self.assertEqual(bo._basename('/x/a\\b.bin', win=False), 'a\\b.bin', 'a backslash is part of a POSIX name')
        self.assertEqual(bo._norm_path('C:/X/A.BIN', win=True), bo._norm_path('c:\\x\\a.bin', win=True))
        self.assertEqual(bo._norm_path('\\\\?\\C:\\x\\a.bin', win=True), bo._norm_path('C:\\X\\a.bin', win=True))
        self.assertEqual((bo._name_key('A.BIN', win=True), bo._name_key('A.BIN', win=False)), ('a.bin', 'A.BIN'))
        self.assertEqual((bo._is_abs_path('/x', win=False), bo._is_abs_path('C:\\x', win=False)), (True, False))

    def test_resolution_with_the_posix_rules(self):
        from unittest import mock
        bo = self.m.bo
        up = self.view('u', 'A.bin', 'A')
        low = self.view('l', 'a.bin', 'B')
        for v, p in ((up, '/x/A.bin'), (low, '/x/a.bin')):
            v.file.filename = v.file.original_filename = p
        with mock.patch.object(bo, '_WIN', False):
            ops = H.new_ops(self.m)
            ops.register_view(up)
            ops.register_view(low)
            for sel, want in (('/x/a.bin', low), ('/x/A.bin', up), ('a.bin', low), ('A.bin', up), ('a', low),
                              ('A', up)):
                with self.subTest(selector=sel):
                    self.assertIs(ops.locate_binary(sel)[0], want)
            for sel in ('/X/a.bin', 'A.BIN'):
                with self.subTest(selector=sel):
                    with self.assertRaises(self.rc.NotFoundError):
                        ops.locate_binary(sel)
            listing = self.m.endpoints.BinaryNinjaEndpoints(ops).list_binaries()['binaries']
            self.assertEqual(sorted(s for e in listing for s in e['selectors'] if not s[0].isdigit()
                                    and not s.startswith('view:')), ['/x/A.bin', '/x/a.bin', 'A.bin', 'a.bin'])

    @unittest.skipIf(sys.platform == 'win32', 'needs a case-sensitive file system')
    def test_two_real_files_that_differ_only_by_case(self):
        d = os.path.join(self.td.name, 'cs')
        up, low = self.view('cs', 'A.bin', 'A'), None
        if os.path.exists(os.path.join(d, 'a.bin')):
            self.skipTest('this file system ignores case')
        low = self.view('cs', 'a.bin', 'B')
        ops = H.new_ops(self.m)
        ops.register_view(up)
        ops.register_view(low)
        self.assertIs(ops.locate_binary(os.path.join(d, 'a.bin'))[0], low)
        self.assertIs(ops.locate_binary(os.path.join(d, 'A.bin'))[0], up)


class ResolutionTests(_Base):
    def setUp(self):
        super().setUp()
        self.ops = H.new_ops(self.m)
        # registration order != sorted (by filename) order: id 1 = zz/late.dll, id 2 = aa/early.dll
        self.late = self.view('zz', 'late.dll', 'L')
        self.early = self.view('aa', 'early.dll', 'E')
        self.id_late = self.ops.register_view(self.late)
        self.id_early = self.ops.register_view(self.early)
        self.assertEqual((self.id_late, self.id_early), ('1', '2'))
        self.ops.current_view = self.late

    def resolve(self, sel):
        return self.ops.resolve_binary(sel)

    def assertResolves(self, sel, view, vid):
        bv, info = self.resolve(sel)
        self.assertIs(bv, view, 'selector %r resolved to the wrong view' % sel)
        self.assertEqual(info['view_id'], vid, sel)
        self.assertEqual(info['resolved_by'], 'explicit', sel)
        self.assertEqual(info['analysis_state'], 'IdleState', sel)
        self.assertIsInstance(info['analysis_state'], str)

    def test_every_selector_form_resolves(self):
        sha, src = self.ops.view_sha256(self.early)
        self.assertEqual(src, 'file')
        path = self.early.file.filename
        forms = [
            'view:%s' % self.id_early, 'V:%s' % self.id_early, 'v:%s' % self.id_early, self.id_early,
            '#1',                                    # sorted listing: aa/early.dll first
            sha, sha.upper(), sha[:12], sha[:40],
            path, 'early.dll', 'early',
        ]
        if sys.platform == 'win32':                  # paths and names compare without case on Windows only
            forms += [path.replace('\\', '/'), path.upper(), '\\\\?\\' + path, 'EARLY.DLL', 'EaRlY']
        for sel in forms:
            with self.subTest(selector=sel):
                self.assertResolves(sel, self.early, self.id_early)
        self.assertResolves('#2', self.late, self.id_late)
        self.assertResolves('late', self.late, self.id_late)

    def test_all_digits_is_an_internal_id_never_an_ordinal(self):
        # '#1' is the first SORTED entry (early.dll, id 2); '1' is the internal id 1 (late.dll)
        self.assertResolves('1', self.late, self.id_late)
        self.assertResolves('#1', self.early, self.id_early)
        with self.assertRaises(self.rc.NotFoundError) as cm:
            self.resolve('7')
        self.assertEqual(cm.exception.http_status, 404)
        self.assertTrue(cm.exception.extra.get('available'))
        with self.assertRaises(self.rc.NotFoundError):
            self.resolve('#9')
        with self.assertRaises(self.rc.NotFoundError):
            self.resolve('view:7')

    def test_unknown_selector_is_not_found_with_available(self):
        with self.assertRaises(self.rc.NotFoundError) as cm:
            self.resolve('nope.dll')
        e = cm.exception
        self.assertEqual((e.code, e.http_status), ('NOT_FOUND', 404))
        names = sorted(x['basename'] for x in e.extra['available'])
        self.assertEqual(names, ['early.dll', 'late.dll'])

    def test_empty_selector_is_bad_argument(self):
        with self.assertRaises(self.rc.ApiError) as cm:
            self.resolve('  ')
        self.assertEqual((cm.exception.code, cm.exception.http_status), ('BAD_ARGUMENT', 400))

    def test_relative_path_selector_is_bad_argument(self):
        for sel in ('aa/early.dll', 'aa\\early.dll', '.\\early.dll', '../aa/early.dll'):
            with self.subTest(selector=sel):
                with self.assertRaises(self.rc.ApiError) as cm:
                    self.resolve(sel)
                self.assertEqual((cm.exception.code, cm.exception.http_status), ('BAD_ARGUMENT', 400))

    def test_absolute_path_of_unopened_file_is_not_found(self):
        with self.assertRaises(self.rc.NotFoundError):
            self.resolve(os.path.join(self.td.name, 'aa', 'other.dll'))

    def test_two_views_one_basename_is_ambiguous_with_two_candidates(self):
        a = self.view('d1', 'foo.dll', 'A')
        b = self.view('d2', 'foo.dll', 'B')
        self.ops.register_view(a)
        self.ops.register_view(b)
        with self.assertRaises(self.rc.AmbiguousError) as cm:
            self.resolve('foo.dll')
        e = cm.exception
        self.assertEqual((e.code, e.http_status), ('AMBIGUOUS', 409))
        self.assertEqual(len(e.extra['candidates']), 2)
        self.assertTrue(str(e).startswith('AMBIGUOUS: 2 binaries match foo.dll: '), str(e))
        sels = sorted(c['selector'] for c in e.extra['candidates'])
        self.assertEqual(len(set(sels)), 2)
        for c in e.extra['candidates']:
            self.assertTrue(c['start'].startswith('0x'))
        # the stem is ambiguous too; each absolute path is unique
        with self.assertRaises(self.rc.AmbiguousError):
            self.resolve('foo')
        self.assertIs(self.resolve(a.file.filename)[0], a)
        self.assertIs(self.resolve(b.file.filename)[0], b)

    def test_locate_binary_returns_the_view_id_and_reads_candidate_starts_through_read_locked(self):
        # locate_binary is resolve_binary's selection half (http_server._dispatch locks between it and describe_view)
        self.assertEqual(self.ops.locate_binary('early.dll'), (self.early, self.id_early))
        self.assertEqual(self.ops.locate_binary('view:' + self.id_late), (self.late, self.id_late))
        a = self.view('d1', 'foo.dll', 'A')
        b = self.view('d2', 'foo.dll', 'B')
        ia, ib = self.ops.register_view(a), self.ops.register_view(b)
        calls = []

        def read_locked(vid, fn):                         # B's lock "not acquired in time"
            calls.append(vid)
            return fn() if vid == ia else None
        with self.assertRaises(self.rc.AmbiguousError) as cm:
            self.ops.locate_binary('foo.dll', read_locked)
        starts = {c['view_id']: c['start'] for c in cm.exception.extra['candidates']}
        self.assertEqual(sorted(calls), sorted([ia, ib]))
        self.assertEqual(starts, {ia: hex(a.start), ib: None})

        def broken(vid, fn):
            raise RuntimeError('reader failed')
        with self.assertRaises(self.rc.AmbiguousError) as cm:  # a failing reader never replaces the 409
            self.ops.locate_binary('foo', broken)
        self.assertEqual({c['start'] for c in cm.exception.extra['candidates']}, {None})

    def test_extension_selector_never_falls_back_to_the_stem(self):
        exe = self.view('x1', 'foo.exe', 'X')
        self.ops.register_view(exe)
        with self.assertRaises(self.rc.NotFoundError):
            self.resolve('foo.dll')                       # only foo.exe is open: no stem match for a dotted selector
        self.assertIs(self.resolve('foo')[0], exe)        # the extension-less stem is unique
        dll = self.view('x2', 'foo.dll', 'Y')
        self.ops.register_view(dll)
        with self.assertRaises(self.rc.AmbiguousError) as cm:
            self.resolve('foo')                           # foo.dll + foo.exe
        self.assertEqual(len(cm.exception.extra['candidates']), 2)
        self.assertIs(self.resolve('foo.dll')[0], dll)
        self.assertIs(self.resolve('foo.exe')[0], exe)

    def test_resolution_never_touches_the_global_selection(self):
        self.ops.current_view = self.late
        for sel in ('early.dll', '#1', self.id_early, self.early.file.filename):
            self.resolve(sel)
            self.assertIs(self.ops.global_view(), self.late)

    def test_two_same_name_functions_raise_ambiguous_and_note_it(self):
        with self.ops.using_view(self.early):
            self.assertIsNone(self.rc.ambiguity())
            with self.assertRaises(self.rc.AmbiguousError) as cm:
                self.ops.get_function_by_name_or_address('dup')
            e = cm.exception
            self.assertIs(self.rc.ambiguity(), e)
            self.assertEqual(e.http_status, 409)
            self.assertEqual(str(e), 'AMBIGUOUS: 2 functions match dup: dup@0x140001400; dup@0x140001480')
            self.assertEqual([c['start'] for c in e.extra['candidates']], ['0x140001400', '0x140001480'])
            # the address form is never ambiguous
            self.assertEqual(self.ops.get_function_by_name_or_address('0x140001480').start, 0x140001480)
        self.assertIsNone(self.rc.ambiguity())           # the scope restored the outer (empty) note


class ScopingTests(_Base):
    def test_sixteen_threads_each_see_only_their_own_view(self):
        ops = H.new_ops(self.m)
        views = []
        for k in range(16):
            v = self.view('t%02d' % k, 'mod%02d.dll' % k, 'T%d' % k)
            ops.register_view(v)
            views.append(v)
        ops.current_view = views[0]
        barrier = threading.Barrier(16)
        errors = []
        done = []                                         # k is appended only after ALL of worker k's checks ran

        def worker(k):
            try:
                v = views[k]
                info = ops.describe_view(v, 'explicit')
                with self.rc.scope(v, info):
                    barrier.wait(timeout=20)          # every thread is inside its scope at the same time
                    for _ in range(25):
                        if ops.current_view is not v or ops._current_view is not v:
                            errors.append('thread %d saw another view' % k)
                        if self.rc.info() is not info or self.rc.override_view() is not v:
                            errors.append('thread %d saw another info' % k)
                        with ops.using_view(v):
                            if ops.get_function_by_name_or_address('main').view is not v:
                                errors.append('thread %d resolved main in another view' % k)
                        time.sleep(random.random() / 500.0)
                if self.rc.override_view() is not self.rc.UNSET:
                    errors.append('thread %d: scope not restored' % k)
                done.append(k)
            except Exception as e:                       # pragma: no cover - reported below
                errors.append('thread %d: %r' % (k, e))

        # daemon=True: a deadlocked worker FAILS this test below instead of hanging interpreter exit after an OK
        ts = [threading.Thread(target=worker, args=(k,), daemon=True) for k in range(16)]
        for t in ts:
            t.start()
        deadline = time.monotonic() + 60.0                # ONE bound for the whole fleet, not 16 x 60 s
        for t in ts:
            t.join(max(0.0, deadline - time.monotonic()))
        stuck = [k for k, t in enumerate(ts) if t.is_alive()]
        self.assertEqual(stuck, [], 'worker(s) still running after 60 s (deadlock?): %r; errors so far: %r'
                         % (stuck, list(errors)[:20]))
        self.assertEqual(errors, [])
        self.assertEqual(sorted(done), list(range(16)), 'a worker ended without completing its checks')
        self.assertIs(ops.global_view(), views[0])
        self.assertIs(self.rc.override_view(), self.rc.UNSET)
        self.assertIs(ops.current_view, views[0])

    def test_nested_scopes_restore_view_info_and_notes(self):
        ops = H.new_ops(self.m)
        a = self.view('a', 'a.dll', 'A')
        b = self.view('b', 'b.dll', 'B')
        ops.register_view(a)
        ops.register_view(b)
        ia, ib = ops.describe_view(a), ops.describe_view(b)
        with self.rc.scope(a, ia):
            self.rc.warn('outer-warning')
            outer_err = self.rc.AmbiguousError('functions', 'x', [{'name': 'x', 'start': 1}, {'name': 'x', 'start': 2}])
            self.rc.note_ambiguity(outer_err)
            with self.rc.scope(b, ib, defaulted=True):
                self.assertIs(ops.current_view, b)
                self.assertIs(self.rc.info(), ib)
                self.assertTrue(self.rc.defaulted())
                self.assertIsNone(self.rc.ambiguity())     # cleared on entry
                self.assertEqual(self.rc.warnings(), [])
                self.rc.warn('inner')
                with self.rc.scope(None, None):
                    self.assertIsNone(ops.current_view)    # an explicit None scope is honoured
            self.assertIs(ops.current_view, a)
            self.assertIs(self.rc.info(), ia)
            self.assertFalse(self.rc.defaulted())
            self.assertIs(self.rc.ambiguity(), outer_err)
            self.assertEqual(self.rc.warnings(), ['outer-warning'])
        self.assertIs(self.rc.override_view(), self.rc.UNSET)
        self.assertIsNone(self.rc.info())

    def test_scope_clears_ambiguity_and_warnings_on_entry(self):
        self.rc.reset_notes()
        self.rc.warn('stale')
        self.rc.note_ambiguity(self.rc.AmbiguousError('functions', 'f', []))
        with self.rc.scope(None, None):
            self.assertIsNone(self.rc.ambiguity())
            self.assertEqual(self.rc.warnings(), [])
        self.assertIsNotNone(self.rc.ambiguity())
        self.rc.reset_notes()
        self.assertIsNone(self.rc.ambiguity())
        self.assertEqual(self.rc.warnings(), [])

    def test_warnings_are_deduplicated_and_capped(self):
        with self.rc.scope(None, None):
            for k in range(50):
                self.rc.warn('w%d' % (k % 30))
                self.rc.warn('w%d' % (k % 30))
            w = self.rc.warnings()
            self.assertEqual(len(w), 20)
            self.assertEqual(len(set(w)), 20)

    def test_serial_server_a_409_then_an_unrelated_404_stays_404(self):
        """BN_MCP_THREADED=0: one thread serves every request, so stale thread-local notes would leak."""
        v = self.view('s', 'serial.dll', 'S')
        srv = H.Server(self.m, threaded=False)
        srv.ops.current_view = v
        srv.start()
        self.addCleanup(srv.stop)
        self.assertIsInstance(srv.mcp.server, self.m.http_server._MCPSerialHTTPServer)
        for params in ({}, {'binary': v.file.filename}):
            with self.subTest(explicit=bool(params)):
                r1 = srv.get('/decompile', dict(params, name='dup'))
                self.assertEqual(r1.status, 409, r1.raw)
                self.assertEqual(r1.json['error_code'], 'AMBIGUOUS')
                self.assertEqual(len(r1.json['candidates']), 2)
                self.assertIn('AMBIGUOUS: 2 functions match dup', r1.json['error'])
                r2 = srv.get('/decompile', dict(params, name='no_such_function'))
                self.assertEqual(r2.status, 404, r2.raw)
                self.assertNotIn('candidates', r2.json)
                self.assertNotEqual(r2.json.get('error_code'), 'AMBIGUOUS')
                r3 = srv.get('/status')
                self.assertEqual(r3.status, 200)
                self.assertNotIn('error_code', r3.json)


if __name__ == '__main__':
    unittest.main()
