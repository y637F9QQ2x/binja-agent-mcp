# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""The MCP bridge (bridge/binja_mcp_bridge.py) against a stub HTTP server (no Binary Ninja, no MCP client).

Needs the `mcp`, `requests` and `anyio` packages. When the running interpreter lacks them, the suite re-runs itself
under the plugin's own bridge venv interpreter (<plugin>/.venv), else it is SKIPPED with the reason printed (a skip
is never reported as a pass of these checks). The bridge is loaded with BN_MCP_TOOLSET=full, so every tool is
registered and driven; test_toolsets.py covers the tool-set selection itself.
"""

import ast
import asyncio
import concurrent.futures
import http.server
import importlib.util
import inspect
import json
import os
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import unittest
import urllib.parse

import run_tests as H

REQ = object()
BN_SIGNATURES = {
    'bn_server_info': [],
    'bn_binary_info': [('binary', '')],
    'bn_function_status': [('function', REQ), ('binary', '')],
    'bn_decompile': [('function', REQ), ('il', 'hlil'), ('ssa', False), ('render', 'ast'), ('line_offset', 0),
                     ('max_lines', 150), ('max_chars', 12000), ('binary', '')],
    'bn_il_search': [('function', ''), ('il', 'mlil'), ('operation', ''), ('callee', ''), ('constant', ''),
                     ('text_regex', ''), ('offset', 0), ('limit', 100), ('binary', '')],
    'bn_ssa_def': [('function', REQ), ('var', REQ), ('version', -1), ('at_va', ''), ('binary', '')],
    'bn_ssa_uses': [('function', REQ), ('var', REQ), ('version', -1), ('at_va', ''), ('binary', '')],
    'bn_backward_slice': [('call_site', REQ), ('arg_index', REQ), ('function', ''), ('max_depth', 24),
                          ('max_nodes', 200), ('binary', '')],
    'bn_possible_values': [('va', REQ), ('function', ''), ('operand', ''), ('var', ''), ('when', 'before'),
                           ('options', ''), ('binary', '')],
    'bn_branch_dependence': [('va', REQ), ('function', ''), ('binary', '')],
    'bn_cfg': [('function', REQ), ('level', 'disasm'), ('max_blocks', 200), ('binary', '')],
    'bn_dominators': [('function', REQ), ('block_va', REQ), ('kind', 'dominators'), ('level', 'disasm'),
                      ('binary', '')],
    'bn_reachable': [('function', REQ), ('from_va', REQ), ('to_va', REQ), ('removed_edges', ''),
                     ('removed_out_of', ''), ('level', 'disasm'), ('binary', '')],
    'bn_callers': [('function', REQ), ('depth', 1), ('max_nodes', 100), ('binary', '')],
    'bn_callees': [('function', REQ), ('depth', 1), ('max_nodes', 100), ('include_imports', True), ('binary', '')],
    'bn_call_paths': [('src', REQ), ('dst', REQ), ('max_hops', 6), ('max_paths', 20), ('binary', '')],
    'bn_return_check': [('call_site', REQ), ('function', ''), ('binary', '')],
    'bn_sinks': [('preset', ''), ('names', ''), ('include_builtins', True), ('offset', 0), ('limit', 100),
                 ('binary', '')],
    'bn_undominated_sinks': [('function', REQ), ('gate', ''), ('preset', ''), ('binary', '')],
    'bn_stack_frame': [('function', REQ), ('binary', '')],
    'bn_handler_slice': [('function', REQ), ('depth', 3), ('max_callees', 40), ('max_chars', 16000),
                         ('include', 'hlil,callers,types,strings,imports'), ('disasm', False), ('binary', '')],
    'bn_resolve_entity': [('ref', REQ), ('binary', '')],
    'bn_resolve_dispatch': [('function', REQ), ('call_site', ''), ('max_targets', 64), ('options', ''),
                            ('binary', '')],
    'bn_ndr_decode': [('va', REQ), ('count', 0), ('format', 'oif'), ('param_offset', 0), ('max_params', 32),
                      ('header', False), ('length', 0), ('binary', '')],
    'bn_interproc_slice': [('call_site', REQ), ('arg_index', REQ), ('function', ''), ('max_hops', 2),
                           ('max_frames', 24), ('gate', ''), ('binary', '')],
    'bn_bytes_at': [('va', REQ), ('length', 16), ('binary', '')],
    'bn_xrefs': [('va', REQ), ('kind', 'code'), ('offset', 0), ('limit', 100), ('binary', '')],
    'bn_debug_info_status': [('binary', '')],
    'bn_uninit_reads': [('function', REQ), ('binary', '')],
    'bn_compute': [('expr', REQ)],
    'bn_batch': [('items_json', REQ), ('binary', '')],
    'bn_close_binary': [('binary', REQ)],
    # the single-POST load verb
    'bn_load_binary': [('filepath', REQ)],
}
EXEMPT_LEGACY = {'list_binaries', 'select_binary', 'list_platforms', 'convert_number'}

# --- the table-driven forwarding test (every registered tool) -------------------------------------------------------
SENTINEL = 'C:\\Sentinel Dir\\s+e&n#t.dll'       # an ABSOLUTE-path selector that needs query encoding
ADDRESS_PARAMS = {'address', 'va', 'call_site', 'block_va', 'from_va', 'to_va', 'at_va', 'name_or_address',
                  'function_address'}
# Extra argument sets: a tool listed here is called once per entry (merged over the synthesized required arguments),
# so every branch that issues a different request is driven with the sentinel (name vs address forms, the delegated
# hexdump_data -> hexdump_address call, the paged list_all_strings follow-up, the three rename_multi_variables forms).
VARIANTS = {
    'rename_multi_variables': [{'function_identifier': 'fn', 'mapping_json': '{"a": "b"}'},
                               {'function_identifier': '0x1000', 'renames_json': '[{"old": "a", "new": "b"}]'},
                               {'function_identifier': 'fn', 'pairs': 'a:b'}],
    'hexdump_data': [{'name_or_address': '0x1000'}, {'name_or_address': 'g_data'}],
    'get_data_decl': [{'name_or_address': '0x1000'}, {'name_or_address': 'g_data'}],
    'get_il': [{'name_or_address': '0x1000'}, {'name_or_address': 'main'}],
    'set_function_prototype': [{'name_or_address': '0x1000'}, {'name_or_address': 'main'}],
    'list_all_strings': [{'batch_size': 2}],
    'bn_batch': [{'items_json': '[{"verb":"compute","params":{"expr":"1"}}]'}],
}
# Tools whose POST answered 404/405 is retried as a GET (_post_json_or_get); the retry must keep the selector.
POST_FALLBACK_TOOLS = {'define_types', 'declare_c_type', 'set_function_prototype'}
_HTTP_HELPERS = ('safe_get', 'get_json', 'get_text', 'safe_post')


def bridge_path():
    return os.path.join(H.plugin_dir(), 'bridge', 'binja_mcp_bridge.py')


def _importable():
    return all(importlib.util.find_spec(n) is not None for n in ('mcp', 'requests', 'anyio'))


def _venv_python():
    cands = [os.path.join(H.plugin_dir(), '.venv', 'Scripts', 'python.exe'),
             os.path.join(H.plugin_dir(), '.venv', 'bin', 'python')]
    for c in cands:
        if os.path.isfile(c):
            return c
    return None


def baseline_legacy_tools():
    """The 53 upstream tool names: @mcp.tool() functions of the baseline bridge."""
    if not H.BASELINE_DIR or not os.path.isdir(H.BASELINE_DIR):
        raise unittest.SkipTest('the upstream v1.1.0 baseline is not available (set BN_MCP_TEST_BASELINE)')
    with open(os.path.join(H.BASELINE_DIR, 'bridge', 'binja_mcp_bridge.py'), encoding='utf-8') as f:
        tree = ast.parse(f.read())
    return [n.name for n in tree.body if isinstance(n, ast.FunctionDef)
            and any(ast.unparse(d) == 'mcp.tool()' for d in n.decorator_list)]


def baseline_legacy_paths():
    """{tool: {'/path', ...}} = every path the BASELINE bridge's tool can request: the constant endpoint passed to
    safe_get/get_json/get_text/safe_post in its own body, plus those of the module functions it calls (transitively,
    e.g. hexdump_data -> hexdump_address, decompile_function -> _active_filename)."""
    if not H.BASELINE_DIR or not os.path.isdir(H.BASELINE_DIR):
        raise unittest.SkipTest('the upstream v1.1.0 baseline is not available (set BN_MCP_TEST_BASELINE)')
    with open(os.path.join(H.BASELINE_DIR, 'bridge', 'binja_mcp_bridge.py'), encoding='utf-8') as f:
        tree = ast.parse(f.read())
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    own, calls = {}, {}
    for name, fn in funcs.items():
        own[name], calls[name] = set(), set()
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                continue
            if (node.func.id in _HTTP_HELPERS and node.args and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                own[name].add('/' + node.args[0].value.lstrip('/'))
            elif node.func.id in funcs and node.func.id != name:
                calls[name].add(node.func.id)

    def closure(name):
        seen, todo, out = set(), [name], set()
        while todo:
            n = todo.pop()
            if n in seen:
                continue
            seen.add(n)
            out |= own[n]
            todo.extend(calls[n])
        return out
    return {name: closure(name) for name in baseline_legacy_tools()}


def server_routes():
    """(ROUTES_GET, ROUTES_POST) of the plugin under test, read from plugin/api/endpoints.py without importing it:
    ROUTES_POST = ROUTES_GET + ROUTES_POST_ONLY (the composition endpoints.py documents and test_expert_ops checks)."""
    with open(os.path.join(H.plugin_dir(), 'plugin', 'api', 'endpoints.py'), encoding='utf-8') as f:
        tree = ast.parse(f.read())
    lit = {}
    for n in tree.body:
        if (isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                and n.targets[0].id in ('ROUTES_GET', 'ROUTES_POST_ONLY') and isinstance(n.value, ast.Dict)):
            lit[n.targets[0].id] = ast.literal_eval(n.value)
    if set(lit) != {'ROUTES_GET', 'ROUTES_POST_ONLY'}:
        raise AssertionError('endpoints.py has no literal ROUTES_GET / ROUTES_POST_ONLY dict (found %s)' % sorted(lit))
    post = dict(lit['ROUTES_GET'])
    post.update(lit['ROUTES_POST_ONLY'])
    return lit['ROUTES_GET'], post


def required_args(fn):
    """Minimal values for the required parameters of a tool (the `binary` selector is supplied by the caller)."""
    out = {}
    for p in inspect.signature(fn).parameters.values():
        if p.name == 'binary' or p.default is not inspect.Parameter.empty:
            continue
        if p.annotation in (bool, 'bool'):
            out[p.name] = False
        elif p.annotation in (int, 'int'):
            out[p.name] = 1
        elif 'json' in p.name:
            out[p.name] = '[]' if p.name.startswith('items') else '{}'
        elif p.name in ADDRESS_PARAMS:
            out[p.name] = '0x1000'
        else:
            out[p.name] = 'x'
    return out


_BRIDGE = {}


def import_bridge(name, env):
    """A fresh import of the bridge under module name `name` with the BN_MCP_* overrides `env` applied during the
    import (tool registration reads them then); the environment is restored afterwards."""
    hook = sys.excepthook
    saved = {k: os.environ.get(k) for k in env}
    for k, v in env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        spec = importlib.util.spec_from_file_location(name, bridge_path())
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        sys.excepthook = hook                   # the bridge installs its own excepthook at import time
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    # run_tests points BN_MCP_URL at a closed port: a test that forgets its stub can never reach a Binary Ninja
    if mod.binja_server_url.endswith(':%d' % H.LIVE_PORT):
        raise AssertionError('the bridge under test points at the live port: %s' % mod.binja_server_url)
    return mod


def load_bridge():
    """The bridge with EVERY tool registered (BN_MCP_TOOLSET=full)."""
    if 'm' not in _BRIDGE:
        _BRIDGE['m'] = import_bridge('bnmcp_bridge_under_test', {'BN_MCP_TOOLSET': 'full', 'BN_MCP_TOOLS': None})
    return _BRIDGE['m']


def _abort_on_close(sock):
    """SO_LINGER on with a 0 s timeout: closing the socket then resets the connection (RST) instead of a FIN."""
    try:
        lin = struct.pack('HH', 1, 0) if sys.platform == 'win32' else struct.pack('ii', 1, 0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, lin)
    except OSError:
        pass                                    # a plain close still drops the request unanswered


class _ConcStub(object):
    """A threaded HTTP stub for the bridge's concurrency tests. Each test makes its own, so each gets a fresh
    _HttpGate (the bridge keys its gates by server URL).
    * GET /status answers `status` (a dict); status=None resets the connection instead.
    * Every other path answers {'ok': true, 'result': {'path': ...}} after delay.get(path, 0) seconds, and counts
      the requests in flight (`inflight`, high-water mark `peak`). The counter drops BEFORE the answer is written,
      so the observed peak can never exceed the bridge's own number of in-flight requests.
    * reset_others=True: every path but /status is answered by resetting the connection once the request was read
      (no status line), which `requests` raises as a ConnectionError. reset_kills_status=True: such a reset also
      sets status=None (the server dies after the first refused request).
    * Every request is logged as (method, path, query) before it is answered or reset."""

    def __init__(self, status=None):
        outer = self
        self.lock = threading.Lock()
        self.status = {'loaded': True} if status is None else status
        self.delay = {}
        self.reset_others = False
        self.reset_kills_status = False
        self.log = []
        self.inflight = 0
        self.peak = 0

        class _H(http.server.BaseHTTPRequestHandler):
            def _handle(self):
                u = urllib.parse.urlsplit(self.path)
                n = int(self.headers.get('Content-Length') or 0)
                if n:
                    self.rfile.read(n)
                q = {k: v[-1] for k, v in urllib.parse.parse_qs(u.query, keep_blank_values=True).items()}
                with outer.lock:
                    outer.log.append((self.command, u.path, q))
                    is_status = u.path == '/status'
                    payload = outer.status if is_status else None
                    reset = (outer.status is None) if is_status else outer.reset_others
                    if reset and not is_status and outer.reset_kills_status:
                        outer.status = None
                    delay = outer.delay.get(u.path, 0.0)
                if reset:
                    _abort_on_close(self.connection)
                    self.close_connection = True
                    return
                if not is_status:
                    with outer.lock:
                        outer.inflight += 1
                        outer.peak = max(outer.peak, outer.inflight)
                    try:
                        if delay:
                            time.sleep(delay)
                    finally:
                        with outer.lock:
                            outer.inflight -= 1
                    payload = {'ok': True, 'result': {'path': u.path}}
                raw = json.dumps(payload).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(raw)

            do_GET = do_POST = _handle

            def log_message(self, *a):
                pass

        class _Srv(socketserver.ThreadingTCPServer):
            daemon_threads = True
            request_queue_size = 128            # never the bottleneck: the bridge's gate is what is under test

            def handle_error(self, request, client_address):
                if not isinstance(sys.exc_info()[1], OSError):   # a peer that went away is expected here
                    socketserver.ThreadingTCPServer.handle_error(self, request, client_address)

        self.httpd = _Srv(('127.0.0.1', 0), _H)
        self.url = 'http://127.0.0.1:%d' % self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def count(self, method, path):
        with self.lock:
            return sum(1 for m, p, _ in self.log if (m, p) == (method, path))

    def probes(self):
        """The gate's classification requests: unscoped GET /status."""
        with self.lock:
            return sum(1 for m, p, q in self.log if (m, p) == ('GET', '/status') and 'binary' not in q)

    def busy(self):
        with self.lock:
            return self.inflight

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@unittest.skipUnless(os.path.isfile(os.path.join(H.plugin_dir(), 'bridge', 'binja_mcp_bridge.py')),
                     'no bridge/binja_mcp_bridge.py in the plugin tree')
class BridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _importable():
            raise unittest.SkipTest('mcp/requests/anyio are not importable here (see VenvRerun)')
        cls.b = load_bridge()
        cls.handler = H.StubHTTP()
        cls.url = cls.handler.url
        cls.saved_url = cls.b.binja_server_url
        cls.b.binja_server_url = cls.url

    @classmethod
    def tearDownClass(cls):
        cls.b.binja_server_url = cls.saved_url
        cls.handler.close()

    def setUp(self):
        self.handler.reset()
        self.b.binja_server_url = self.url

    def route(self, path, status, payload, method=None):
        self.handler.routes[(method, path) if method else path] = (status, payload)

    def last(self, path=None):
        rows = [r for r in self.handler.log if path is None or r['path'] == path]
        self.assertTrue(rows, 'no request to %s' % path)
        return rows[-1]

    # --------------------------------------------------------------------------------------------------------
    def test_identifiers_with_plus_ampersand_and_hash_arrive_intact(self):
        self.route('/decompile', 200, {'decompiled': 'body', '_binary': {'filename': 'C:/f/x+y&z#w.dll'}})
        name = 'a+b&c#d e%41'
        sel = 'C:\\dir\\x+y&z#w.dll'
        out = self.b.decompile_function(name, binary=sel)
        q = self.last('/decompile')['query']
        self.assertEqual(q['name'], name)
        self.assertEqual(q['binary'], sel)
        self.assertNotIn('max_lines', q)                 # 0 caps are not sent (server default = uncapped)
        self.assertTrue(out.startswith('File: C:/f/x+y&z#w.dll\n\nbody'), out)
        self.route('/x/decompile', 200, {'ok': True, 'result': {'text': 't'}})
        out = json.loads(self.b.bn_decompile('op+&#=?', binary='sel#1&x=2'))
        q = self.last('/x/decompile')['query']
        self.assertEqual((q['function'], q['binary'], q['ssa']), ('op+&#=?', 'sel#1&x=2', '0'))
        self.assertTrue(out['ok'])
        self.b.get_il('x&y=1#z', binary='b+c')
        q = self.last('/il')['query']
        self.assertEqual((q['name'], q['binary']), ('x&y=1#z', 'b+c'))

    def test_legacy_tools_are_registered_with_binary_and_new_tools_exist(self):
        tm = self.b.mcp._tool_manager
        tools = {t.name: t for t in tm.list_tools()}
        legacy = baseline_legacy_tools()
        self.assertEqual(len(legacy), 53)
        self.assertEqual(sorted(set(legacy) - set(tools)), [])
        for name in legacy:
            with self.subTest(tool=name):
                fn = getattr(self.b, name)
                params = list(inspect.signature(fn).parameters.values())
                if name in EXEMPT_LEGACY:
                    self.assertNotIn('binary', [p.name for p in params])
                else:
                    self.assertEqual(params[-1].name, 'binary')
                    self.assertEqual(params[-1].default, '')
                    self.assertIn('binary', tools[name].parameters['properties'])
        self.assertEqual(sorted(n for n in tools if n.startswith('bn_')), sorted(BN_SIGNATURES))
        self.assertEqual(len(tools), 53 + len(BN_SIGNATURES))
        for name, want in BN_SIGNATURES.items():
            with self.subTest(tool=name):
                sig = inspect.signature(getattr(self.b, name))
                got = [(p.name, REQ if p.default is inspect.Parameter.empty else p.default)
                       for p in sig.parameters.values()]
                self.assertEqual(got, want)

    def test_every_tool_forwards_the_selector_and_hits_its_route(self):
        """Table-driven over EVERY registered tool, called through FastMCP (the path an agent uses):
        * a tool with a `binary` parameter, called with binary=<sentinel>, makes at least one request and EVERY
          request it makes (follow-up pages, delegated calls and the POST->GET fallback included) carries
          binary=<sentinel>; a tool without one never sends `binary`;
        * a bn_* tool makes exactly one request, to a (method, path) the plugin routes to the verb of the same
          name, and every routed verb has a tool (the stub answers unrouted paths 200, so only this check can
          see a mis-routed verb);
        * a legacy tool requests only paths its baseline (upstream) counterpart requests."""
        get_routes, post_routes = server_routes()
        base_paths = baseline_legacy_paths()
        tools = {t.name: t for t in self.b.mcp._tool_manager.list_tools()}
        takes_binary = {n for n in tools if 'binary' in inspect.signature(getattr(self.b, n)).parameters}
        no_binary = set(EXEMPT_LEGACY) | {n for n, sig in BN_SIGNATURES.items() if 'binary' not in [a for a, _ in sig]}
        self.assertEqual(sorted(set(tools) - takes_binary), sorted(no_binary))
        self.assertEqual(len(takes_binary), len(tools) - len(no_binary))
        self.assertEqual(sorted(set(VARIANTS) - set(tools)), [])

        def pager(rec):                         # 2 rows at offset 0 (= batch_size 2), then 1 row: two pages
            off = int(rec['query'].get('offset') or 0)
            return 200, {'strings': [{'address': hex(0x1000 + off + i), 'length': 1, 'type': 'ascii', 'value': 's'}
                                     for i in range(2 if off == 0 else 1)]}

        self.handler.routes['/strings'] = pager
        runs = {}                               # (tool, variant, mode) -> [(method, path, query)] | 'EXC ...'

        async def drive():
            for name in sorted(tools):
                for vi, extra in enumerate(VARIANTS.get(name, [{}])):
                    kw = dict(required_args(getattr(self.b, name)), **extra)
                    if name in takes_binary:
                        kw['binary'] = SENTINEL
                    del self.handler.log[:]
                    try:
                        await self.b.mcp.call_tool(name, kw)
                    except Exception as e:
                        runs[(name, vi, 'A')] = 'EXC %s: %s' % (type(e).__name__, e)
                        continue
                    reqs = [(r['method'], r['path'], dict(r['query'])) for r in self.handler.log]
                    runs[(name, vi, 'A')] = reqs
                    posts = sorted({p for m, p, _ in reqs if m == 'POST'})
                    if not posts:
                        continue
                    for p in posts:             # mode B: the same call against a server that has no POST form
                        self.handler.routes[('POST', p)] = (405, {'error': 'no POST form'})
                    del self.handler.log[:]
                    try:
                        await self.b.mcp.call_tool(name, kw)
                    except Exception as e:
                        runs[(name, vi, 'B')] = 'EXC %s: %s' % (type(e).__name__, e)
                    else:
                        runs[(name, vi, 'B')] = [(r['method'], r['path'], dict(r['query'])) for r in self.handler.log]
                    for p in posts:
                        self.handler.routes.pop(('POST', p), None)

        asyncio.run(drive())
        self.assertEqual(sorted({k[0] for k in runs}), sorted(tools))
        verbs = {}
        for (name, vi, mode), reqs in sorted(runs.items()):
            with self.subTest(tool=name, variant=vi, mode=mode):
                self.assertIsInstance(reqs, list, reqs)
                self.assertTrue(reqs, 'the call made no request')
                if name.startswith('bn_') and mode == 'A':
                    method, path, _ = reqs[0]
                    verb = {'GET': get_routes, 'POST': post_routes}.get(method, {}).get(path)
                    if verb is not None:        # recorded first: the coverage check below then reports only route gaps
                        verbs.setdefault(verb, set()).add(name)
                    self.assertEqual(len(reqs), 1, reqs)
                    self.assertEqual(verb, name[3:], '%s %s routes to %r' % (method, path, verb))
                for method, path, q in reqs:
                    if name in takes_binary:
                        self.assertEqual(q.get('binary'), SENTINEL, '%s %s dropped/changed the selector' % (method, path))
                    else:
                        self.assertNotIn('binary', q, '%s %s sent a selector' % (method, path))
                    if not name.startswith('bn_'):
                        self.assertIn(path, base_paths.get(name, set()), '%s %s is not a baseline path' % (method, path))
        self.assertEqual(sorted(verbs), sorted(set(post_routes.values())), 'a routed verb has no bn_* tool')
        self.assertEqual(sorted(n for n, owners in verbs.items() if len(owners) > 1), [])
        # the follow-up / delegated / fallback requests above were really driven
        for key in (('list_all_strings', 0, 'A'), ('hexdump_data', 0, 'A'), ('hexdump_data', 1, 'A')):
            self.assertIsInstance(runs.get(key), list, '%s: %r' % (key, runs.get(key)))
        self.assertEqual([(m, p, q.get('offset')) for m, p, q in runs[('list_all_strings', 0, 'A')]],
                         [('GET', '/strings', '0'), ('GET', '/strings', '2')])
        self.assertEqual([p for _, p, _ in runs[('hexdump_data', 0, 'A')]], ['/hexdump'])
        self.assertEqual([p for _, p, _ in runs[('hexdump_data', 1, 'A')]], ['/hexdumpByName'])
        fallback = {k[0] for k, reqs in runs.items() if k[2] == 'B' and isinstance(reqs, list)
                    and [m for m, _, _ in reqs] == ['POST', 'GET'] and reqs[0][1] == reqs[1][1]}
        self.assertEqual(sorted(fallback), sorted(POST_FALLBACK_TOOLS))

    def test_registered_tools_are_coroutines_with_the_original_schema(self):
        """The _threaded wrapper must keep FastMCP's schema = the original signature (functools.wraps)."""
        tools = self.b.mcp._tool_manager.list_tools()
        for t in tools:
            with self.subTest(tool=t.name):
                self.assertTrue(inspect.iscoroutinefunction(t.fn), t.name)
                self.assertTrue(getattr(t, 'is_async', True))
                sig = inspect.signature(getattr(self.b, t.name))
                self.assertEqual(list(t.parameters.get('properties', {})), list(sig.parameters))
                req = [p.name for p in sig.parameters.values() if p.default is inspect.Parameter.empty]
                self.assertEqual(sorted(t.parameters.get('required', [])), sorted(req))
                self.assertFalse(inspect.iscoroutinefunction(getattr(self.b, t.name)),
                                 'the module-level name must stay the plain function')
        listed = asyncio.run(self.b.mcp.list_tools())
        self.assertEqual(len(listed), len(tools))
        self.route('/x/compute', 200, {'ok': True, 'result': {'dec': '3'}})
        res = asyncio.run(self.b.mcp.call_tool('bn_compute', {'expr': '1+2'}))
        self.assertIn('"dec":"3"', str(res))        # the tool's compact JSON text, inside FastMCP's result

    def test_a_truncated_legacy_reply_shows_the_trailer(self):
        echo = {'filename': 'C:/f/foo.dll'}
        self.route('/decompile', 200, {'decompiled': 'l1\nl2', 'truncated': True, 'returned_lines': 2,
                                       'total_lines': 5, 'next_line_offset': 2, '_binary': echo})
        out = self.b.decompile_function('main', max_lines=2)
        self.assertTrue(out.endswith('\n[TRUNCATED: returned 2 of 5 lines; re-call with line_offset=2]'), out)
        self.assertEqual(self.last('/decompile')['query']['max_lines'], '2')
        self.route('/il', 200, {'il': 'x', 'truncated': True, 'returned_lines': 1, 'total_lines': 1,
                                'next_line_offset': None, '_binary': echo})
        out = self.b.get_il('main', max_chars=100)
        self.assertIn('a line was cut at max_chars; re-call with a larger max_chars]', out)
        self.route('/assembly', 200, {'assembly': 'a\nb', 'truncated': False, 'returned_lines': 2, 'total_lines': 2,
                                      'next_line_offset': None, '_binary': echo})
        out = self.b.fetch_disassembly('main')
        self.assertTrue(out.endswith('a\nb'), out)
        self.assertNotIn('TRUNCATED', out)

    def test_a_409_shows_the_candidates(self):
        amb = {'error': 'AMBIGUOUS: 2 functions match dup: dup@0x140001400; dup@0x140001480',
               'error_code': 'AMBIGUOUS', 'candidates': [{'name': 'dup', 'start': '0x140001400'},
                                                         {'name': 'dup', 'start': '0x140001480'}]}
        for path, call in (('/decompile', lambda: self.b.decompile_function('dup')),
                           ('/il', lambda: self.b.get_il('dup')),
                           ('/assembly', lambda: self.b.fetch_disassembly('dup'))):
            with self.subTest(path=path):
                self.route(path, 409, amb)
                out = call()
                self.assertIn('Error: AMBIGUOUS: 2 functions match dup', out)
                self.assertIn('Candidates', out)
                self.assertIn('  dup@0x140001400', out)
                self.assertIn('  dup@0x140001480', out)
        self.route('/x/decompile', 409, dict(amb, ok=False, verb='decompile'))
        out = json.loads(self.b.bn_decompile('dup', binary='foo.dll'))
        self.assertEqual((out['ok'], out['error_code'], out['http_status'], len(out['candidates'])),
                         (False, 'AMBIGUOUS', 409, 2))

    def test_get_binary_status_carries_the_bridge_contract(self):
        self.route('/status', 200, {'loaded': True, 'filename': 'x.dll',
                                    'server': {'contract': 'binja-agent-mcp/1', 'version': '1.0.0'}})
        out = json.loads(self.b.get_binary_status())
        self.assertEqual(out['bridge'], {'contract': 'binja-agent-mcp/1', 'version': '1.0.0', 'toolset': 'full',
                                         'tools': 86, 'output_cap_chars': 48000})
        self.assertEqual(out['server']['contract'], 'binja-agent-mcp/1')
        self.assertNotIn('binary', self.last('/status')['query'])
        json.loads(self.b.get_binary_status(binary='C:\\a\\x.dll'))
        self.assertEqual(self.last('/status')['query']['binary'], 'C:\\a\\x.dll')
        self.b.binja_server_url = 'http://127.0.0.1:%d' % H.free_port()
        out = json.loads(self.b.get_binary_status())
        self.assertEqual(out['bridge']['contract'], 'binja-agent-mcp/1')
        self.assertIn('error', out)
        self.assertNotIn('server', out)

    def test_load_binary_is_one_post_with_request_id_and_deadline(self):
        """bn_load_binary sends ONE POST to /x/loadBinary whose body carries request_id (uuid4 hex) and deadline_ms
        (the call's remaining budget minus 3000 ms, never above it); a refused POST is never retried as a GET."""
        import re as _re
        self.b.bn_load_binary('C:\\x\\a.exe')
        r = self.last('/x/loadBinary')
        body = json.loads(r['body'])
        self.assertEqual(r['method'], 'POST')
        self.assertEqual((body['filepath'], body['wait']), ('C:\\x\\a.exe', 0))
        self.assertTrue(_re.match(r'^[0-9a-f]{32}$', body['request_id']), body)
        self.assertTrue(0 < body['deadline_ms'] <= int(self.b.CALL_DEADLINE_S * 1000) - 3000, body)
        self.b.bn_load_binary('C:\\x\\a.exe')
        self.assertNotEqual(json.loads(self.last('/x/loadBinary')['body'])['request_id'], body['request_id'])
        self.route('/x/loadBinary', 405, {'error': 'no POST'}, method='POST')
        del self.handler.log[:]
        out = json.loads(self.b.bn_load_binary('C:\\x\\a.exe'))
        self.assertFalse(out['ok'])
        self.assertEqual([x['method'] for x in self.handler.log], ['POST'], 'never a GET fallback')

    def test_patch_bytes_defaults_to_no_save(self):
        sig = inspect.signature(self.b.patch_bytes)
        self.assertIs(sig.parameters['save_to_file'].default, False)
        self.route('/patch', 200, {'status': 'ok', 'address': '0x1', 'original_bytes': '00', 'patched_bytes': '90',
                                   'bytes_written': 1, 'bytes_requested': 1, 'saved_to_file': False,
                                   'save_refused': True, 'save_error': 'refused by policy'})
        out = self.b.patch_bytes('0x1', '90')
        q = self.last('/patch')['query']
        self.assertEqual(q['save_to_file'].lower(), 'false')
        self.assertIn('Patched 1/1 bytes at 0x1', out)
        self.assertIn('File not saved - refused by policy', out)

    def test_required_binary_is_refused_locally_and_post_bodies(self):
        for args in (('',), ('  ',)):
            with self.subTest(binary=args):
                out = json.loads(self.b.bn_close_binary(*args))
                self.assertEqual((out['ok'], out['error_code']), (False, 'BAD_ARGUMENT'))
        self.assertEqual(self.handler.log, [])
        self.route('/x/batch', 200, {'ok': True, 'result': {'items': []}})
        self.b.bn_batch('[{"verb":"compute","params":{"expr":"1"}}]', binary='foo.dll')
        r = self.last('/x/batch')
        self.assertEqual(r['method'], 'POST')
        self.assertEqual(json.loads(r['body'])['items'], '[{"verb":"compute","params":{"expr":"1"}}]')
        self.assertEqual(r['query']['binary'], 'foo.dll')
        self.b.bn_close_binary('foo.dll')
        r = self.last('/x/closeBinary')
        self.assertEqual((r['method'], json.loads(r['body']), r['query']), ('POST', {}, {'binary': 'foo.dll'}))
        self.route('/defineTypes', 405, {'error': 'no POST'}, method='POST')
        self.route('/defineTypes', 200, {'T': 'struct T'}, method='GET')
        out = self.b.define_types('struct T { int a; };')
        self.assertEqual([x['method'] for x in self.handler.log if x['path'] == '/defineTypes'], ['POST', 'GET'])
        self.assertIn('T', out)

    def test_transport_failures_are_structured(self):
        self.b.binja_server_url = 'http://127.0.0.1:%d' % H.free_port()
        out = json.loads(self.b.bn_server_info())
        self.assertEqual((out['ok'], out['error_code']), (False, 'UNREACHABLE'))
        self.assertTrue(self.b.decompile_function('main').startswith('File: '))

    def test_a_reply_without_an_echo_marks_the_requested_binary_unconfirmed(self):
        """bridge _file_name: a legacy reply that carries no `_binary` echo (an older plugin) names the requested
        selector only as unconfirmed, never as the binary that answered."""
        self.route('/decompile', 200, {'decompiled': 'body'})
        out = self.b.decompile_function('main', binary='C:\\a\\x.dll')
        self.assertTrue(out.startswith('File: C:\\a\\x.dll (requested; the server did not confirm which binary '
                                       'answered)\n\nbody'), out)

    # --- concurrency: the HTTP gate, the retry policy, the off-loop tool threads, the respond-once guard ----------
    def conc_stub(self, status=None):
        """A fresh _ConcStub that the bridge talks to for the rest of this test (removed, with its gate, after it)."""
        stub = _ConcStub(status)
        self.addCleanup(self._drop_conc_stub, stub)
        self.b.binja_server_url = stub.url
        return stub

    def _drop_conc_stub(self, stub):
        self.b.binja_server_url = self.url
        gates, lock = getattr(self.b, '_GATES', None), getattr(self.b, '_GATES_LOCK', None)
        if isinstance(gates, dict) and lock is not None:
            with lock:
                gates.pop(stub.url, None)
        stub.close()

    def test_the_http_gate_bounds_concurrency_by_the_probed_server_kind(self):
        """bridge _HttpGate / _probe_server: concurrent tool calls (run through FastMCP, as an agent's are) reach a
        server whose /status has no `server` block (the upstream plugin: single-threaded, listen backlog 5) or
        says threaded:false ONE at a time; server.threaded:true widens the gate to min(64, request_queue_size).
        However many calls arrive together, the server is classified by exactly ONE unscoped GET /status."""
        calls = 6

        async def burst():
            return await asyncio.gather(*[self.b.mcp.call_tool('bn_decompile', {'function': 'f%d' % i,
                                                                                'binary': 'foo.dll'})
                                          for i in range(calls)])
        cases = (('no server block (upstream)', {'loaded': True}, 1, 1),
                 ('threaded false', {'loaded': True, 'server': {'threaded': False}}, 1, 1),
                 ('threaded, request_queue_size 2',
                  {'loaded': True, 'server': {'threaded': True, 'request_queue_size': 2}}, 2, 2),
                 ('threaded', {'loaded': True, 'server': {'threaded': True}}, 2, calls))
        for label, status, lo, hi in cases:
            with self.subTest(server=label):
                stub = self.conc_stub(status)
                stub.delay['/x/decompile'] = 0.3
                res = asyncio.run(burst())
                self.assertEqual(len(res), calls)
                for r in res:
                    self.assertIn('"ok":true', str(r))
                self.assertEqual(stub.count('GET', '/x/decompile'), calls)
                self.assertEqual(stub.probes(), 1, 'the server must be classified by exactly one unscoped /status')
                self.assertGreaterEqual(stub.peak, lo, 'peak in-flight %d < %d' % (stub.peak, lo))
                self.assertLessEqual(stub.peak, hi, 'peak in-flight %d > %d' % (stub.peak, hi))

    def test_only_read_only_requests_are_retried_after_a_transport_error(self):
        """bridge _req / _read_only: after a transport error (the connection is reset unanswered) a read-only GET
        is retried len(_RETRY_DELAYS) times while the re-probe still finds a server; every POST and every mutating
        GET is sent exactly ONCE. A transport error resets the gate's classification (the next call re-probes);
        a re-probe that finds no server ends the retries, a dead server costs no probe per call, and the first
        answer while it is 'down' makes the next call probe again."""
        stub = self.conc_stub({'loaded': True})
        stub.reset_others = True
        retries = len(self.b._RETRY_DELAYS)
        self.assertGreaterEqual(retries, 1)

        def unreachable(text):
            out = json.loads(text)
            self.assertEqual((out['ok'], out['error_code']), (False, 'UNREACHABLE'), out)

        unreachable(self.b.bn_load_binary('C:\\x\\a.exe'))
        self.assertEqual((stub.count('POST', '/x/loadBinary'), stub.probes()), (1, 1))
        unreachable(self.b.bn_batch('[{"verb":"compute","params":{"expr":"1"}}]', binary='foo.dll'))
        self.assertEqual((stub.count('POST', '/x/batch'), stub.probes()), (1, 2),
                         'a transport error must reset the classification (the next call re-probes)')
        unreachable(self.b.bn_close_binary('foo.dll'))
        self.b.set_comment('0x1000', 'c')
        self.b.select_binary('foo.dll')
        self.b.retype_variable('fn', 'v', 'int')
        for method, path in (('POST', '/x/loadBinary'), ('POST', '/x/batch'), ('POST', '/x/closeBinary'),
                             ('POST', '/comment'), ('GET', '/selectBinary'), ('GET', '/retypeVariable')):
            with self.subTest(mutating=path):
                self.assertEqual(stub.count(method, path), 1, '%s %s must never be retried' % (method, path))

        with concurrent.futures.ThreadPoolExecutor(2) as ex:   # the two backoff schedules run side by side
            f_x = ex.submit(self.b.bn_decompile, 'main', binary='foo.dll')
            f_legacy = ex.submit(self.b.decompile_function, 'main')
            unreachable(f_x.result(timeout=120))
            legacy = f_legacy.result(timeout=120)
        self.assertTrue(legacy.startswith('File: ') and 'Request failed' in legacy, legacy)
        for path in ('/x/decompile', '/decompile'):
            with self.subTest(read_only=path):
                self.assertEqual(stub.count('GET', path), 1 + retries, 'GET %s retry count' % path)

        stub = self.conc_stub({'loaded': True})     # a fresh (unprobed) gate; the server dies with its first reset
        stub.reset_others = stub.reset_kills_status = True
        unreachable(self.b.bn_decompile('main', binary='foo.dll'))
        self.assertEqual((stub.count('GET', '/x/decompile'), stub.probes()), (1, 2),
                         'one send, the probe before it and the re-probe that found no server; no retry')
        sent, probes = stub.count('GET', '/x/decompile'), stub.probes()
        unreachable(self.b.bn_decompile('main', binary='foo.dll'))
        self.assertEqual((stub.count('GET', '/x/decompile') - sent, stub.probes() - probes), (1, 0),
                         "a call while 'down' is sent once and costs no probe")

        with stub.lock:                              # the server comes back
            stub.status, stub.reset_others, stub.reset_kills_status = {'loaded': True}, False, False
        probes = stub.probes()
        self.assertTrue(json.loads(self.b.bn_decompile('main', binary='foo.dll'))['ok'])
        self.assertEqual(stub.probes() - probes, 0, "the first call while 'down' is sent without a probe")
        self.assertTrue(json.loads(self.b.bn_decompile('main', binary='foo.dll'))['ok'])
        self.assertEqual(stub.probes() - probes, 1, "an answer while 'down' makes the next call re-probe")

    def test_tool_bodies_run_off_the_event_loop_on_their_own_limiter(self):
        """bridge _threaded / _tool_limiter: a registered tool's body runs in a worker thread, so a slow call does
        not hold up another call (or the stdio transport) on the event loop, and those threads come from the
        bridge's OWN limiter, never from anyio's default one (which mcp's stdio transport uses)."""
        import anyio
        import anyio.to_thread
        stub = self.conc_stub({'loaded': True, 'server': {'threaded': True}})
        stub.delay['/x/decompile'] = 1.0
        done, seen = [], {}

        async def call(name, args):
            await self.b.mcp.call_tool(name, args)
            done.append(name)

        async def sample():
            t_end = time.monotonic() + 5.0
            while not stub.busy() and time.monotonic() < t_end:
                await asyncio.sleep(0.01)
            seen['slow_in_flight'] = stub.busy() > 0
            seen['default_borrowed'] = anyio.to_thread.current_default_thread_limiter().borrowed_tokens
            lim = self.b._tool_limiter()
            seen['tool_borrowed'], seen['tool_total'] = lim.borrowed_tokens, lim.total_tokens

        async def go():
            await asyncio.gather(call('bn_decompile', {'function': 'slow', 'binary': 'foo.dll'}),
                                 call('bn_close_binary', {'binary': ''}),     # refused locally: no request
                                 sample())
        asyncio.run(go())
        self.assertEqual(done, ['bn_close_binary', 'bn_decompile'], 'the fast call waited for the slow one')
        self.assertTrue(seen['slow_in_flight'], 'the event loop was blocked while the slow call ran: %r' % seen)
        self.assertEqual(seen['default_borrowed'], 0, "a tool thread used anyio's default limiter: %r" % seen)
        self.assertGreaterEqual(seen['tool_borrowed'], 1, seen)
        self.assertEqual(seen['tool_total'], self.b._TOOL_THREADS, seen)

    def test_the_respond_once_guard_absorbs_only_a_client_cancel(self):
        """bridge _install_respond_once_guard, driven on a REAL mcp RequestResponder: after the client's cancel
        (cancel() already sent 'Request cancelled') a late respond() is dropped instead of failing `assert not
        self._completed`, and a cancel that lands while respond() is sending ends it quietly instead of raising the
        CancelledError out of the responder (either would kill the server TaskGroup); a normal respond() and any
        other cancellation (e.g. a transport close) go through unchanged."""
        import anyio
        import anyio.lowlevel
        from mcp.shared import session as mcp_session
        rr = mcp_session.RequestResponder
        class Sess(object):
            def __init__(self):
                self.sent, self.hook = [], None

            async def _send_response(self, request_id, response):
                self.sent.append((request_id, getattr(response, 'message', response)))
                if self.hook is not None:
                    hook, self.hook = self.hook, None
                    await hook()

        async def scenario(kind):
            sess = Sess()
            r = rr(request_id=7, request_meta=None, request=None, session=sess, on_complete=lambda _r: None)
            raised = None
            try:
                if kind == 'late':
                    with r:
                        await r.cancel()
                        await r.respond('late result')
                else:
                    async def client_cancel():           # notifications/cancelled while the answer is written
                        await r.cancel()
                        await anyio.lowlevel.checkpoint()

                    async def transport_close():         # a cancellation that is NOT the client's
                        raise anyio.get_cancelled_exc_class()('transport closed')
                    sess.hook = {'in-send': client_cancel, 'other': transport_close}.get(kind)
                    with r:
                        await r.respond('result')
            except BaseException as e:                   # CancelledError / AssertionError are outcomes here
                raised = type(e).__name__
            return raised, sess.sent

        want = {'late': (None, [(7, 'Request cancelled')]),
                'in-send': (None, [(7, 'result'), (7, 'Request cancelled')]),
                'normal': (None, [(7, 'result')]),
                'other': ('CancelledError', [(7, 'result')])}
        for kind, expected in want.items():
            with self.subTest(scenario=kind):
                self.assertEqual(asyncio.run(scenario(kind)), expected)

        self.assertIs(getattr(rr.respond, '_bnmcp_respond_once', False), True,
                      'the respond-once guard is not installed on mcp RequestResponder.respond')
        guard = rr.respond
        self.b._install_respond_once_guard()         # idempotent: a second install must not wrap the guard
        self.assertIs(rr.respond, guard)
        inner = getattr(guard, '__wrapped__', None)
        self.assertTrue(callable(inner), 'the guard must wrap the original respond (functools.wraps)')
        self.assertFalse(getattr(inner, '_bnmcp_respond_once', False), 'the guard wraps itself')


@unittest.skipUnless(os.path.isfile(os.path.join(H.plugin_dir(), 'bridge', 'binja_mcp_bridge.py')),
                     'no bridge/binja_mcp_bridge.py in the plugin tree')
class BridgeTransportTests(unittest.TestCase):
    """Where the bridge sends requests: the loopback server of BN_MCP_URL, never through a proxy; the /status probe
    within the call deadline; the parent watchdog's process selection."""

    @classmethod
    def setUpClass(cls):
        if not _importable():
            raise unittest.SkipTest('mcp/requests/anyio are not importable here (see VenvRerun)')
        cls.b = load_bridge()

    def test_requests_ignore_proxy_environment_variables(self):
        import requests
        stub = H.StubHTTP()
        self.addCleanup(stub.close)
        stub.routes['/x/serverInfo'] = (200, {'ok': True, 'result': {'contract': H.CONTRACT}})
        stub.routes['/status'] = (200, {'loaded': False, 'server': {'threaded': True}})
        dead = 'http://127.0.0.1:%d' % H.free_port()           # nothing listens there
        env = {'HTTP_PROXY': dead, 'http_proxy': dead, 'HTTPS_PROXY': dead, 'ALL_PROXY': dead}
        saved = {k: os.environ.get(k) for k in list(env) + ['NO_PROXY', 'no_proxy']}

        def restore():
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.addCleanup(restore)
        os.environ.update(env)
        os.environ.pop('NO_PROXY', None)
        os.environ.pop('no_proxy', None)
        # the test means something only if requests itself would use the proxy for this URL
        self.assertIn('http', requests.utils.get_environ_proxies(stub.url + '/status'))
        saved_url = self.b.binja_server_url
        self.addCleanup(setattr, self.b, 'binja_server_url', saved_url)
        self.b.binja_server_url = stub.url
        out = json.loads(self.b.bn_server_info())
        self.assertTrue(out['ok'], out)
        self.assertEqual(self.b._probe_server(stub.url)[0], 'threaded')
        self.assertEqual([r['path'] for r in stub.log][-1], '/status')

    def test_bn_mcp_url_accepts_the_loopback_server_only(self):
        f = self.b.server_url_from_env
        for raw, want in (('', 'http://127.0.0.1:9009'), ('http://127.0.0.1:9100', 'http://127.0.0.1:9100'),
                          ('http://LOCALHOST:9009/', 'http://localhost:9009')):
            with self.subTest(raw=raw):
                self.assertEqual(f(raw), (want, ''))
        for raw in ('http://192.0.2.1:9009', 'http://example.com:9009', 'https://127.0.0.1:9009',
                    'http://127.0.0.1', 'http://127.0.0.1:9009/x', 'http://u:p@127.0.0.1:9009', 'http://[::1]:9009',
                    'http://127.0.0.1:notaport'):
            with self.subTest(raw=raw):
                url, err = f(raw)
                self.assertEqual(url, 'http://127.0.0.1:9009')
                self.assertIn('BN_MCP_URL', err)
        env = dict(os.environ, BN_MCP_URL='http://example.com:9009')
        p = subprocess.run([sys.executable, '-I', '-B', bridge_path()], capture_output=True, text=True, timeout=120,
                           env=env, stdin=subprocess.DEVNULL)
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertIn('not starting', p.stderr)
        self.assertIn('BN_MCP_URL', p.stderr)

    def test_the_status_probe_stays_inside_the_call_deadline(self):
        b = self.b
        self.assertEqual(b._probe_timeout(None), b._PROBE_TIMEOUT)
        now = time.monotonic()
        c, r = b._probe_timeout(now + 3.0)
        self.assertLessEqual(c, b._PROBE_TIMEOUT[0])
        self.assertLessEqual(r, 3.0)
        stub = _ConcStub({'loaded': True})
        self.addCleanup(stub.close)
        gate = b._HttpGate(stub.url)
        with self.assertRaises(b._CallDeadline):
            gate.acquire(time.monotonic() + b._MIN_ATTEMPT_S / 2)   # too little left to start a probe
        self.assertEqual(stub.probes(), 0, 'no probe was sent')
        self.assertEqual(gate.state, 'unprobed')
        state, gen = gate.acquire(time.monotonic() + 30.0)
        gate.release(gen, True)
        self.assertEqual((state, stub.probes()), ('serial', 1))

    def test_the_watchdog_watches_the_client_behind_a_venv_launcher(self):
        wt = self.b._watch_targets
        parents = {100: 50}
        exe = os.path.join(os.sep, 'venv', 'Scripts', 'python.exe')
        base = os.path.join(os.sep, 'py', 'python.exe')
        self.assertEqual(wt(100, exe, exe, base, parents.get), [100, 50], 'the launcher and the MCP client')
        self.assertEqual(wt(100, os.path.join(os.sep, 'client.exe'), exe, base, parents.get), [100])
        self.assertEqual(wt(100, exe, exe, exe, parents.get), [100], 'no venv: the parent is the client')
        self.assertEqual(wt(100, exe, exe, base, {}.get), [100], 'the launcher parent cannot be found')
        if sys.platform == 'win32':
            me = self.b._win32_open(os.getpid())
            self.assertIsNotNone(me)
            self.assertTrue(self.b._win32_alive(me))
            self.assertEqual(os.path.normcase(self.b._win32_image(me)),
                             os.path.normcase(os.path.abspath(getattr(sys, '_base_executable', sys.executable))))
            self.assertEqual(self.b._win32_parent_of(os.getpid()), os.getppid())

    def test_the_binary_parameter_carries_one_short_description(self):
        defs = self.b.tool_definitions()
        with_binary = [d for d in defs if 'binary' in d['inputSchema'].get('properties', {})]
        self.assertGreater(len(with_binary), 70)
        for d in with_binary:
            with self.subTest(tool=d['name']):
                self.assertEqual(d['inputSchema']['properties']['binary']['description'], 'selector from list_binaries')
                self.assertNotIn('binary: optional selector', d['description'])

    def test_an_output_cap_above_50000_is_declared_to_the_client(self):
        big = import_bridge('bnmcp_bridge_bigcap', {'BN_MCP_TOOLSET': 'core', 'BN_MCP_TOOLS': None,
                                                     'BN_MCP_MAX_OUTPUT_CHARS': '60000'})
        defs = big.tool_definitions()
        self.assertTrue(defs)
        for d in defs:
            self.assertEqual(d.get('_meta'), {'anthropic/maxResultSizeChars': 60000}, d['name'])
        small = import_bridge('bnmcp_bridge_smallcap', {'BN_MCP_TOOLSET': 'core', 'BN_MCP_TOOLS': None,
                                                         'BN_MCP_MAX_OUTPUT_CHARS': '50000'})
        self.assertTrue(all('_meta' not in d for d in small.tool_definitions()))


class VenvRerun(unittest.TestCase):
    """When this interpreter cannot import mcp/requests, run BridgeTests under the bridge venv interpreter."""

    @unittest.skipIf(_importable() or os.environ.get('BN_MCP_TEST_BRIDGE_CHILD') == '1',
                     'the bridge is importable in this interpreter')
    def test_bridge_suite_under_the_bridge_venv(self):
        py = _venv_python()
        if not py:
            self.skipTest('SKIPPED: mcp/requests are not importable and no bridge venv interpreter was found')
        env = dict(os.environ, BN_MCP_TEST_BRIDGE_CHILD='1')
        p = subprocess.run([py, '-I', '-B', os.path.join(H.HERE, 'run_tests.py'), '--plugin', H.plugin_dir(),
                            '--client', H.client_path(), '-k', 'test_bridge.BridgeTests'],
                           capture_output=True, text=True, env=env, timeout=600)
        self.assertEqual(p.returncode, 0, p.stdout[-3000:] + p.stderr[-3000:])
        tail = [ln for ln in p.stderr.strip().splitlines() if ln.strip()][-1]
        self.assertTrue(tail.startswith('OK'), tail)
        self.assertNotIn('skipped', tail, 'the bridge suite was skipped under %s: %s' % (py, tail))


if __name__ == '__main__':
    unittest.main()
