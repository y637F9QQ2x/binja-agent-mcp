# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""Server hardening against callers and against text from analyzed binaries.

* Load paths: network and device paths are refused before any file-system call (a UNC path would make Windows
  connect to that host); the network-drive check, the realpath re-check and BN_MCP_ALLOW_NETWORK_PATHS; the cap on
  binaries the server loaded. No test opens a network path: os.path.isfile / realpath / stat are guarded so that a
  broken check fails the test instead of reaching the network.
* C text with #include and the like is refused before Binary Ninja's type parser sees it.
* patch_bytes(save_to_file) never writes over a .bndb database.
* BN_MCP_REQUIRE_TOKEN=0: requests without the token can read but not change anything.
* Idle connections are closed, the number of connections is capped, refusals are logged at most once a minute.
* The load paths take the global lock in lock_mode 'global'.
* Request data never reaches the Binary Ninja log: one debug line per request without the query string.
"""

import ast
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import run_tests as H

UNC = '\\\\attacker.example\\share\\x.exe'


def _is_network(p):
    s = str(p).replace('/', '\\')
    return s.startswith('\\\\')


class _NoNetworkFs(object):
    """Fail a test, instead of touching the network, when a guarded file-system function gets a UNC path."""

    def __init__(self, test):
        self.test = test
        self.patches = []
        for name in ('os.path.isfile', 'os.path.realpath', 'os.stat', 'os.path.exists'):
            real = getattr(os.path, name.split('.')[-1]) if name.startswith('os.path') else os.stat
            self.patches.append(mock.patch(name, side_effect=self._guard(real, name)))

    @staticmethod
    def _guard(real, name):
        def call(p, *a, **k):
            if _is_network(p):
                raise AssertionError('%s was called with the network path %r' % (name, p))
            return real(p, *a, **k)
        return call

    def __enter__(self):
        for p in self.patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self.patches):
            p.stop()


class LoadPathTests(unittest.TestCase):
    def setUp(self):
        self.m = H.plugin_modules()
        H.reset_plugin_state(self.m)
        self.td = tempfile.TemporaryDirectory(prefix='bnmcp-hard-')
        self.addCleanup(self.td.cleanup)
        self.fb = H.fake_bv()
        self.srv = H.Server(self.m)
        self.srv.start()
        self.addCleanup(self.srv.stop)
        self.bn = H.ensure_fake()
        self.loads = []
        orig = self.bn.load

        def spy(source, *a, **k):
            self.loads.append(str(source))
            return orig(source, *a, **k)
        self.bn.load = spy
        self.addCleanup(setattr, self.bn, 'load', orig)

    def test_the_string_rules(self):
        lp = self.m.bo.load_path_problem
        remote = {'Z:': True}

        def drive(p):
            return remote.get(p[:2].upper(), False)
        for path, allow, refused in (
                (UNC, False, True), (UNC, True, False), ('//host/share/x.exe', False, True),
                ('\\\\?\\UNC\\host\\share\\x.exe', True, True), ('\\\\.\\PhysicalDrive0', True, True),
                ('\\??\\C:\\x.exe', True, True), ('\\\\?\\C:\\x.exe', False, True), ('C:\\x\\a.exe', False, False),
                ('c:/x/a.exe', False, False), ('Z:\\x\\a.exe', False, True), ('Z:\\x\\a.exe', True, False),
                ('\\x\\a.exe', False, True), ('a.exe', False, True), ('', False, True)):
            with self.subTest(path=path, allow=allow):
                why = lp(path, allow_network=allow, win=True, drive_is_remote=drive)
                self.assertEqual(why is not None, refused, why)
        for path, allow, refused in (('/x/a.bin', False, False), ('//host/x', False, True), ('//host/x', True, False),
                                     ('x/a.bin', False, True), ('C:\\x\\a.exe', False, True)):
            with self.subTest(posix=path, allow=allow):
                self.assertEqual(lp(path, allow_network=allow, win=False) is not None, refused)

    @unittest.skipUnless(sys.platform == 'win32', 'UNC and device paths are Windows paths')
    def test_network_and_device_paths_are_refused_before_any_file_system_call(self):
        with _NoNetworkFs(self):
            for path in (UNC, '\\\\?\\UNC\\attacker.example\\share\\x.exe', '//attacker.example/share/x.exe',
                         '\\\\.\\PhysicalDrive0'):
                with self.subTest(path=path):
                    r = self.srv.post('/x/loadBinary', json_body={'filepath': path})
                    self.assertEqual((r.status, r.json['error_code']), (403, 'POLICY'), r.raw[:300])
                    self.assertIn('refused to open', r.json['error'])
                    r = self.srv.post('/load', json_body={'filepath': path})
                    self.assertEqual((r.status, r.json.get('error_code')), (403, 'POLICY'), r.raw[:300])
        self.assertEqual(self.loads, [], 'bn.load was never called')

    @unittest.skipUnless(sys.platform == 'win32', 'drive letters are Windows paths')
    def test_a_network_drive_and_a_link_to_a_share_are_refused(self):
        path = self.fb.make_standard_file(self.td.name, 'local.dll', 'L')
        bo = self.m.bo
        with mock.patch.object(bo, '_drive_is_remote', return_value=True):
            r = self.srv.post('/x/loadBinary', json_body={'filepath': path})
        self.assertEqual((r.status, r.json['error_code']), (403, 'POLICY'), r.raw[:300])
        self.assertIn('network drive', r.json['error'])
        # a local path whose realpath is on a share (a junction or link): refused after the realpath
        with mock.patch.object(bo.os.path, 'realpath', return_value='\\\\?\\UNC\\attacker.example\\s\\x.dll'):
            with self.assertRaises(self.m.rc.ApiError) as cm:
                bo.check_load_path(path)
        self.assertEqual((cm.exception.code, cm.exception.http_status), ('POLICY', 403))
        self.assertIn('resolves to \\\\attacker.example', str(cm.exception))
        self.assertEqual(self.loads, [])
        # BN_MCP_ALLOW_NETWORK_PATHS=1 (allow_network_paths) lifts the network-drive refusal
        self.srv.cfg.binary_ninja.allow_network_paths = True
        with mock.patch.object(bo, '_drive_is_remote', return_value=True):
            r = self.srv.post('/x/loadBinary', json_body={'filepath': path})
        self.assertEqual(r.status, 200, r.raw[:300])

    def test_the_server_holds_at_most_max_owned_views_binaries_it_loaded(self):
        self.srv.cfg.binary_ninja.max_owned_views = 2
        paths = [self.fb.make_standard_file(self.td.name, 'o%d.dll' % i, 'O%d' % i) for i in range(3)]
        for p in paths[:2]:
            r = self.srv.post('/x/loadBinary', json_body={'filepath': p})
            self.assertEqual(r.status, 200, r.raw[:300])
        r = self.srv.post('/x/loadBinary', json_body={'filepath': paths[2]})
        self.assertEqual((r.status, r.json['error_code']), (403, 'POLICY'), r.raw[:300])
        self.assertEqual(sorted(x['filename'] for x in r.json['owned']), sorted(paths[:2]))
        r = self.srv.post('/load', json_body={'filepath': paths[2]})
        self.assertEqual((r.status, r.json.get('error_code')), (403, 'POLICY'), r.raw[:300])
        r = self.srv.post('/x/loadBinary', json_body={'filepath': paths[0]})
        self.assertEqual((r.status, r.json['result']['reused']), (200, True), 'a reused view needs no room')
        vid = r.json['result']['view_id']
        self.assertEqual(self.srv.post('/x/closeBinary', params={'binary': 'view:' + vid}, json_body={}).status, 200)
        r = self.srv.post('/x/loadBinary', json_body={'filepath': paths[2]})
        self.assertEqual(r.status, 200, r.raw[:300])

    def test_config_reads_the_new_variables(self):
        cfgmod = self.m.config
        with mock.patch.dict(os.environ, {'BN_MCP_ALLOW_NETWORK_PATHS': '1', 'BN_MCP_MAX_OWNED': '3'}):
            c = cfgmod.Config()
        self.assertEqual((c.binary_ninja.allow_network_paths, c.binary_ninja.max_owned_views), (True, 3))
        with mock.patch.dict(os.environ, {'BN_MCP_ALLOW_NETWORK_PATHS': 'yes', 'BN_MCP_MAX_OWNED': '0'}):
            c = cfgmod.Config()
        self.assertEqual((c.binary_ninja.allow_network_paths, c.binary_ninja.max_owned_views), (False, 8))


class CTextTests(unittest.TestCase):
    def test_file_directives_are_detected_and_ordinary_declarations_are_not(self):
        hs = H.plugin_modules().http_server
        names_a_file = hs.c_text_names_a_file
        for text in ('#include "x.h"', '  #  include <x.h>', '#include_next <x.h>', '#import "x.h"',
                     '#embed "x.bin"', '/* c */ #include "x.h"', '#/* c */include "x.h"', '%:include "x.h"',
                     '#inc\\\nlude "x.h"', '/* line 1\nline 2 */ #include "x.h"',
                     'char *s = "/*";\n#include "x.h"', '#if __has_include("x.h")\n#endif',
                     'struct A { int a; };\n#include "\\\\attacker.example\\s\\x.h"'):
            with self.subTest(text=text):
                self.assertTrue(names_a_file(text))
        for text in ('struct importer { int embed; int include; };', '#pragma pack(push, 1)\nstruct P { char c; };',
                     '#define N 4\nint a[N];', 'int f(char *s);', 'char *s = "#include x";',
                     'int a; // #include "x.h"', 'int a; /* #include "x.h" */', ''):
            with self.subTest(text=text):
                self.assertFalse(names_a_file(text))

    def test_the_c_text_routes_refuse_them(self):
        m = H.plugin_modules()
        H.reset_plugin_state(m)
        td = tempfile.TemporaryDirectory(prefix='bnmcp-hard-')
        self.addCleanup(td.cleanup)
        v = H.make_view(td.name, 'foo.dll', 'A')
        with H.Server(m) as srv:
            srv.ops.current_view = v
            bad = '/**/#include "\\\\attacker.example\\s\\x.h"\nstruct X { int a; };'
            for method, path, kw in (('POST', '/declareCType', {'json_body': {'declaration': bad}}),
                                     ('POST', '/defineTypes', {'json_body': {'cCode': bad}}),
                                     ('GET', '/defineTypes', {'params': {'cCode': bad}}),
                                     ('POST', '/setFunctionPrototype', {'json_body': {'name': 'main',
                                                                                      'prototype': bad}}),
                                     ('GET', '/retypeVariable', {'params': {'functionName': 'main',
                                                                            'variableName': 'x', 'type': bad}})):
                with self.subTest(path=path, method=method):
                    r = H.http_request(srv.port, method, path, **kw)
                    self.assertEqual((r.status, r.json['error_code']), (403, 'POLICY'), r.raw[:300])
            self.assertNotIn('X', v.types)
            r = srv.post('/declareCType', json_body={'declaration': 'struct Fine { int a; };'})
            self.assertEqual(r.status, 200, r.raw[:300])


class PatchSaveTests(unittest.TestCase):
    def test_save_to_file_never_writes_over_a_database(self):
        m = H.plugin_modules()
        H.reset_plugin_state(m)
        td = tempfile.TemporaryDirectory(prefix='bnmcp-hard-')
        self.addCleanup(td.cleanup)
        v = H.make_view(td.name, 'foo.dll', 'A')
        v.file.filename = os.path.join(td.name, 'foo.bndb')     # a session opened from a database
        ops = H.new_ops(m, allow_save=True)
        ops.current_view = v
        out = ops.patch_bytes('0x140001000', '90', save_to_file=True)
        self.assertEqual((out['saved_to_file'], out['save_refused']), (False, True), out)
        self.assertIn('database', out['save_error'])
        self.assertEqual(v.save_calls, [], 'BinaryView.save was never called')
        self.assertEqual(out['status'], 'ok', 'the in-memory patch is applied')


class TokenOffTests(unittest.TestCase):
    def test_without_the_token_only_reads_are_served(self):
        m = H.plugin_modules()
        H.reset_plugin_state(m)
        td = tempfile.TemporaryDirectory(prefix='bnmcp-hard-')
        self.addCleanup(td.cleanup)
        v = H.make_view(td.name, 'foo.dll', 'A')
        with H.Server(m, require_token=False) as srv:
            srv.ops.current_view = v
            name0 = v.get_function_at(0x140001000).name if hasattr(v, 'get_function_at') else None
            r = srv.get('/decompile', {'name': 'main'}, token=None)
            self.assertEqual(r.status, 200, r.raw[:300])
            r = srv.get('/x/decompile', {'function': 'main', 'binary': 'foo.dll'}, token=None)
            self.assertEqual(r.status, 200, r.raw[:300])
            r = srv.post('/x/decompile', json_body={'function': 'main', 'binary': 'foo.dll'}, token=None)
            self.assertEqual(r.status, 200, 'the POST form of a read-only verb reads')
            for method, path, kw in (('GET', '/renameVariable', {'params': {'functionName': 'main',
                                                                            'variableName': 'x', 'newName': 'y'}}),
                                     ('GET', '/patch', {'params': {'address': '0x140001000', 'data': '90'}}),
                                     ('GET', '/selectBinary', {'params': {'view': 'foo.dll'}}),
                                     ('POST', '/renameFunction', {'form': {'oldName': 'main', 'newName': 'pwned'}}),
                                     ('POST', '/x/loadBinary', {'json_body': {'filepath': v.file.filename}}),
                                     ('POST', '/x/closeBinary', {'json_body': {}, 'params': {'binary': 'foo.dll'}})):
                with self.subTest(path=path):
                    r = H.http_request(srv.port, method, path, token=None, **kw)
                    self.assertEqual((r.status, r.json['error_code']), (401, 'UNAUTHORIZED'), r.raw[:300])
            self.assertEqual(v.write_calls, [], 'no patch was written')
            if name0 is not None:
                self.assertEqual(v.get_function_at(0x140001000).name, name0, 'no rename happened')
            r = srv.post('/renameFunction', form={'oldName': 'main', 'newName': 'renamed_ok'})   # with the token
            self.assertEqual(r.status, 200, r.raw[:300])


class ConnectionLimitTests(unittest.TestCase):
    def setUp(self):
        self.m = H.plugin_modules()
        H.reset_plugin_state(self.m)
        self.socks = []
        self.addCleanup(self._close_all)

    def _close_all(self):
        for s in self.socks:
            try:
                s.close()
            except OSError:
                pass

    def idle(self, port, n):
        for _ in range(n):
            s = socket.create_connection(('127.0.0.1', port), timeout=5)
            self.socks.append(s)
        return self.socks[-n:]

    def test_an_idle_connection_is_closed_after_request_timeout_s(self):
        with H.Server(self.m, request_timeout_s=1.0) as srv:
            s, = self.idle(srv.port, 1)
            s.settimeout(10)
            t0 = time.monotonic()
            try:
                data = s.recv(100)
            except ConnectionResetError:
                data = b''
            self.assertEqual(data, b'')
            self.assertLess(time.monotonic() - t0, 6.0)
            self.assertEqual(srv.get('/status', timeout=5).status, 200)

    def test_connections_above_the_limit_are_closed_at_once(self):
        with H.Server(self.m, max_connections=4, request_timeout_s=30.0) as srv:
            self.idle(srv.port, 4)
            time.sleep(0.3)
            extra = socket.create_connection(('127.0.0.1', srv.port), timeout=5)
            self.socks.append(extra)
            extra.settimeout(5)
            t0 = time.monotonic()
            try:
                data = extra.recv(100)
            except ConnectionResetError:
                data = b''
            self.assertEqual(data, b'', 'the fifth connection is closed without an answer')
            self.assertLess(time.monotonic() - t0, 3.0)
            self._close_all()                            # the idle ones go away: their slots free up
            deadline = time.monotonic() + 10
            status = None
            while time.monotonic() < deadline:
                try:
                    status = srv.get('/status', timeout=5).status
                    break
                except OSError:
                    time.sleep(0.2)
            self.assertEqual(status, 200)

    def test_many_idle_connections_leave_the_server_answering(self):
        n = 200
        try:
            import resource                      # POSIX: each connection costs two descriptors in this process
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            want = 1024 if hard == resource.RLIM_INFINITY else min(hard, 1024)
            if soft < want:
                resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
            n = min(n, max(20, (resource.getrlimit(resource.RLIMIT_NOFILE)[0] - 100) // 2))
        except (ImportError, ValueError, OSError):
            pass
        with H.Server(self.m) as srv:
            self.idle(srv.port, n)
            r = srv.get('/status', timeout=10)
            self.assertEqual(r.status, 200)
            self.assertLess(r.elapsed, 5.0)

    def test_refusals_are_logged_at_most_once_a_minute_per_reason(self):
        bn = H.ensure_fake()
        with H.Server(self.m) as srv:
            n0 = len(bn.LOGS)
            for _ in range(30):
                r = srv.get('/status', token=None, timeout=5)
                self.assertEqual(r.status, 401)
            warns = [msg for lvl, msg in list(bn.LOGS)[n0:] if lvl == 'warn' and 'refused' in msg]
            self.assertEqual(len(warns), 1, warns)


class LoadLockTests(unittest.TestCase):
    def test_the_load_paths_take_the_global_lock(self):
        m = H.plugin_modules()
        H.reset_plugin_state(m)
        td = tempfile.TemporaryDirectory(prefix='bnmcp-hard-')
        self.addCleanup(td.cleanup)
        path = H.fake_bv().make_standard_file(td.name, 'locked.dll', 'K')
        with H.Server(m, lock_wait_s=0.5) as srv:
            lk = srv.ops.view_lock('')
            self.assertTrue(lk.acquire(timeout=5))
            try:
                r = srv.post('/x/loadBinary', json_body={'filepath': path}, timeout=10)
                self.assertEqual((r.status, r.json['error_code']), (503, 'BUSY'), r.raw[:300])
                box = {}
                t = threading.Thread(target=lambda: box.setdefault('r', srv.post('/load', json_body={'filepath': path},
                                                                                 timeout=30)))
                t.start()
                time.sleep(0.8)
                self.assertNotIn('r', box, 'the legacy /load waited for the global lock')
            finally:
                lk.release()
            t.join(30)
            self.assertEqual(box['r'].status, 200, box['r'].raw[:300])
            r = srv.post('/x/loadBinary', json_body={'filepath': path})
            self.assertEqual(r.status, 200, r.raw[:300])


class LogHygieneTests(unittest.TestCase):
    _FORBIDDEN_NAMES = {'params', 'raw_params', 'body', 'post_data', 'query'}

    def test_no_log_call_formats_request_data(self):
        """Static: no bn.log_* call in the plugin passes request parameters, a body or the raw request line; the
        request-path modules log at info level only the events of _INFO_ALLOWED."""
        info_allowed = ('Patched binary saved to', 'Successfully re-signed binary', 'Server started on',
                        'Server stopped')
        bad = []
        for path in H.plugin_py_files():
            rel = os.path.relpath(path, H.plugin_dir())
            if not rel.startswith('plugin'):
                continue
            tree = ast.parse(open(path, encoding='utf-8').read())
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr.startswith('log_')
                        and isinstance(node.func.value, ast.Name) and node.func.value.id in ('bn', '_bn')):
                    continue
                for arg in node.args:
                    for sub in ast.walk(arg):
                        if isinstance(sub, ast.Name) and sub.id in self._FORBIDDEN_NAMES:
                            bad.append('%s:%d uses %s' % (rel, node.lineno, sub.id))
                        if (isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name)
                                and sub.value.id == 'self' and sub.attr in ('path', 'requestline')):
                            bad.append('%s:%d uses self.%s' % (rel, node.lineno, sub.attr))
                request_path = rel.replace('\\', '/') in ('plugin/server/http_server.py', 'plugin/api/endpoints.py',
                                                          'plugin/core/binary_operations.py',
                                                          'plugin/core/expert_ops.py')
                if request_path and node.func.attr == 'log_info':
                    text = ast.unparse(node)
                    if not any(k in text for k in info_allowed):
                        bad.append('%s:%d logs at info level: %s' % (rel, node.lineno, text[:100]))
        self.assertEqual(bad, [])

    def test_a_request_leaves_no_parameter_in_the_log(self):
        """Successful requests: neither the query string nor the body reaches the log (an error line may still name
        the function or variable a FAILED request referred to)."""
        m = H.plugin_modules()
        H.reset_plugin_state(m)
        bn = H.ensure_fake()
        td = tempfile.TemporaryDirectory(prefix='bnmcp-hard-')
        self.addCleanup(td.cleanup)
        v = H.make_view(td.name, 'foo.dll', 'A')
        marker = 'zzmarker_7f3a'
        with H.Server(m) as srv:
            srv.ops.current_view = v
            n0 = len(bn.LOGS)
            srv.get('/strings', {'offset': '0', 'limit': '5', 'x': marker})
            srv.get('/strings/filter', {'filter': marker})
            srv.post('/renameFunction', form={'oldName': 'main', 'newName': marker})
            srv.post('/comment', json_body={'address': '0x140001000', 'comment': marker})
            srv.post('/declareCType', json_body={'declaration': 'struct %s { int a; };' % marker})
            logs = list(bn.LOGS)[n0:]
        self.assertTrue(any('MCP request GET /strings -> 200' in msg for _lvl, msg in logs), logs[:5])
        self.assertEqual([x for x in logs if marker in x[1]], [])


if __name__ == '__main__':
    unittest.main()
