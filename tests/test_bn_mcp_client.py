# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""bn_mcp_client.py (caps / pack) against stub servers and the real plugin server.

The client runs as a subprocess in a temporary working directory (relative paths resolve there), so nothing is
written outside the test's temporary tree. Every run checks the output contract: one line of compact ASCII JSON.
"""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import run_tests as H

STATUS = {'loaded': False, 'filename': None,
          'server': {'version': '1.0.0', 'contract': 'binja-agent-mcp/1', 'lock_mode': 'global',
                     'threaded': True, 'max_inflight': 8, 'bn_core_version': '6.0.10601',
                     'capabilities': ['per_call_binary', 'ambiguity_errors', 'output_caps', 'analysis_state',
                                      'save_policy', 'post_type_routes', 'local_auth_v1', 'expert_v1'],
                     'import_errors': {}}}
PACK_TEXT = '# BN-PACK v1\nbinary_id: x\n\n## TARGET HLIL (main)\n140001000  r\u00e9sum\u00e9 \u03b4\u03bf\u03ba\u03b9\u03bc\u03ae = 1\n'


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stub = H.StubHTTP()

    @classmethod
    def tearDownClass(cls):
        cls.stub.close()

    def setUp(self):
        self.stub.reset()
        self.td = tempfile.TemporaryDirectory(prefix='bnmcp-client-')
        self.addCleanup(self.td.cleanup)
        # The client makes a relative path absolute with os.getcwd(), which names the real directory: on macOS the
        # temporary directory is under /var, a link to /private/var. So the working directory is the real path.
        self.cwd = os.path.join(os.path.realpath(self.td.name), 'work')
        os.makedirs(self.cwd)
        self.packs = os.path.join(self.cwd, 'packs')
        self.token_file = os.path.join(self.td.name, 'token')

    # ------------------------------------------------------------------------------------------------------------
    def run_client(self, *args, url=None, env=None):
        argv = [sys.executable, '-I', '-B', H.client_path()] + list(args)
        if url is not False and '--url' not in args and args and args[0] in ('caps', 'pack'):
            argv += ['--url', url or self.stub.url]
        e = dict(os.environ, BN_MCP_TOKEN_FILE=self.token_file)
        e.update(env or {})
        t0 = time.monotonic()
        p = subprocess.run(argv, capture_output=True, cwd=self.cwd, timeout=120, env=e)
        elapsed = time.monotonic() - t0
        out = p.stdout.decode('ascii')
        lines = out.split('\n')
        self.assertEqual(len(lines), 2, out)                  # one line plus the final newline
        self.assertEqual(lines[1], '')
        return p.returncode, json.loads(lines[0]), elapsed

    def pack_args(self, binary, out=os.path.join('packs', 'main.pack'), *extra):
        return ['pack', '--binary', binary, '--function', 'main', '--out', out, '--busy-sleep', '0'] + list(extra)

    def slice_route(self, echo=None, result=None, status=200, body=None):
        text = PACK_TEXT
        res = {'pack_text': text, 'pack_sha256': hashlib.sha256(text.encode('utf-8')).hexdigest(),
               'function': {'name': 'main', 'start': '0x140001000'}, 'sections': ['TARGET HLIL (main)'],
               'sections_missing': [], 'complete': True, 'modified_bytes_in_slice': 0, 'callees_omitted': 0,
               'truncated': False, 'render_used': 'ast-lines'}
        res.update(result or {})

        def route(rec):
            sel = rec['query'].get('binary', '')
            e = {'view_id': '1', 'binary_id': 'a' * 64, 'sha256': 'a' * 64, 'sha256_source': 'file',
                 'filename': sel if ('/' in sel or '\\' in sel) else os.path.join(os.sep, 'x', sel),
                 'original_filename': '',
                 'basename': os.path.basename(sel), 'resolved_by': 'explicit', 'analysis_state': 'IdleState',
                 'analysis_state_code': 2}
            e.update(echo or {})
            if body is not None:
                return status, body
            return status, {'ok': True, 'verb': 'handler_slice', 'result': res, 'truncated': False,
                            'next_offset': None, 'warnings': [], 'limits': {}, '_binary': e}
        self.stub.routes['/x/handlerSlice'] = route

    def pack_files(self):
        return sorted(os.listdir(self.packs)) if os.path.isdir(self.packs) else []

    # ------------------------------------------------------------------------------------------------------------ caps
    def test_caps_reports_the_contract(self):
        self.stub.routes['/status'] = (200, STATUS)
        code, o, _ = self.run_client('caps')
        self.assertEqual(code, 0)
        self.assertEqual((o['ok'], o['subcommand'], o['reachable'], o['contract']),
                         (True, 'caps', True, 'binja-agent-mcp/1'))
        self.assertIn('per_call_binary', o['capabilities'])
        self.assertIn('expert_v1', o['capabilities'])
        self.assertEqual((o['version'], o['lock_mode'], o['import_errors']), ('1.0.0', 'global', {}))
        self.assertEqual(self.stub.log[-1]['path'], '/status')
        self.assertEqual(self.stub.log[-1]['query'], {})       # unscoped

    def test_caps_sends_the_token_from_the_token_file(self):
        self.stub.routes['/status'] = (200, STATUS)
        self.run_client('caps')
        self.assertNotIn('x-bn-mcp-token', self.stub.log[-1]['headers'], 'no token file: no header')
        tok = 'T' * 43
        with open(self.token_file, 'w', encoding='utf-8') as f:
            f.write(tok + '\n')
        self.run_client('caps')
        self.assertEqual(self.stub.log[-1]['headers'].get('x-bn-mcp-token'), tok)
        with open(self.token_file, 'w', encoding='utf-8') as f:
            f.write('not a token\n')
        self.run_client('caps')
        self.assertNotIn('x-bn-mcp-token', self.stub.log[-1]['headers'], 'a malformed token file is not sent')

    def test_caps_old_plugin_has_no_contract(self):
        self.stub.routes['/status'] = (200, {'loaded': True, 'filename': 'C:/x.dll'})
        code, o, _ = self.run_client('caps')
        self.assertEqual((code, o['reachable'], o['contract'], o['capabilities']), (0, True, '', []))
        self.assertIn('upstream plugin', o['error'])

    def test_caps_closed_port_is_unreachable_exit_0(self):
        code, o, elapsed = self.run_client('caps', url='http://127.0.0.1:%d' % H.free_port())
        self.assertEqual((code, o['ok'], o['reachable'], o['contract']), (0, True, False, ''))
        self.assertLess(elapsed, 15.0)

    def test_caps_strict_fails_unless_the_server_answers_with_the_contract(self):
        code, o, _ = self.run_client('caps', '--strict', url='http://127.0.0.1:%d' % H.free_port())
        self.assertEqual((code, o['ok'], o['reachable'], o['exit_code']), (5, False, False, 5))
        self.stub.routes['/status'] = (200, {'loaded': True, 'filename': 'x.dll'})     # an upstream plugin
        code, o, _ = self.run_client('caps', '--strict')
        self.assertEqual((code, o['ok'], o['reachable'], o['contract']), (3, False, True, ''))
        self.stub.routes['/status'] = (401, {'ok': False, 'error_code': 'UNAUTHORIZED', 'error': 'no token'})
        code, o, _ = self.run_client('caps', '--strict')
        self.assertEqual((code, o['http_status']), (3, 401))
        self.stub.routes['/status'] = (200, STATUS)
        code, o, _ = self.run_client('caps', '--strict')
        self.assertEqual((code, o['ok'], o['contract']), (0, True, 'binja-agent-mcp/1'))

    def test_only_a_loopback_url_is_accepted(self):
        for url in ('http://192.0.2.1:9009', 'http://example.com:9009', 'https://127.0.0.1:9009', 'http://127.0.0.1'):
            with self.subTest(url=url):
                code, o, _ = self.run_client('caps', url=url)
                self.assertEqual((code, o['ok'], o['exit_code']), (2, False, 2), o)
                self.assertIn('127.0.0.1', o['error'])
        code, o, _ = self.run_client('caps', url=False, env={'BN_MCP_URL': 'http://example.com:9009'})
        self.assertEqual(code, 2, o)
        self.assertEqual(self.stub.log, [], 'nothing was sent')

    def test_caps_and_pack_against_the_real_plugin_server(self):
        m = H.plugin_modules()
        H.reset_plugin_state(m)
        v = H.make_view(os.path.join(self.td.name, 'bin'), 'foo.dll', 'A')
        srv = H.Server(m).start()
        self.addCleanup(srv.stop)
        srv.ops.register_view(v)
        url = 'http://127.0.0.1:%d' % srv.port
        # without the server's token file the server refuses the client (401), and nothing else happens
        code, o, _ = self.run_client('caps', url=url)
        self.assertEqual((code, o['reachable'], o['http_status'], o['contract']), (0, True, 401, ''))
        self.assertIn('UNAUTHORIZED', o['error'])
        env = {'BN_MCP_TOKEN_FILE': srv.cfg.server.token_file}
        code, o, _ = self.run_client('caps', url=url, env=env)
        self.assertEqual((code, o['reachable'], o['contract']), (0, True, 'binja-agent-mcp/1'))
        self.assertIn('per_call_binary', o['capabilities'])
        self.assertIn('expert_v1', o['capabilities'])
        code, o, _ = self.run_client(*self.pack_args(v.file.filename, os.path.join('packs', 'main.pack'),
                                                     '--disasm', '1'), url=url, env=env)
        self.assertEqual(code, 0, o)
        self.assertTrue(o['written'], o)
        self.assertTrue(o['binary_echo_ok'])
        self.assertEqual(o['analysis_state'], 'IdleState')
        with open(os.path.join(self.packs, 'main.pack'), 'rb') as f:
            data = f.read()
        self.assertTrue(data.startswith(b'# BN-PACK v1\n'))
        self.assertIn(b'## DISASSEMBLY (main)', data)
        self.assertEqual(hashlib.sha256(data).hexdigest(), o['pack_sha256'])
        # a modified slice is refused
        v.write(H.fake_bv().A_HELPER + 4, b'\xcc')
        code, o, _ = self.run_client(*self.pack_args(v.file.filename, os.path.join('packs', 'm2.pack')),
                                     url=url, env=env)
        self.assertEqual((code, o['written']), (0, False))
        self.assertIn('modified_bytes_in_slice', o['refused_reason'])
        self.assertNotIn('m2.pack', self.pack_files())

    # ------------------------------------------------------------------------------------------------------------ pack
    def test_pack_writes_the_text_byte_exactly(self):
        sel = os.path.join(self.td.name, 'bin', 'foo.dll')
        self.slice_route()
        code, o, _ = self.run_client(*self.pack_args(sel))
        self.assertEqual(code, 0, o)
        self.assertTrue(o['written'], o)
        self.assertEqual(o['pack_sha256'], hashlib.sha256(PACK_TEXT.encode('utf-8')).hexdigest())
        self.assertEqual(o['out'], os.path.join(self.packs, 'main.pack').replace('\\', '/'))
        with open(os.path.join(self.packs, 'main.pack'), 'rb') as f:
            self.assertEqual(f.read(), PACK_TEXT.encode('utf-8'))
        q = self.stub.log[-1]['query']
        self.assertEqual(q, {'binary': sel, 'function': 'main', 'depth': '3', 'max_callees': '40',
                             'max_chars': '120000', 'include': 'hlil,callers,types,strings,imports', 'disasm': '0'})
        self.assertEqual(self.pack_files(), ['main.pack'])     # no temp file left behind

    def test_relative_binary_is_sent_absolute_and_the_echo_verifies(self):
        self.slice_route()
        rel = os.path.join('bin', 'foo.dll')
        code, o, _ = self.run_client(*self.pack_args(rel))
        self.assertEqual(code, 0, o)
        sent = self.stub.log[-1]['query']['binary']
        self.assertTrue(os.path.isabs(sent), sent)
        self.assertEqual(os.path.normcase(sent), os.path.normcase(os.path.normpath(os.path.join(self.cwd, rel))))
        self.assertTrue(o['binary_echo_ok'])
        self.assertTrue(o['written'])

    def test_refusals_write_nothing(self):
        sel = os.path.join(self.td.name, 'bin', 'foo.dll')
        cases = [
            ('resolved_by global', sel, {'resolved_by': 'global'}, {}, '_binary echo'),
            ('another filename', sel, {'filename': os.path.join(self.td.name, 'bin', 'other.dll')}, {}, '_binary echo'),
            ('stem-only match for an extension selector', 'foo.dll',
             {'filename': os.path.join(os.sep, 'x', 'foo.exe')}, {},
             '_binary echo'),
            ('analysis not idle', sel, {'analysis_state': 'AnalyzeState'}, {}, 'not IdleState'),
            ('incomplete', sel, {}, {'complete': False, 'sections_missing': ['TARGET HLIL (main): NO_IL']},
             'incomplete'),
            ('modified bytes', sel, {}, {'modified_bytes_in_slice': 3}, 'modified_bytes_in_slice'),
            ('modified bytes unknown', sel, {}, {'modified_bytes_in_slice': None}, 'modified_bytes_in_slice'),
            ('file changed since load', sel, {'sha256_source': 'file-changed-since-load'}, {}, 'sha256_source'),
            ('sha mismatch', sel, {}, {'pack_sha256': '0' * 64}, 'does not equal pack_sha256'),
            ('no echo at all', sel, None, {}, '_binary echo'),
        ]
        for name, s, echo, result, why in cases:
            with self.subTest(case=name):
                if echo is None:
                    text = PACK_TEXT
                    self.slice_route(body={'ok': True, 'result': {
                        'pack_text': text, 'pack_sha256': hashlib.sha256(text.encode('utf-8')).hexdigest(),
                        'complete': True, 'modified_bytes_in_slice': 0, 'function': {'name': 'main'}}})
                else:
                    self.slice_route(echo=echo, result=result)
                code, o, _ = self.run_client(*self.pack_args(s))
                self.assertEqual((code, o['ok'], o['written']), (0, True, False), o)
                self.assertIn(why, o['refused_reason'])
                self.assertEqual(self.pack_files(), [])

    def test_stem_selector_and_extension_selector_rules(self):
        self.slice_route(echo={'filename': os.path.join(os.sep, 'x', 'foo.dll')})
        code, o, _ = self.run_client(*self.pack_args('foo'))
        self.assertEqual((code, o['binary_echo_ok'], o['written']), (0, True, True), o)
        os.remove(os.path.join(self.packs, 'main.pack'))
        # names compare without case on Windows only (as the plugin compares them)
        win = sys.platform == 'win32'
        code, o, _ = self.run_client(*self.pack_args('FOO.DLL'))
        self.assertEqual((o['binary_echo_ok'], o['written']), (win, win), o)

    def test_409_passes_candidates_through_and_writes_nothing(self):
        cands = [{'name': 'dup', 'start': '0x%x' % (0x140001400 + 0x80 * k)} for k in range(25)]
        self.slice_route(status=409, body={'ok': False, 'verb': 'handler_slice', 'error_code': 'AMBIGUOUS',
                                           'error': 'AMBIGUOUS: 25 function match dup: ...', 'candidates': cands})
        code, o, _ = self.run_client(*self.pack_args(os.path.join(self.td.name, 'foo.dll')))
        self.assertEqual((code, o['written'], o['error_code'], o['http_status']), (0, False, 'AMBIGUOUS', 409))
        self.assertEqual(len(o['candidates']), 20)
        self.assertEqual(o['candidates'][0], {'name': 'dup', 'start': '0x140001400'})
        self.assertEqual(self.pack_files(), [])

    def test_503_busy_is_retried_then_written_false(self):
        self.slice_route(status=503, body={'error': 'BUSY: view 1 is busy', 'error_code': 'BUSY', 'retry_after_s': 5})
        code, o, _ = self.run_client(*self.pack_args(os.path.join(self.td.name, 'foo.dll'),
                                                     os.path.join('packs', 'main.pack'), '--busy-retries', '2'))
        self.assertEqual((code, o['written'], o['error_code'], o['busy_retries_used']), (0, False, 'BUSY', 2))
        self.assertEqual(len([r for r in self.stub.log if r['path'] == '/x/handlerSlice']), 3)
        self.assertEqual(self.pack_files(), [])

    def test_bad_out_paths_exit_4_before_any_request(self):
        sel = os.path.join(self.td.name, 'foo.dll')
        os.makedirs(os.path.join(self.cwd, 'adir'))
        with open(os.path.join(self.cwd, 'exists.pack'), 'wb') as f:
            f.write(b'OLD')
        with open(os.path.join(self.cwd, 'afile'), 'wb') as f:
            f.write(b'x')
        for out in ('adir', 'exists.pack', os.path.join('afile', 'main.pack')):
            with self.subTest(out=out):
                code, o, _ = self.run_client(*self.pack_args(sel, out))
                self.assertEqual((code, o['ok'], o['written'], o['exit_code']), (4, False, False, 4), o)
        self.assertEqual(self.stub.log, [])
        with open(os.path.join(self.cwd, 'exists.pack'), 'rb') as f:
            self.assertEqual(f.read(), b'OLD')

    def test_overwrite_replaces_an_existing_pack(self):
        self.slice_route()
        os.makedirs(self.packs)
        with open(os.path.join(self.packs, 'main.pack'), 'wb') as f:
            f.write(b'OLD')
        code, o, _ = self.run_client(*self.pack_args(os.path.join(self.td.name, 'foo.dll'),
                                                     os.path.join('packs', 'main.pack'), '--overwrite'))
        self.assertEqual((code, o['written']), (0, True), o)
        with open(os.path.join(self.packs, 'main.pack'), 'rb') as f:
            self.assertEqual(f.read(), PACK_TEXT.encode('utf-8'))

    def test_usage_errors_still_emit_one_json_line(self):
        code, o, _ = self.run_client('pack', '--binary', 'x.dll', '--out', 'a.pack', url=False)
        self.assertEqual((code, o['ok'], o['exit_code']), (2, False, 2))
        code, o, _ = self.run_client(*self.pack_args('x.dll', 'a.pack', '--disasm', '2'))
        self.assertEqual(code, 2)
        code, o, _ = self.run_client('bogus', url=False)
        self.assertEqual(code, 2)
        p = subprocess.run([sys.executable, '-I', '-B', H.client_path(), '--help'], capture_output=True,
                           cwd=self.cwd, timeout=60)
        self.assertEqual(p.returncode, 0)
        self.assertIn(b'caps', p.stdout)

    def test_pack_unreachable_server_writes_nothing(self):
        code, o, _ = self.run_client(*self.pack_args(os.path.join(self.td.name, 'foo.dll')),
                                     url='http://127.0.0.1:%d' % H.free_port())
        self.assertEqual((code, o['ok'], o['written'], o['error_code']), (5, False, False, 'UNREACHABLE'))
        self.assertEqual(self.pack_files(), [])

    def test_atomic_write_leaves_no_partial_file(self):
        spec = importlib.util.spec_from_file_location('bnmcp_client_under_test', H.client_path())
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        os.makedirs(self.packs)
        target = os.path.join(self.packs, 'atomic.pack')
        with mock.patch.object(mod.os, 'fsync', side_effect=OSError('disk full (simulated)')):
            with self.assertRaises(OSError):
                mod._write_atomic(target, PACK_TEXT * 1000)
        self.assertEqual(self.pack_files(), [])
        with open(target, 'wb') as f:
            f.write(b'OLD')
        with mock.patch.object(mod.os, 'replace', side_effect=OSError('replace failed (simulated)')):
            with self.assertRaises(OSError):
                mod._write_atomic(target, PACK_TEXT)
        with open(target, 'rb') as f:
            self.assertEqual(f.read(), b'OLD')
        self.assertEqual(self.pack_files(), ['atomic.pack'])
        mod._write_atomic(target, PACK_TEXT)
        with open(target, 'rb') as f:
            self.assertEqual(f.read(), PACK_TEXT.encode('utf-8'))
        self.assertEqual(self.pack_files(), ['atomic.pack'])


if __name__ == '__main__':
    unittest.main()
