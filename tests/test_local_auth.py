# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""Who may call the plugin's HTTP server (plugin/core/local_auth.py, MCPRequestHandler._reject_untrusted).

Against the real server on 127.0.0.1:<ephemeral> with the fake binaryninja:
  * the Host allowlist (DNS rebinding), the refusal of browser requests (Origin, Referer, Sec-Fetch-Site) and the
    per-run token, each on read routes AND on state-changing routes, which must have no effect when refused;
  * no CORS header on any answer, and an OPTIONS preflight that is never granted;
  * the token file: written after the bind, mode 0600 on POSIX, removed on stop, never replaced by a second server
    that fails to bind;
  * the same token-file path rule in the plugin, the bridge and bn_mcp_client.py;
  * the bridge end to end: with the token file it is served, without it every tool answers UNAUTHORIZED.
"""

import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest

import run_tests as H


class _Base(unittest.TestCase):
    def setUp(self):
        self.m = H.plugin_modules()
        H.reset_plugin_state(self.m)
        self.la = self.m.local_auth
        self.td = tempfile.TemporaryDirectory(prefix='bnmcp-auth-')
        self.addCleanup(self.td.cleanup)

    def server(self, **cfg):
        srv = H.Server(self.m, **cfg).start()
        self.addCleanup(srv.stop)
        return srv

    def req(self, srv, method, path, params=None, headers=None, token=H.AUTO, **kw):
        return H.http_request(srv.port, method, path, params, headers=headers, token=token, **kw)


class RequestCheckTests(_Base):
    def test_token_is_required_and_compared_exactly(self):
        srv = self.server()
        self.assertTrue(srv.token)
        for label, tok in (('missing', None), ('wrong', 'x' * 43), ('truncated', srv.token[:-1]),
                           ('padded', srv.token + 'A'), ('lower-cased', srv.token.lower() if srv.token.lower() !=
                                                         srv.token else srv.token + 'b')):
            with self.subTest(token=label):
                r = self.req(srv, 'GET', '/status', token=tok)
                self.assertEqual((r.status, r.json['error_code']), (401, 'UNAUTHORIZED'), r.raw[:300])
                self.assertNotIn('server', r.json)
        r = self.req(srv, 'GET', '/status', token=' %s ' % srv.token)
        self.assertEqual(r.status, 200, 'surrounding spaces are not part of the token')
        r = self.req(srv, 'GET', '/status')
        self.assertEqual(r.status, 200, r.raw[:300])

    def test_host_header_allowlist(self):
        srv = self.server()
        p = srv.port
        for host, ok in (('127.0.0.1:%d' % p, True), ('localhost:%d' % p, True), ('LOCALHOST:%d' % p, True),
                         ('127.0.0.1', False), ('localhost', False), ('127.0.0.1:%d' % (p + 1), False),
                         ('evil.example:%d' % p, False), ('attacker.test', False), ('[::1]:%d' % p, False),
                         ('127.0.0.1:%d.evil.example' % p, False), ('', False)):
            with self.subTest(host=host):
                r = self.req(srv, 'GET', '/status', headers={'Host': host})
                if ok:
                    self.assertEqual(r.status, 200, r.raw[:300])
                else:
                    self.assertEqual((r.status, r.json['error_code']), (403, 'FORBIDDEN_HOST'), r.raw[:300])

    def test_browser_requests_are_refused_even_with_the_token(self):
        srv = self.server()
        for hdr in ({'Origin': 'https://evil.example'}, {'Origin': 'null'},
                    {'Origin': 'http://127.0.0.1:%d' % srv.port}, {'Referer': 'https://evil.example/page'},
                    {'Sec-Fetch-Site': 'cross-site'}, {'Sec-Fetch-Site': 'same-site'},
                    {'Sec-Fetch-Site': 'same-origin'}):
            with self.subTest(headers=hdr):
                r = self.req(srv, 'GET', '/status', headers=hdr)
                self.assertEqual((r.status, r.json['error_code']), (403, 'BROWSER_REQUEST'), r.raw[:300])
        r = self.req(srv, 'GET', '/status', headers={'Sec-Fetch-Site': 'none', 'Sec-Fetch-Mode': 'navigate'})
        self.assertEqual(r.status, 200, 'a URL the user typed (Sec-Fetch-Site: none) is not a cross-site request')

    def test_no_cors_header_is_ever_sent_and_a_preflight_is_never_granted(self):
        srv = self.server()
        answers = [self.req(srv, 'GET', '/status'), self.req(srv, 'GET', '/status', token=None),
                   self.req(srv, 'GET', '/status', headers={'Origin': 'https://evil.example'}),
                   self.req(srv, 'POST', '/x/compute', json_body={'expr': '1+1'}),
                   self.req(srv, 'OPTIONS', '/x/loadBinary', headers={
                       'Origin': 'https://evil.example', 'Access-Control-Request-Method': 'POST',
                       'Access-Control-Request-Headers': 'x-bn-mcp-token, content-type'})]
        for r in answers:
            with self.subTest(status=r.status):
                self.assertEqual([k for k in r.headers if k.startswith('access-control-')], [])
        self.assertGreaterEqual(answers[-1].status, 400, 'OPTIONS must not succeed')

    def test_refused_state_changing_requests_have_no_effect(self):
        srv = self.server()
        v = H.make_view(os.path.join(self.td.name, 'bin'), 'foo.dll', 'A')
        srv.ops.register_view(v)
        srv.ops.current_view = v
        target = H.fake_bv().make_standard_file(os.path.join(self.td.name, 'other'), 'other.dll', 'B')
        before = v.read(0x140002060, 2)
        name_before = v.get_function_at(H.fake_bv().A_LEAF).name
        attacks = (
            ('GET', '/patch', {'address': '0x140002060', 'data': '9090'}, None),
            ('GET', '/renameFunction', {'oldName': 'leaf', 'newName': 'pwned'}, None),
            ('POST', '/renameFunction', None, {'oldName': 'leaf', 'newName': 'pwned'}),
            ('POST', '/x/loadBinary', None, {'filepath': target}),
            ('POST', '/load', None, {'filepath': target}),
            ('POST', '/comment', None, {'address': '0x140001180', 'comment': 'x'}),
        )
        refusals = (('no token', {}, None, 401), ('wrong token', {}, 'y' * 43, 401),
                    ('rebinding host', {'Host': 'evil.example:%d' % srv.port}, H.AUTO, 403),
                    ('browser page', {'Origin': 'https://evil.example'}, H.AUTO, 403))
        for method, path, params, body in attacks:
            for label, hdr, tok, status in refusals:
                with self.subTest(route=path, method=method, refusal=label):
                    r = self.req(srv, method, path, params, headers=hdr, token=tok, json_body=body)
                    self.assertEqual(r.status, status, r.raw[:300])
        self.assertEqual(v.read(0x140002060, 2), before, 'a refused /patch changed bytes')
        self.assertEqual(v.get_function_at(H.fake_bv().A_LEAF).name, name_before, 'a refused rename happened')
        self.assertEqual(srv.ops.open_view_count(), 1, 'a refused load opened a view')
        self.assertEqual(srv.ops.raw_patches(srv.ops.describe_view(v)['view_id']), [])
        # control: the same rename with the token and a good Host is applied
        r = self.req(srv, 'POST', '/renameFunction', json_body={'oldName': 'leaf', 'newName': 'renamed'})
        self.assertEqual(r.status, 200, r.raw[:300])
        self.assertEqual(v.get_function_at(H.fake_bv().A_LEAF).name, 'renamed')

    def test_a_refused_post_with_a_body_still_gets_its_answer(self):
        """The refusal is sent after the body was read, so the client reads a 401 instead of a connection reset
        (unread data in the receive buffer makes Windows reset the connection on close)."""
        srv = self.server()
        body = {'filepath': 'C:\\x.dll', 'pad': 'p' * (200 * 1024)}
        for i in range(20):
            with self.subTest(i=i):
                r = self.req(srv, 'POST', '/x/loadBinary', token='z' * 43, json_body=body)
                self.assertEqual((r.status, r.json['error_code']), (401, 'UNAUTHORIZED'))

    def test_require_token_off_keeps_the_host_and_browser_checks(self):
        srv = self.server(require_token=False)
        self.assertEqual(self.req(srv, 'GET', '/status', token=None).status, 200)
        st = self.req(srv, 'GET', '/status', token=None).json['server']['auth']
        self.assertEqual(st, {'host_check': True, 'browser_check': True, 'require_token': False})
        r = self.req(srv, 'GET', '/status', token=None, headers={'Host': 'evil.example:%d' % srv.port})
        self.assertEqual(r.status, 403)
        r = self.req(srv, 'GET', '/status', token=None, headers={'Origin': 'https://evil.example'})
        self.assertEqual(r.status, 403)

    def test_environment_switches(self):
        old = {k: os.environ.get(k) for k in ('BN_MCP_REQUIRE_TOKEN', 'BN_MCP_TOKEN_FILE')}

        def restore():
            for k, val in old.items():
                if val is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = val
        self.addCleanup(restore)
        os.environ['BN_MCP_REQUIRE_TOKEN'] = '0'
        os.environ['BN_MCP_TOKEN_FILE'] = os.path.join(self.td.name, 'env-token')
        cfg = self.m.config.Config()
        self.assertIs(cfg.server.require_token, False)
        self.assertEqual(cfg.server.token_file, os.path.join(self.td.name, 'env-token'))
        os.environ['BN_MCP_REQUIRE_TOKEN'] = 'no'                 # invalid: ignored, the default stays
        self.assertIs(self.m.config.Config().server.require_token, True)


class TokenFileTests(_Base):
    def test_written_after_the_bind_and_removed_on_stop(self):
        path = os.path.join(self.td.name, 'sub', 'token')
        srv = H.Server(self.m, token_file=path).start()
        try:
            self.assertEqual(self.la.read_token(path), srv.token)
            with open(path, encoding='utf-8') as f:
                self.assertEqual(f.read(), srv.token + '\n')
            if os.name == 'posix':
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertGreaterEqual(len(srv.token), 40)
        finally:
            srv.stop()
        self.assertFalse(os.path.exists(path), 'the token file outlived the server')

    def test_the_temporary_file_has_a_new_name_and_none_is_left(self):
        """write_token creates its temporary file exclusively under a random name: a file planted at a predictable
        name (<path>.<pid>.tmp, which an earlier version used) is neither truncated nor followed, the token file holds
        exactly the token and one LF, and no temporary file is left."""
        d = os.path.join(self.td.name, 'tok')
        os.makedirs(d)
        path = os.path.join(d, 'token')
        planted = '%s.%d.tmp' % (path, os.getpid())
        with open(planted, 'w', encoding='utf-8') as f:
            f.write('planted')
        tok = self.la.new_token()
        self.la.write_token(path, tok)
        with open(path, 'rb') as f:
            self.assertEqual(f.read(), (tok + '\n').encode('ascii'))
        with open(planted, encoding='utf-8') as f:
            self.assertEqual(f.read(), 'planted')
        self.assertEqual(sorted(os.listdir(d)), sorted(['token', os.path.basename(planted)]))
        if os.name == 'posix':
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_a_second_server_that_cannot_bind_never_replaces_the_token(self):
        path = os.path.join(self.td.name, 'token')
        first = H.Server(self.m, token_file=path).start()
        self.addCleanup(first.stop)
        second = H.Server(self.m, port=first.port, token_file=path)
        with self.assertRaises(OSError):
            second.start()
        self.assertEqual(self.la.read_token(path), first.token, 'the failed server replaced the token')
        self.assertEqual(self.req(first, 'GET', '/status').status, 200)

    def test_each_start_gets_a_new_token_and_stop_removes_only_its_own(self):
        path = os.path.join(self.td.name, 'token')
        a = H.Server(self.m, token_file=path).start()
        tok_a = a.token
        a.stop()
        b = H.Server(self.m, token_file=path).start()
        self.addCleanup(b.stop)
        self.assertNotEqual(b.token, tok_a)
        self.la.remove_token(path, tok_a)                       # a stale owner never deletes the new token
        self.assertEqual(self.la.read_token(path), b.token)

    def test_read_token_rejects_malformed_content(self):
        path = os.path.join(self.td.name, 'token')
        for content, want in (('', ''), ('short\n', ''), ('a b c d e f g h i j k l m n o p\n', ''),
                              ('A' * 43 + '\n', 'A' * 43), ('  ' + 'B' * 43 + '  ', 'B' * 43),
                              ('é' * 43, '')):
            with self.subTest(content=content[:12]):
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.assertEqual(self.la.read_token(path), want)
        os.remove(path)
        self.assertEqual(self.la.read_token(path), '')


class PathRuleParityTests(_Base):
    def _client(self):
        spec = importlib.util.spec_from_file_location('bnmcp_client_parity', H.client_path())
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _bridge(self):
        import test_bridge as TB
        if not TB._importable():
            return None
        return TB.load_bridge()

    def test_plugin_bridge_and_client_agree_on_the_token_file(self):
        impls = [('plugin', self.la.token_file_path), ('client', self._client().token_file_path)]
        b = self._bridge()
        if b is not None:
            impls.append(('bridge', b.token_file_path))
        keys = ('BN_MCP_TOKEN_FILE', 'LOCALAPPDATA', 'XDG_STATE_HOME', 'HOME', 'USERPROFILE')
        saved = {k: os.environ.get(k) for k in keys}

        def restore():
            for k, val in saved.items():
                if val is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = val
        self.addCleanup(restore)
        home = os.path.join(self.td.name, 'home')
        cases = (
            {'BN_MCP_TOKEN_FILE': os.path.join(self.td.name, 'explicit', 'tok')},
            {'BN_MCP_TOKEN_FILE': None, 'LOCALAPPDATA': os.path.join(self.td.name, 'lad'),
             'XDG_STATE_HOME': os.path.join(self.td.name, 'xdg'), 'HOME': home, 'USERPROFILE': home},
            {'BN_MCP_TOKEN_FILE': None, 'LOCALAPPDATA': None, 'XDG_STATE_HOME': None, 'HOME': home,
             'USERPROFILE': home},
            {'BN_MCP_TOKEN_FILE': '   '},
        )
        for case in cases:
            for k, val in case.items():
                if val is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = val
            got = {name: fn() for name, fn in impls}
            with self.subTest(case=case):
                self.assertEqual(len(set(got.values())), 1, got)
                p = next(iter(got.values()))
                self.assertTrue(os.path.isabs(p), p)
                if (case.get('BN_MCP_TOKEN_FILE') or '').strip():
                    self.assertEqual(p, os.path.abspath(case['BN_MCP_TOKEN_FILE']))
                else:
                    self.assertTrue(p.endswith(os.path.join('binja-agent-mcp', 'token')), p)
        if sys.platform == 'win32':
            os.environ.pop('BN_MCP_TOKEN_FILE', None)
            os.environ['LOCALAPPDATA'] = os.path.join(self.td.name, 'lad')
            self.assertEqual(self.la.token_file_path(), os.path.join(self.td.name, 'lad', 'binja-agent-mcp', 'token'))


class BridgeEndToEndTests(_Base):
    def test_the_bridge_is_served_with_the_token_file_and_refused_without_it(self):
        import test_bridge as TB
        if not TB._importable():
            self.skipTest('mcp/requests/anyio are not importable here')
        b = TB.load_bridge()
        path = os.path.join(self.td.name, 'token')
        srv = self.server(token_file=path)
        saved_url = b.binja_server_url
        old = os.environ.get('BN_MCP_TOKEN_FILE')

        def restore():
            b.binja_server_url = saved_url
            if old is None:
                os.environ.pop('BN_MCP_TOKEN_FILE', None)
            else:
                os.environ['BN_MCP_TOKEN_FILE'] = old
            gates, lock = getattr(b, '_GATES', None), getattr(b, '_GATES_LOCK', None)
            if isinstance(gates, dict) and lock is not None:
                with lock:
                    gates.pop('http://127.0.0.1:%d' % srv.port, None)
        self.addCleanup(restore)
        b.binja_server_url = 'http://127.0.0.1:%d' % srv.port
        os.environ['BN_MCP_TOKEN_FILE'] = path
        out = json.loads(b.bn_server_info())
        self.assertTrue(out['ok'], out)
        self.assertEqual(out['result']['contract'], H.CONTRACT)
        st = json.loads(b.get_binary_status())
        self.assertEqual(st['server']['contract'], H.CONTRACT)
        os.environ['BN_MCP_TOKEN_FILE'] = os.path.join(self.td.name, 'no-such-token')
        out = json.loads(b.bn_server_info())
        self.assertEqual((out['ok'], out['error_code'], out['http_status']), (False, 'UNAUTHORIZED', 401))
        self.assertIn('UNAUTHORIZED', b.decompile_function('main'))


if __name__ == '__main__':
    unittest.main()
