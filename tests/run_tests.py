#!/usr/bin/env python3
# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""run_tests.py - offline unittest suite of binja-agent-mcp (contract binja-agent-mcp/1).

USAGE
  python -I tests/run_tests.py [--plugin DIR] [--client PATH] [-k PATTERN] [-v]
    --plugin  the plugin tree to test (the directory holding plugin/, bridge/ and plugin.json). Default:
              ../binja_agent_mcp. Pass an installed copy explicitly to test that one instead.
    --client  bn_mcp_client.py to test (default ../bn_mcp_client.py).
    -k        run only tests whose id contains PATTERN (repeatable); -v verbose.
  Exit 0 = every test passed (skips included), 1 = a failure/error, 2 = usage (a missing tree).

OPTIONAL INPUTS (environment variables; a test that needs a missing one is SKIPPED)
  BN_MCP_TEST_BASELINE    a checkout of the upstream plugin fosdickio/binary_ninja_mcp at tag v1.1.0 (commit
                          d8a2709df69ff475d6be6366c2eec733663b008b): the backward-compatibility tests compare the
                          legacy routes and MCP tool names of the plugin under test with it.

WHAT IT DOES
  * Puts fake_bn/ FIRST on sys.path, so `import binaryninja` binds to the offline fake (fake_bn/binaryninja), never
    to a real Binary Ninja. No Binary Ninja and no network beyond 127.0.0.1 ephemeral ports.
  * Imports the plugin's core/server/api modules through a SYNTHETIC parent package (default name 'bnmcp_live') whose
    __path__ points at <plugin>/plugin, so plugin/__init__.py (the Binary Ninja UI glue) does not run there;
    test_plugin_glue executes it on its own, with a stand-in for binaryninjaui.
  * The backward-compatibility baseline (BN_MCP_TEST_BASELINE) is loaded the same way under 'bnmcp_base' from a
    temporary tree (its core/config.py and utils/*.py are taken from the plugin under test; the old server ignores
    the new config fields).
  * sys.dont_write_bytecode is set before any plugin import: no __pycache__ is written into the plugin tree.
    Every file a test creates lives in a tempfile.TemporaryDirectory; nothing is written into the repository.
  * BN_MCP_* environment variables are cleared before the tests (each test sets what it needs; the BN_MCP_TEST_*
    inputs are kept), BN_MCP_TOKEN_FILE always points into a temporary directory of the suite and BN_MCP_URL at a
    closed port: no test reads or writes the token file of a Binary Ninja that may be running on the same computer,
    and no server started by a test binds 9009. A tripwire makes any connect of this process to 127.0.0.1:9009 fail.

Test modules (stdlib unittest only): test_resolution_and_scoping, test_http_threading, test_backcompat_routes,
test_expert_ops, test_bridge, test_toolsets, test_local_auth, test_bn_mcp_client, test_load_binary,
test_static_rules, test_plugin_glue, test_hardening, test_mcp_clients, test_tools (see README.md). Nothing here
talks to a real Binary Ninja.
"""

import argparse
import collections
import http.client
import importlib
import importlib.util
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.parse

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
FAKE_DIR = os.path.join(HERE, 'fake_bn')
DEFAULT_PLUGIN = os.path.join(REPO_ROOT, 'binja_agent_mcp')
DEFAULT_CLIENT = os.path.join(REPO_ROOT, 'bn_mcp_client.py')
# Optional inputs (see the docstring): '' when not configured, and the tests that need them are skipped.
BASELINE_DIR = os.path.abspath(os.environ['BN_MCP_TEST_BASELINE']) if os.environ.get('BN_MCP_TEST_BASELINE') else ''
LIVE_ALIAS = 'bnmcp_live'
BASE_ALIAS = 'bnmcp_base'
CONTRACT = 'binja-agent-mcp/1'

CONFIG = {'plugin': None, 'client': None}
_TMP_KEEP = []          # TemporaryDirectory objects that must outlive a single test (the baseline tree)
_MODS = {}


# =====================================================================================================================
# configuration and the fake
# =====================================================================================================================
def configure(plugin=None, client=None):
    plugin = os.path.abspath(plugin or os.environ.get('BN_MCP_TEST_PLUGIN') or DEFAULT_PLUGIN)
    client = os.path.abspath(client or os.environ.get('BN_MCP_TEST_CLIENT') or DEFAULT_CLIENT)
    CONFIG['plugin'] = plugin
    CONFIG['client'] = client
    return plugin, client


def plugin_dir():
    if CONFIG['plugin'] is None:
        configure()
    return CONFIG['plugin']


def client_path():
    if CONFIG['client'] is None:
        configure()
    return CONFIG['client']


_SUITE_TMP = []


def suite_token_file():
    """The token file every test server writes unless a test names another one (inside a temporary directory)."""
    if not _SUITE_TMP:
        td = tempfile.TemporaryDirectory(prefix='bnmcp-suite-')
        _SUITE_TMP.append(td)
        _TMP_KEEP.append(td)
    return os.path.join(_SUITE_TMP[0].name, 'token')


# The port the plugin serves on outside the tests. A Binary Ninja that runs on the same computer may listen there.
LIVE_PORT = 9009
# Port 9 (discard) on the loopback address: nothing of this project listens there, so a bridge or client that a test
# forgot to point at its own stub fails to connect instead of reaching a Binary Ninja on LIVE_PORT.
CLOSED_URL = 'http://127.0.0.1:9'


def clear_bn_env():
    """Remove every BN_MCP_* variable (BN_MCP_TEST_* inputs of the suite are kept), point the token file into a
    temporary directory and BN_MCP_URL at a closed port."""
    for k in list(os.environ):
        if k.startswith('BN_MCP_') and not k.startswith('BN_MCP_TEST_'):
            os.environ.pop(k, None)
    os.environ['BN_MCP_TOKEN_FILE'] = suite_token_file()
    os.environ['BN_MCP_URL'] = CLOSED_URL


_TRIPWIRE = []


def install_live_port_tripwire():
    """Make every socket connect of this process to a loopback LIVE_PORT fail (ConnectionRefusedError) instead of
    reaching a Binary Ninja that may be running: no test may talk to the real server. Child processes are covered
    by CLOSED_URL and by the explicit --url / BN_MCP_URL each test passes."""
    if _TRIPWIRE:
        return
    real_connect, real_connect_ex = socket.socket.connect, socket.socket.connect_ex

    def _blocked(address):
        try:
            host, port = address[0], int(address[1])
        except Exception:
            return False
        return port == LIVE_PORT and str(host) in ('127.0.0.1', 'localhost', '::1', '0.0.0.0', '')

    def connect(self, address):
        if _blocked(address):
            raise ConnectionRefusedError('run_tests tripwire: a test tried to connect to %r' % (address,))
        return real_connect(self, address)

    def connect_ex(self, address):
        if _blocked(address):
            raise ConnectionRefusedError('run_tests tripwire: a test tried to connect to %r' % (address,))
        return real_connect_ex(self, address)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    _TRIPWIRE.append((real_connect, real_connect_ex))


def ensure_fake():
    """Import the offline fake binaryninja (and refuse a real Binary Ninja module)."""
    if FAKE_DIR not in sys.path:
        sys.path.insert(0, FAKE_DIR)
    bn = sys.modules.get('binaryninja')
    if bn is None:
        bn = importlib.import_module('binaryninja')
    if not hasattr(bn, 'LOAD_HOOK') or 'fake_bn' not in os.path.abspath(getattr(bn, '__file__', '') or ''):
        raise RuntimeError('a non-fake binaryninja module is loaded (%r); run the suite with python -I'
                           % getattr(bn, '__file__', None))
    return bn


def fake_bv():
    ensure_fake()
    return importlib.import_module('binaryninja.binaryview')


# =====================================================================================================================
# plugin loading (synthetic parent package; plugin/__init__.py is never executed)
# =====================================================================================================================
def _synthetic_package(alias, plugin_pkg_dir):
    pkg = types.ModuleType(alias)
    pkg.__path__ = [plugin_pkg_dir]
    pkg.__package__ = alias
    pkg.__file__ = None
    pkg.__doc__ = 'synthetic test parent package for %s (plugin/__init__.py NOT executed)' % plugin_pkg_dir
    sys.modules[alias] = pkg
    return pkg


def _load_modules(alias, root):
    ensure_fake()
    pkg_dir = os.path.join(root, 'plugin')
    if not os.path.isfile(os.path.join(pkg_dir, 'core', 'binary_operations.py')):
        raise RuntimeError('not a plugin tree (no plugin/core/binary_operations.py): %s' % root)
    _synthetic_package(alias, pkg_dir)
    ns = types.SimpleNamespace(alias=alias, root=root)
    for short, mod in (('config', 'core.config'), ('rc', 'core.request_context'), ('bo', 'core.binary_operations'),
                       ('expert_ops', 'core.expert_ops'), ('local_auth', 'core.local_auth'),
                       ('endpoints', 'api.endpoints'), ('http_server', 'server.http_server')):
        full = alias + '.' + mod
        if not os.path.isfile(os.path.join(pkg_dir, *mod.split('.')) + '.py'):
            setattr(ns, short, None)
            continue
        setattr(ns, short, importlib.import_module(full))
    return ns


def plugin_modules():
    """The plugin under test, imported once per process as 'bnmcp_live'."""
    if LIVE_ALIAS not in _MODS:
        _MODS[LIVE_ALIAS] = _load_modules(LIVE_ALIAS, plugin_dir())
    return _MODS[LIVE_ALIAS]


def baseline_modules():
    """The upstream v1.1.0 baseline (BN_MCP_TEST_BASELINE) imported as 'bnmcp_base' from a temporary tree."""
    if BASE_ALIAS in _MODS:
        return _MODS[BASE_ALIAS]
    if not BASELINE_DIR or not os.path.isdir(BASELINE_DIR):
        raise unittest.SkipTest('the upstream v1.1.0 baseline is not available (set BN_MCP_TEST_BASELINE)')
    td = tempfile.TemporaryDirectory(prefix='bnmcp-baseline-')
    _TMP_KEEP.append(td)
    root = os.path.join(td.name, 'base')
    src_plugin = os.path.join(plugin_dir(), 'plugin')
    for sub in ('core', 'server', 'api', 'utils'):
        os.makedirs(os.path.join(root, 'plugin', sub))
        open(os.path.join(root, 'plugin', sub, '__init__.py'), 'w').close()
    open(os.path.join(root, 'plugin', '__init__.py'), 'w').close()
    for rel in ('core/binary_operations.py', 'server/http_server.py', 'api/endpoints.py'):
        shutil.copyfile(os.path.join(BASELINE_DIR, 'plugin', *rel.split('/')), os.path.join(root, 'plugin', *rel.split('/')))
    for rel in ('core/config.py', 'utils/string_utils.py', 'utils/number_utils.py'):
        shutil.copyfile(os.path.join(src_plugin, *rel.split('/')), os.path.join(root, 'plugin', *rel.split('/')))
    _MODS[BASE_ALIAS] = _load_modules(BASE_ALIAS, root)
    return _MODS[BASE_ALIAS]


def reset_plugin_state(mods=None):
    """Forget process-wide plugin state between tests (module-status cache, fake hooks)."""
    mods = mods or plugin_modules()
    bn = ensure_fake()
    bn.LOAD_HOOK = None
    hs = getattr(mods, 'http_server', None)
    if hs is not None and hasattr(hs, 'reset_module_status'):
        hs.reset_module_status()
    fake_bv().ACTIVITY.reset()


# =====================================================================================================================
# fake views
# =====================================================================================================================
def make_view(directory, basename='foo.dll', tag='A', delay_s=0.0, extra=None):
    """Write a standard-program file and return a fresh fake BinaryView of it (the caller keeps the reference)."""
    fb = fake_bv()
    path = fb.make_standard_file(directory, basename, tag, delay_s, extra)
    return fb.open_view(path)


def new_ops(mods=None, lock_mode='global', lock_wait_s=20.0, allow_save=False):
    mods = mods or plugin_modules()
    cfg = mods.config.Config()
    cfg.server.lock_mode = lock_mode
    cfg.server.lock_wait_s = lock_wait_s
    cfg.binary_ninja.allow_save_to_file = allow_save
    return mods.bo.BinaryOperations(cfg.binary_ninja, server_config=cfg.server)


# =====================================================================================================================
# HTTP
# =====================================================================================================================
Resp = collections.namedtuple('Resp', 'status headers raw json elapsed')
AUTO = object()          # http_request(token=AUTO): the token of the test Server listening on that port, if any
PORT_TOKENS = {}         # port -> token of a running test Server (Server.start / Server.stop)
TOKEN_HEADER = 'X-BN-MCP-Token'


def http_request(port, method, path, params=None, json_body=None, form=None, raw_body=None, headers=None,
                 timeout=30.0, host='127.0.0.1', token=AUTO):
    q = ''
    if params:
        items = list(params.items()) if isinstance(params, dict) else list(params)
        q = urllib.parse.urlencode([(k, v if isinstance(v, str) else str(v)) for k, v in items])
    url = path + ('?' + q if q else '')
    body = None
    hdr = {'Connection': 'close'}
    if json_body is not None:
        body = json.dumps(json_body).encode('utf-8')
        hdr['Content-Type'] = 'application/json'
    elif form is not None:
        body = urllib.parse.urlencode(form).encode('utf-8')
        hdr['Content-Type'] = 'application/x-www-form-urlencoded'
    elif raw_body is not None:
        body = raw_body if isinstance(raw_body, bytes) else str(raw_body).encode('utf-8')
    tok = PORT_TOKENS.get(port) if token is AUTO else token
    if tok:
        hdr[TOKEN_HEADER] = tok
    if headers:
        hdr.update(headers)
    t0 = time.monotonic()
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(method, url, body=body, headers=hdr)
        r = conn.getresponse()
        raw = r.read()
        hd = {k.lower(): v for k, v in r.getheaders()}
        status = r.status
    finally:
        conn.close()
    try:
        js = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        js = None
    return Resp(status, hd, raw, js, time.monotonic() - t0)


class Server(object):
    """The plugin's real MCPServer on 127.0.0.1:<ephemeral> (or a given port) with its own BinaryOperations."""

    def __init__(self, mods=None, port=0, **server_cfg):
        self.mods = mods or plugin_modules()
        cfg = self.mods.config.Config()
        cfg.server.port = port
        if hasattr(cfg.server, 'token_file') and 'token_file' not in server_cfg:
            self._td = tempfile.TemporaryDirectory(prefix='bnmcp-srv-')
            cfg.server.token_file = os.path.join(self._td.name, 'token')
        allow_save = server_cfg.pop('allow_save', None)
        for k, v in server_cfg.items():
            if not hasattr(cfg.server, k):
                raise AttributeError('ServerConfig has no %s' % k)
            setattr(cfg.server, k, v)
        if allow_save is not None:
            cfg.binary_ninja.allow_save_to_file = allow_save
        self.cfg = cfg
        self.mcp = self.mods.http_server.MCPServer(cfg)
        self.ops = self.mcp.binary_ops
        self.port = None

    def start(self):
        self.mcp.start()
        self.port = self.mcp.server.server_address[1]
        st = getattr(self.mcp, 'state', None)
        self.token = getattr(st, 'token', '') or ''
        if self.token:
            PORT_TOKENS[self.port] = self.token
        return self

    def stop(self):
        if self.mcp.server is not None:
            self.mcp.stop()
        if self.port is not None:
            PORT_TOKENS.pop(self.port, None)
        td = getattr(self, '_td', None)
        if td is not None:
            td.cleanup()
            self._td = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *a):
        self.stop()

    def get(self, path, params=None, **kw):
        return http_request(self.port, 'GET', path, params, **kw)

    def post(self, path, params=None, **kw):
        return http_request(self.port, 'POST', path, params, **kw)


class StubHTTP(object):
    """A tiny threaded HTTP server for client/bridge tests. routes: {(METHOD, path) | path: (status, payload) |
    callable(request_record) -> (status, payload)}; payload is a dict (sent as JSON) or bytes. Every request is
    recorded in .log as {method, path, query{k: last value}, body, ctype}."""

    def __init__(self):
        import http.server
        import socketserver
        outer = self
        self.routes = {}
        self.log = []

        class _H(http.server.BaseHTTPRequestHandler):
            def _handle(self):
                u = urllib.parse.urlsplit(self.path)
                n = int(self.headers.get('Content-Length') or 0)
                body = self.rfile.read(n) if n else b''
                q = urllib.parse.parse_qs(u.query, keep_blank_values=True)
                rec = {'method': self.command, 'path': u.path, 'query': {k: v[-1] for k, v in q.items()},
                       'headers': {k.lower(): v for k, v in self.headers.items()},
                       'body': body, 'ctype': self.headers.get('Content-Type', '')}
                outer.log.append(rec)
                spec = outer.routes.get((self.command, u.path), outer.routes.get(u.path, (200, {'ok': True})))
                st, payload = spec(rec) if callable(spec) else spec
                raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode('utf-8')
                self.send_response(st)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(raw)

            do_GET = do_POST = do_DELETE = _handle

            def log_message(self, *a):
                pass

        self.httpd = socketserver.ThreadingTCPServer(('127.0.0.1', 0), _H)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.url = 'http://127.0.0.1:%d' % self.port
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def reset(self):
        self.routes.clear()
        del self.log[:]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def fnv1a32(data):
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return '%08x' % h


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]
    finally:
        s.close()


def plugin_py_files(root=None):
    root = root or plugin_dir()
    out = []
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in ('.venv', '__pycache__', '.git', 'node_modules'))
        for f in sorted(files):
            if f.endswith('.py'):
                out.append(os.path.join(d, f))
    return out


# =====================================================================================================================
# main
# =====================================================================================================================
def _filter(suite, patterns):
    out = unittest.TestSuite()
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            out.addTests(_filter(t, patterns))
        elif any(p in t.id() for p in patterns):
            out.addTest(t)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description='Offline tests of binja-agent-mcp (contract %s).' % CONTRACT)
    ap.add_argument('--plugin', default=None, help='plugin tree (default ../binja_agent_mcp)')
    ap.add_argument('--client', default=None, help='bn_mcp_client.py (default ../bn_mcp_client.py)')
    ap.add_argument('-k', action='append', default=[], help='run only tests whose id contains this text')
    ap.add_argument('-v', action='store_true', help='verbose')
    args = ap.parse_args(argv)
    plugin, client = configure(args.plugin, args.client)
    if not os.path.isfile(os.path.join(plugin, 'plugin', 'core', 'binary_operations.py')):
        sys.stderr.write('run_tests: not a plugin tree (no plugin/core/binary_operations.py): %s\n' % plugin)
        return 2
    if not os.path.isfile(client):
        sys.stderr.write('run_tests: bn_mcp_client.py not found: %s\n' % client)
        return 2
    os.environ['BN_MCP_TEST_PLUGIN'] = plugin
    os.environ['BN_MCP_TEST_CLIENT'] = client
    clear_bn_env()
    install_live_port_tripwire()
    sys.modules.setdefault('run_tests', sys.modules[__name__])
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    ensure_fake()
    sys.stderr.write('run_tests: plugin=%s\nrun_tests: client=%s\nrun_tests: python=%s %s\n'
                     % (plugin, client, sys.executable, sys.version.split()[0]))
    suite = unittest.TestLoader().discover(HERE, pattern='test_*.py', top_level_dir=HERE)
    if args.k:
        suite = _filter(suite, args.k)
    res = unittest.TextTestRunner(verbosity=2 if args.v else 1, stream=sys.stderr).run(suite)
    for td in _TMP_KEEP:
        try:
            td.cleanup()
        except Exception:
            pass
    return 0 if res.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
