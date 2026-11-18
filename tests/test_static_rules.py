# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""Static rules over the plugin under test (plugin/** and bridge/**), and one HTTP check.

Fails on:
  * a UI prompt or focus API anywhere in code (tokens, so comments and docstrings do not count): show_message_box,
    get_text_line_input, get_int_input, get_address_input, get_choice_input, get_open_filename_input,
    get_save_filename_input, get_directory_name_input, get_form_input, openFilename, `.navigate(`,
    SetForegroundWindow, BringWindowToTop, ShowWindow (the README says the plugin never shows a dialog);
  * execute_on_main_thread_and_wait anywhere (a request thread must never wait for the UI thread), and
    binaryninjaui's execute_on_main_thread anywhere;
  * a subprocess.run / Popen / call / check_output / check_call (or an injected `popen`) call without
    creationflags=_NO_WINDOW, or a module that spawns without `_NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)`;
  * a CORS header (Access-Control-Allow-*) anywhere in the server code.
The scanner itself is tested on planted violations.
"""

import ast
import io
import os
import re
import tempfile
import tokenize
import unittest

import run_tests as H

FORBIDDEN_TOKENS = frozenset((
    'show_message_box', 'get_text_line_input', 'get_int_input', 'get_address_input', 'get_choice_input',
    'get_open_filename_input', 'get_save_filename_input', 'get_directory_name_input', 'get_form_input',
    'openFilename', 'SetForegroundWindow', 'BringWindowToTop', 'ShowWindow'))
SPAWN_ATTRS = frozenset(('run', 'Popen', 'call', 'check_output', 'check_call'))


def scan_source(rel, src):
    """-> list of violation strings for one file (rel: forward-slash path relative to the plugin root)."""
    v = []
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return ['%s: does not parse (%s)' % (rel, e)]
    toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
    for i, t in enumerate(toks):
        if t.type != tokenize.NAME:
            continue
        if t.string in FORBIDDEN_TOKENS:
            v.append('%s:%d uses %s' % (rel, t.start[0], t.string))
        if t.string == 'navigate' and i and toks[i - 1].string == '.' and i + 1 < len(toks) and toks[i + 1].string == '(':
            v.append('%s:%d calls .navigate(' % (rel, t.start[0]))
        if t.string == 'execute_on_main_thread_and_wait':
            v.append('%s:%d uses execute_on_main_thread_and_wait' % (rel, t.start[0]))
    for t in toks:
        if t.type == tokenize.STRING and re.search(r'Access-Control-Allow-', t.string):
            v.append('%s:%d sends a CORS header' % (rel, t.start[0]))
    ui_aliases = {'binaryninjaui', 'ui'}
    for n in ast.walk(tree):
        if isinstance(n, ast.Attribute) and n.attr == 'execute_on_main_thread' and isinstance(n.value, ast.Name) \
                and n.value.id in ui_aliases:
            v.append('%s:%d uses %s.execute_on_main_thread (use binaryninja.mainthread)' % (rel, n.lineno, n.value.id))
    spawns = False
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        hit = (isinstance(f, ast.Attribute) and f.attr in SPAWN_ATTRS and isinstance(f.value, ast.Name)
               and f.value.id == 'subprocess') or (isinstance(f, ast.Name) and f.id == 'Popen') or \
              (isinstance(f, ast.Attribute) and f.attr.lower() == 'popen')
        if not hit:
            continue
        spawns = True
        kw = [k for k in n.keywords if k.arg == 'creationflags']
        if not kw or not any(isinstance(x, ast.Name) and x.id == '_NO_WINDOW' for x in ast.walk(kw[0].value)):
            v.append('%s:%d spawns a process without creationflags=_NO_WINDOW' % (rel, n.lineno))
    if spawns:
        has_def = False
        for n in tree.body:
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == '_NO_WINDOW' for t in n.targets):
                s = ast.unparse(n.value)
                if s.replace(' ', '') in ("getattr(subprocess,'CREATE_NO_WINDOW',0)", 'getattr(subprocess,"CREATE_NO_WINDOW",0)'):
                    has_def = True
        if not has_def:
            v.append("%s: spawns processes but lacks _NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)" % rel)
    return v


def scan_tree(root):
    out = []
    files = 0
    for sub in ('plugin', 'bridge', 'scripts'):
        d = os.path.join(root, sub)
        for dp, dirs, fs in os.walk(d):
            dirs[:] = [x for x in dirs if x not in ('__pycache__', '.venv')]
            for f in sorted(fs):
                if not f.endswith('.py'):
                    continue
                p = os.path.join(dp, f)
                rel = os.path.relpath(p, root).replace('\\', '/')
                with open(p, encoding='utf-8') as fh:
                    out.extend(scan_source(rel, fh.read()))
                files += 1
    return out, files


class StaticRulesTests(unittest.TestCase):
    def test_plugin_bridge_and_scripts_obey_the_rules(self):
        v, n = scan_tree(H.plugin_dir())
        self.assertGreaterEqual(n, 14)
        self.assertEqual(v, [])

    def test_the_spawning_modules_are_the_expected_ones(self):
        spawning = []
        for sub in ('plugin', 'bridge', 'scripts'):
            for dp, dirs, fs in os.walk(os.path.join(H.plugin_dir(), sub)):
                dirs[:] = [x for x in dirs if x != '__pycache__']
                for f in fs:
                    if f.endswith('.py'):
                        src = open(os.path.join(dp, f), encoding='utf-8').read()
                        if re.search(r'\bsubprocess\.(run|Popen|call|check_output)\(|self\.popen\(', src):
                            spawning.append(f)
        self.assertEqual(sorted(spawning), ['binary_operations.py', 'mcp_clients.py', 'python_detection.py'])

    def test_the_scanner_catches_planted_violations(self):
        planted = {
            'plugin/x.py': "from binaryninja.interaction import show_message_box\nshow_message_box('a', 'b')\n",
            'plugin/y.py': "import subprocess\nsubprocess.run(['x'])\n",
            'plugin/z.py': "import subprocess\n_NO_WINDOW = 0\nsubprocess.Popen(['x'], creationflags=_NO_WINDOW)\n",
            'plugin/core/q.py': "import binaryninja\nbinaryninja.execute_on_main_thread_and_wait(f)\n",
            'plugin/v.py': "import binaryninjaui as ui\nui.execute_on_main_thread(f)\n",
            'plugin/n.py': "def f(frame):\n    frame.navigate(view, 0x1000)\n",
            'plugin/s.py': "import ctypes\nctypes.windll.user32.SetForegroundWindow(0)\n",
            'plugin/c.py': "def h(self):\n    self.send_header('Access-Control-Allow-Origin', '*')\n",
            'plugin/q2.py': "import subprocess\n_NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)\n"
                            "self.popen(['x'])\n",
        }
        for rel, src in planted.items():
            with self.subTest(rel=rel):
                self.assertTrue(scan_source(rel, src), 'the planted violation in %s was not caught' % rel)
        clean = {
            'plugin/c.py': "import subprocess\n_NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)\n"
                           "subprocess.run(['x'], creationflags=_NO_WINDOW | 4)\n",
            'plugin/d.py': "# show_message_box is never called\n'''SetForegroundWindow is documented here'''\n",
            'plugin/e.py': "from binaryninja import mainthread\nmainthread.execute_on_main_thread(f)\n",
        }
        for rel, src in clean.items():
            with self.subTest(clean=rel):
                self.assertEqual(scan_source(rel, src), [])


class StatusPathTests(unittest.TestCase):
    def test_status_never_calls_the_main_thread_and_reports_the_auth_policy(self):
        m = H.plugin_modules()
        H.reset_plugin_state(m)
        bn = H.ensure_fake()
        with H.Server(m) as srv:
            n0 = len(bn.MAIN_THREAD_CALLS)
            r = srv.get('/status')
            self.assertEqual(r.status, 200, r.raw[:300])
            self.assertEqual(bn.MAIN_THREAD_CALLS[n0:], [], '/status never calls the main thread')
            sv = r.json['server']
            self.assertEqual(sv['auth'], {'host_check': True, 'browser_check': True, 'require_token': True})
            self.assertEqual(sv['pid'], os.getpid())
            # with a binary selected, a path outside the route tables is a plain 404, for GET and POST alike
            td = tempfile.TemporaryDirectory(prefix='bnmcp-static-')
            self.addCleanup(td.cleanup)
            v = H.make_view(td.name, 'foo.dll', 'A')
            srv.ops.current_view = v
            for method in ('GET', 'POST'):
                r = H.http_request(srv.port, method, '/x/noSuchVerb', json_body={} if method == 'POST' else None)
                self.assertEqual(r.status, 404, (method, r.raw[:200]))


if __name__ == '__main__':
    unittest.main()
