# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""The scripts in tools/: the smoke test (run here against the plugin's real HTTP server on the fake binaryninja, so
this checks the script, not Binary Ninja) and the tool-definition measurement behind the README table."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

import run_tests as H

TOOLS = os.path.join(H.REPO_ROOT, 'tools')


def _importable():
    return all(importlib.util.find_spec(n) is not None for n in ('mcp', 'requests', 'anyio'))


class SmokeScriptTests(unittest.TestCase):
    def test_every_step_passes_against_the_real_server(self):
        m = H.plugin_modules()
        H.reset_plugin_state(m)
        td = tempfile.TemporaryDirectory(prefix='bnmcp-smoke-')
        self.addCleanup(td.cleanup)
        path = H.fake_bv().make_standard_file(td.name, 'sample.dll', 'S')
        with H.Server(m) as srv:
            env = dict(os.environ, BN_MCP_TOKEN_FILE=srv.cfg.server.token_file)
            p = subprocess.run([sys.executable, '-I', '-B', os.path.join(TOOLS, 'smoke_test.py'), '--binary', path,
                                '--url', 'http://127.0.0.1:%d' % srv.port, '--analysis-timeout', '30'],
                               capture_output=True, text=True, timeout=180, env=env, cwd=td.name)
            rows = [json.loads(x) for x in p.stdout.splitlines() if x.strip()]
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertEqual([r['step'] for r in rows[:-1]],
                             ['status', 'binaries', 'load', 'analysis', 'decompile', 'xrefs', 'rename', 'close'])
            self.assertEqual(rows[-1], {'summary': 'passed', 'steps': 8, 'failed': []})
            self.assertEqual([b for b in srv.ops.list_open_binaries() if b.get('owned')], [], 'the view was closed')

    def test_a_server_without_the_token_fails_at_the_first_step(self):
        m = H.plugin_modules()
        with H.Server(m) as srv:
            td = tempfile.TemporaryDirectory(prefix='bnmcp-smoke-')
            self.addCleanup(td.cleanup)
            env = dict(os.environ, BN_MCP_TOKEN_FILE=os.path.join(td.name, 'missing-token'))
            p = subprocess.run([sys.executable, '-I', '-B', os.path.join(TOOLS, 'smoke_test.py'), '--binary',
                                os.path.join(td.name, 'x.dll'), '--url', 'http://127.0.0.1:%d' % srv.port],
                               capture_output=True, text=True, timeout=120, env=env, cwd=td.name)
        rows = [json.loads(x) for x in p.stdout.splitlines() if x.strip()]
        self.assertEqual(p.returncode, 1)
        self.assertEqual((rows[0]['step'], rows[0]['ok']), ('status', False))
        self.assertEqual(rows[-1]['summary'], 'failed')


@unittest.skipUnless(_importable(), 'mcp/requests/anyio are not importable here')
class MeasureScriptTests(unittest.TestCase):
    def measure(self, bridge, toolset=None):
        args = [sys.executable, '-I', '-B', os.path.join(TOOLS, 'measure_tool_definitions.py'), bridge, '--json']
        if toolset:
            args += ['--toolset', toolset]
        p = subprocess.run(args, capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout)

    def test_the_measurement_equals_the_bridges_own_list_tools(self):
        bridge = os.path.join(H.plugin_dir(), 'bridge', 'binja_mcp_bridge.py')
        for toolset in ('core', 'full'):
            with self.subTest(toolset=toolset):
                got = self.measure(bridge, toolset)
                env = dict(os.environ, BN_MCP_TOOLSET=toolset)
                p = subprocess.run([sys.executable, '-I', '-B', bridge, '--list-tools', '--json'], capture_output=True,
                                   text=True, timeout=120, env=env, stdin=subprocess.DEVNULL)
                own = json.loads(p.stdout)
                self.assertEqual((got['tools'], got['chars']), (own['tools'], own['tools_list_chars']))
                self.assertEqual(got['per_tool'], own['per_tool_chars'])

    def test_the_upstream_bridge_registers_53_tools(self):
        if not H.BASELINE_DIR or not os.path.isdir(H.BASELINE_DIR):
            self.skipTest('the upstream v1.1.0 baseline is not available (set BN_MCP_TEST_BASELINE)')
        got = self.measure(os.path.join(H.BASELINE_DIR, 'bridge', 'binja_mcp_bridge.py'))
        self.assertEqual(got['tools'], 53)


if __name__ == '__main__':
    unittest.main()
