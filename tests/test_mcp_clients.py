# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""MCP client configuration: plugin/utils/mcp_clients.py and scripts/mcp_client_installer.py.

Every configuration file lives in a temporary HOME / USERPROFILE / APPDATA (each target path is checked to be inside
it before the installer runs). No virtual environment is created and nothing is downloaded: the installer gets
--python (the running interpreter) and --config / --list are read-only.
"""

import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

import run_tests as H


def _mc():
    H.plugin_modules()                       # the synthetic package bnmcp_live; utils is a subpackage of it
    return importlib.import_module(H.LIVE_ALIAS + '.utils.mcp_clients')


def _importable():
    import importlib.util as u
    return all(u.find_spec(n) is not None for n in ('mcp', 'requests', 'anyio'))


class ClientTableTests(unittest.TestCase):
    def test_timeouts_are_written_only_where_a_client_documents_them_in_its_unit(self):
        mc = _mc()
        for platform in ('win32', 'darwin', 'linux'):
            with self.subTest(platform=platform):
                cs = {c.name: c for c in mc.clients(home='H', appdata='A', platform=platform)}
                want = ['Cline', 'Roo Code', 'Cursor', 'Windsurf', 'LM Studio', 'Claude Code']
                if platform != 'linux':
                    want.insert(2, 'Claude Desktop')
                self.assertEqual(list(cs), want)
                for name in ('Cline', 'Roo Code'):
                    self.assertEqual(cs[name].extra, {'timeout': 60, 'disabled': False}, 'seconds')
                for name in ('Cursor', 'Windsurf', 'LM Studio') + (('Claude Desktop',) if platform != 'linux' else ()):
                    self.assertEqual(cs[name].extra, {}, '%s documents no timeout key' % name)
                self.assertFalse(cs['Claude Code'].writes_file, '~/.claude.json is never edited')
        self.assertEqual(mc.clients(platform='sunos5'), [])

    def test_the_claude_code_command(self):
        """The --env pairs come before --scope: --env takes one or more values, so the server name must follow
        another flag's value, never a KEY=value pair."""
        mc = _mc()
        cmd = mc.claude_code_command('C:\\Program Files\\py\\python.exe', 'C:\\b\\bridge.py', {'BN_MCP_TOOLSET': 'core'},
                                     platform='win32')
        self.assertEqual(cmd, 'claude mcp add --env BN_MCP_TOOLSET=core --scope user --transport stdio binja_agent_mcp '
                              '-- "C:\\Program Files\\py\\python.exe" C:\\b\\bridge.py')
        cmd = mc.claude_code_command('/opt/my py/bin/python3', '/b/bridge.py', None, platform='linux')
        self.assertEqual(cmd, "claude mcp add --scope user --transport stdio binja_agent_mcp -- '/opt/my py/bin/python3' "
                              "/b/bridge.py")
        env = {'PYTHONPATH': '/x y', 'BN_MCP_TOOLSET': 'core'}
        cmd = mc.claude_code_command('/usr/bin/python3', '/b/bridge.py', env, platform='linux')
        self.assertEqual(cmd, "claude mcp add --env BN_MCP_TOOLSET=core --env 'PYTHONPATH=/x y' --scope user "
                              "--transport stdio binja_agent_mcp -- /usr/bin/python3 /b/bridge.py")


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.mc = _mc()
        self.td = tempfile.TemporaryDirectory(prefix='bnmcp-clients-')
        self.addCleanup(self.td.cleanup)
        self.home = os.path.join(self.td.name, 'home')
        self.appdata = os.path.join(self.td.name, 'appdata')
        os.makedirs(self.home)
        os.makedirs(self.appdata)
        self.targets = {c.name: c for c in self.mc.clients(self.home, self.appdata)}
        for c in self.targets.values():
            self.assertTrue(os.path.abspath(c.config_path).startswith(self.td.name), c.config_path)

    def read(self, name):
        with open(self.targets[name].config_path, encoding='utf-8') as f:
            return json.load(f)

    def test_install_merges_keeps_other_servers_and_uninstall_removes(self):
        cline, cursor = self.targets['Cline'], self.targets['Cursor']
        os.makedirs(cline.config_dir)
        os.makedirs(cursor.config_dir)
        with open(cline.config_path, 'w', encoding='utf-8') as f:
            json.dump({'mcpServers': {'other': {'command': 'x'},
                                      'binja_agent_mcp': {'command': 'old', 'env': {'BN_MCP_TOOLSET': 'analysis'}}},
                       'keep': 1}, f)
        res = self.mc.install(list(self.targets.values()), 'PY', 'BRIDGE')
        by = {name: what for name, _p, what in res}
        self.assertTrue(by['Cline'].startswith('installed'), by)
        self.assertTrue(by['Cursor'].startswith('installed'), by)
        self.assertTrue(by['Claude Code'].startswith('run: claude mcp add'), by)
        self.assertTrue(by['Windsurf'].startswith('skipped'), by)
        self.assertFalse(os.path.exists(self.targets['Claude Code'].config_path), '~/.claude.json was not created')
        c = self.read('Cline')
        self.assertEqual(c['keep'], 1)
        self.assertEqual(c['mcpServers']['other'], {'command': 'x'})
        self.assertEqual(c['mcpServers']['binja_agent_mcp'],
                         {'command': 'PY', 'args': ['BRIDGE'], 'env': {'BN_MCP_TOOLSET': 'analysis'}, 'timeout': 60,
                          'disabled': False})
        self.assertEqual(self.read('Cursor')['mcpServers']['binja_agent_mcp'], {'command': 'PY', 'args': ['BRIDGE']})
        self.assertEqual(sorted(os.listdir(cline.config_dir)), ['cline_mcp_settings.json'], 'no temporary file is left')
        res = self.mc.install(list(self.targets.values()), 'PY', 'BRIDGE', uninstall=True)
        self.assertNotIn('binja_agent_mcp', self.read('Cline')['mcpServers'])
        self.assertEqual(self.read('Cline')['mcpServers']['other'], {'command': 'x'})
        self.assertIn('claude mcp remove', dict((n, w) for n, _p, w in res)['Claude Code'])

    def test_a_file_that_is_not_a_configuration_is_left_alone(self):
        cursor = self.targets['Cursor']
        os.makedirs(cursor.config_dir)
        for text in ('{not json', '[1, 2]', '{"mcpServers": []}'):
            with self.subTest(text=text):
                with open(cursor.config_path, 'w', encoding='utf-8') as f:
                    f.write(text)
                res = dict((n, w) for n, _p, w in self.mc.install([cursor], 'PY', 'BRIDGE'))
                self.assertTrue(res['Cursor'].startswith('skipped'), res)
                with open(cursor.config_path, encoding='utf-8') as f:
                    self.assertEqual(f.read(), text)

    def test_a_missing_interpreter_or_package_is_reported(self):
        ok, why = self.mc.modules_importable(os.path.join(self.td.name, 'no-such-python.exe'))
        self.assertFalse(ok)
        self.assertIn('could not be run', why)
        with self.assertRaises(RuntimeError) as cm:
            self.mc.ensure_bridge_python(root=os.path.join(self.td.name, 'plugin'), create=False)
        self.assertIn('does not exist', str(cm.exception))
        pd = importlib.import_module(H.LIVE_ALIAS + '.utils.python_detection')
        env = {'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_NO_INDEX': '1'}
        saved = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            with self.assertRaises(RuntimeError) as cm:     # pip fails at once: the requirements file is missing
                pd._pip_install(sys.executable, os.path.join(self.td.name, 'missing.txt'), False, lambda m: None)
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.assertIn('exit code', str(cm.exception))


@unittest.skipUnless(_importable(), 'the running interpreter cannot import mcp, requests and anyio')
class InstallerCliTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(prefix='bnmcp-installer-')
        self.addCleanup(self.td.cleanup)
        self.home = os.path.join(self.td.name, 'home')
        self.appdata = os.path.join(self.td.name, 'appdata')
        os.makedirs(self.home)
        os.makedirs(self.appdata)
        self.env = dict(os.environ, HOME=self.home, USERPROFILE=self.home, APPDATA=self.appdata,
                        XDG_CONFIG_HOME=os.path.join(self.home, '.config'))
        mc = _mc()
        saved = {k: os.environ.get(k) for k in ('HOME', 'USERPROFILE', 'APPDATA')}
        os.environ.update({'HOME': self.home, 'USERPROFILE': self.home, 'APPDATA': self.appdata})
        try:
            self.targets = {c.name: c for c in mc.clients()}
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        for c in self.targets.values():
            self.assertTrue(os.path.abspath(c.config_path).startswith(self.td.name),
                            'the installer would write outside the test folder: %s' % c.config_path)
        self.script = os.path.join(H.plugin_dir(), 'scripts', 'mcp_client_installer.py')
        self.venv = os.path.join(H.plugin_dir(), '.venv')
        self.venv_existed = os.path.exists(self.venv)

    def run_installer(self, *args):
        p = subprocess.run([sys.executable, '-I', '-B', self.script] + list(args), capture_output=True, text=True,
                           timeout=180, env=self.env, cwd=self.td.name)
        self.assertEqual(os.path.exists(self.venv), self.venv_existed, 'the installer created <plugin>/.venv')
        return p

    def test_install_list_config_and_uninstall(self):
        os.makedirs(self.targets['Roo Code'].config_dir)
        p = self.run_installer('--list')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('Roo Code', p.stdout)
        p = self.run_installer('--config', '--python', sys.executable)
        self.assertEqual(p.returncode, 0, p.stderr)
        entry = json.loads(p.stdout)['mcpServers']['binja_agent_mcp']
        self.assertEqual(entry, {'command': os.path.abspath(sys.executable),
                                 'args': [os.path.join(os.path.realpath(H.plugin_dir()), 'bridge',
                                                       'binja_mcp_bridge.py')]})
        p = self.run_installer('--install', '--python', sys.executable)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('run: claude mcp add', p.stdout)
        with open(self.targets['Roo Code'].config_path, encoding='utf-8') as f:
            roo = json.load(f)['mcpServers']['binja_agent_mcp']
        self.assertEqual((roo['timeout'], roo['command']), (60, os.path.abspath(sys.executable)))
        self.assertNotIn('env', roo, 'no PYTHON* variable without --copy-python-env')
        self.assertFalse(os.path.exists(self.targets['Claude Code'].config_path))
        p = self.run_installer('--uninstall')
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(self.targets['Roo Code'].config_path, encoding='utf-8') as f:
            self.assertNotIn('binja_agent_mcp', json.load(f)['mcpServers'])

    def test_an_interpreter_without_the_packages_writes_nothing(self):
        os.makedirs(self.targets['Cursor'].config_dir)
        p = self.run_installer('--install', '--python', os.path.join(self.td.name, 'no-such-python.exe'))
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn('No configuration file was changed', p.stdout)
        self.assertFalse(os.path.exists(self.targets['Cursor'].config_path))

    def test_no_flag_prints_the_usage_and_changes_nothing(self):
        os.makedirs(self.targets['Cursor'].config_dir)
        p = self.run_installer()
        self.assertEqual(p.returncode, 0)
        self.assertIn('--install', p.stdout)
        self.assertFalse(os.path.exists(self.targets['Cursor'].config_path))


if __name__ == '__main__':
    unittest.main()
