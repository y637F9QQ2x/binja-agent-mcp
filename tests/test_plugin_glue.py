# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""The Binary Ninja glue (plugin/__init__.py) and the registry of views open in the UI.

* plugin/__init__.py is executed here (the other modules import the plugin through a synthetic package that skips it)
  with a test-local stand-in for `binaryninjaui`: the menu commands, the close notifications and the UI view sync.
* Binary Ninja creates a new Python wrapper of a view for every call and event callback, and its BinaryView compares
  and hashes by the core handle. _Wrapper models that: a fresh object per call, equal to every other wrapper of the
  same (fake) view. The fake's own views compare by identity, so these tests use _Wrapper for everything the UI hands
  to the plugin.
* No server started here binds 9009: the glue's configuration gets port 0 before any start.
"""

import gc
import importlib.util
import inspect
import os
import sys
import tempfile
import types
import unittest

import run_tests as H


class _Wrapper(object):
    """A Binary Ninja-like wrapper: a new object per call, equal to (and hashing like) every wrapper of the same view."""

    def __init__(self, core):
        object.__setattr__(self, '_core', core)

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, '_core'), name)

    def __setattr__(self, name, value):
        setattr(object.__getattribute__(self, '_core'), name, value)

    def __eq__(self, other):
        return isinstance(other, _Wrapper) and other._core is self._core

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return id(object.__getattribute__(self, '_core'))


class RegistryOfUIViewsTests(unittest.TestCase):
    def setUp(self):
        self.m = H.plugin_modules()
        H.reset_plugin_state(self.m)
        self.td = tempfile.TemporaryDirectory(prefix='bnmcp-glue-')
        self.addCleanup(self.td.cleanup)
        self.a = H.make_view(os.path.join(self.td.name, 'a'), 'a.dll', 'A')
        self.b = H.make_view(os.path.join(self.td.name, 'b'), 'b.dll', 'B')
        self.ops = H.new_ops(self.m)

    def ids(self):
        return {x['filename']: x['id'] for x in self.ops.list_open_binaries()}

    def test_a_view_registered_from_a_dying_wrapper_disappears(self):
        """The problem sync_ui_views solves: a wrapper that only the registry's weak reference holds is gone after the
        callback that registered it (Binary Ninja's event callbacks hand the plugin exactly such wrappers)."""
        self.ops.register_view(_Wrapper(self.a))
        gc.collect()
        self.assertEqual(self.ops.list_open_binaries(), [])

    def test_ui_views_keep_their_ids_until_their_tab_closes(self):
        r = self.ops.sync_ui_views([_Wrapper(self.a), _Wrapper(self.b)], active=_Wrapper(self.a))
        self.assertEqual(r['removed'], [])
        gc.collect()
        ids = self.ids()
        self.assertEqual(sorted(ids), sorted([self.a.file.filename, self.b.file.filename]))
        self.assertEqual(sorted(ids.values()), r['pinned'])
        # a request by view id answers from the right view, after every wrapper the UI handed over is gone
        bv, vid = self.ops.locate_binary('view:' + ids[self.b.file.filename])
        self.assertEqual((bv, vid), (_Wrapper(self.b), ids[self.b.file.filename]))
        self.assertEqual(self.ops.global_view(), _Wrapper(self.a), 'the active tab becomes the selection')
        # the next sync hands over new wrappers: same ids
        self.assertEqual(self.ops.sync_ui_views([_Wrapper(self.a), _Wrapper(self.b)])['pinned'], r['pinned'])
        gc.collect()
        self.assertEqual(self.ids(), ids)
        # b's tab was closed: a complete sync without it unregisters it, a stays
        r3 = self.ops.sync_ui_views([_Wrapper(self.a)])
        self.assertEqual(r3['removed'], [ids[self.b.file.filename]])
        gc.collect()
        self.assertEqual(self.ids(), {self.a.file.filename: ids[self.a.file.filename]})
        with self.assertRaises(self.m.rc.NotFoundError):
            self.ops.locate_binary('view:' + ids[self.b.file.filename])
        # OnAfterCloseFile for a (by its FileMetadata): unregistered, and the selection is cleared
        self.assertEqual(self.ops.release_file(self.a.file, self.a.file.filename), 1)
        self.assertIsNone(self.ops.global_view())
        self.assertEqual(self.ops.list_open_binaries(), [])

    def test_an_incomplete_sync_never_unregisters(self):
        self.ops.sync_ui_views([_Wrapper(self.a), _Wrapper(self.b)])
        r = self.ops.sync_ui_views([_Wrapper(self.a)], complete=False)
        self.assertEqual(r['removed'], [])
        gc.collect()
        self.assertEqual(len(self.ops.list_open_binaries()), 2)

    def test_owned_views_are_never_touched_by_the_ui_sync(self):
        vid = self.ops.mark_owned(self.a)
        self.ops.sync_ui_views([_Wrapper(self.b)])
        self.ops.sync_ui_views([])
        self.assertEqual([x['id'] for x in self.ops.list_open_binaries()], [vid])
        self.assertEqual(self.ops.release_file(self.a.file, self.a.file.filename), 0)

    def test_release_by_file_name_when_the_metadata_matches_nothing(self):
        self.ops.sync_ui_views([_Wrapper(self.a), _Wrapper(self.b)])
        self.assertEqual(self.ops.release_file(object(), self.b.file.filename), 1)
        gc.collect()
        self.assertEqual(list(self.ids()), [self.a.file.filename])


# ---------------------------------------------------------------------------------------------------------------------
# plugin/__init__.py with a stand-in for binaryninjaui
# ---------------------------------------------------------------------------------------------------------------------
class _Frame(object):
    def __init__(self, view):
        self.view = view

    def getCurrentBinaryView(self):
        return _Wrapper(self.view) if self.view is not None else None


class _Context(object):
    def __init__(self):
        self.views = []          # fake views open in tabs
        self.active = None

    def getAvailableBinaryViews(self):
        return [(_Wrapper(v), os.path.basename(v.file.filename)) for v in self.views]

    def getCurrentViewFrame(self):
        return _Frame(self.active)


class _FileContext(object):
    def __init__(self, view):
        self.view = view

    def getMetadata(self):
        return self.view.file

    def getFilename(self):
        return self.view.file.filename


def _fake_ui_module(ctx):
    ui = types.ModuleType('binaryninjaui')

    class UIContextNotification(object):
        pass

    class UIContext(object):
        notifications = []

        @staticmethod
        def registerNotification(n):
            UIContext.notifications.append(n)

        @staticmethod
        def allContexts():
            return [ctx]

        @staticmethod
        def activeContext():
            return ctx

    ui.UIContextNotification = UIContextNotification
    ui.UIContext = UIContext
    return ui


class PluginGlueTests(unittest.TestCase):
    def setUp(self):
        self.bn = H.ensure_fake()
        H.reset_plugin_state()
        self.td = tempfile.TemporaryDirectory(prefix='bnmcp-glue-')
        self.addCleanup(self.td.cleanup)
        self.ctx = _Context()
        self.a = H.make_view(os.path.join(self.td.name, 'a'), 'a.dll', 'A')
        self.b = H.make_view(os.path.join(self.td.name, 'b'), 'b.dll', 'B')
        self.ctx.views = [self.a, self.b]
        self.ctx.active = self.a
        saved_ui = sys.modules.get('binaryninjaui')
        sys.modules['binaryninjaui'] = _fake_ui_module(self.ctx)
        self.addCleanup(self._restore_ui, saved_ui)
        del self.bn.PluginCommand.REGISTERED[:]

    @staticmethod
    def _restore_ui(saved):
        if saved is None:
            sys.modules.pop('binaryninjaui', None)
        else:
            sys.modules['binaryninjaui'] = saved

    def load_glue(self, name):
        pkg_dir = os.path.join(H.plugin_dir(), 'plugin')
        spec = importlib.util.spec_from_file_location(name, os.path.join(pkg_dir, '__init__.py'),
                                                      submodule_search_locations=[pkg_dir])
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        self.addCleanup(sys.modules.pop, name, None)
        spec.loader.exec_module(mod)
        cfg = mod.plugin.config.server
        cfg.port = 0                                    # never the port a running Binary Ninja may hold
        cfg.token_file = os.path.join(self.td.name, name + '.token')
        self.addCleanup(self._stop, mod)
        return mod

    @staticmethod
    def _stop(mod):
        if mod.plugin.server and mod.plugin.server.server:
            mod.plugin.server.stop()

    def test_menu_commands_are_global_and_take_no_argument(self):
        glue = self.load_glue('bnmcp_glue_global')
        self.assertEqual(glue.MENU_KIND, 'global')
        regs = [r for r in self.bn.PluginCommand.REGISTERED]
        self.assertEqual([(r[0], r[1]) for r in regs],
                         [('register_global', 'MCP Server\\Start MCP Server'),
                          ('register_global', 'MCP Server\\Stop MCP Server')])
        for _kind, _name, _desc, action in regs:
            self.assertEqual(list(inspect.signature(action).parameters), [], 'a global command gets no argument')
        start, stop = regs[0][3], regs[1][3]
        self.assertEqual(glue.plugin.config.server.port, 0)
        start()                                         # what the menu does, with no binary open
        self.assertIsNotNone(glue.plugin.server.server)
        ops = glue.plugin.server.binary_ops
        self.assertEqual(ops.global_view(), _Wrapper(self.a), 'the active tab is selected after the start')
        stop()
        self.assertIsNone(glue.plugin.server.server)

    def test_an_invalid_switch_value_is_off_and_logged_once(self):
        """BN_MCP_AUTOSTART and BN_MCP_AUTO_SETUP: 1 is on; unset, empty and 0 are off; any other value is off, with
        one warning in the log. The glue is loaded with both unset, and the switch functions are only called (with a
        value of 1 nothing starts here)."""
        glue = self.load_glue('bnmcp_glue_switches')
        self.assertIsNone(glue.plugin.server.server, 'nothing started at load')
        names = ('BN_MCP_AUTOSTART', 'BN_MCP_AUTO_SETUP')
        saved = {k: os.environ.get(k) for k in names}

        def restore():
            for k, val in saved.items():
                if val is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = val
        self.addCleanup(restore)
        for fn, name in zip((glue._autostart_enabled, glue._auto_setup_enabled), names):
            with self.subTest(variable=name):
                for value, want in (('1', True), (' 1 ', True), ('0', False), ('', False)):
                    os.environ[name] = value
                    self.assertIs(fn(), want, repr(value))
                os.environ.pop(name)
                self.assertIs(fn(), False)
                msg = "MCP config: ignoring %s='on please' (use 1 or 0)" % name

                def warned():
                    return sum(1 for lvl, m in list(self.bn.LOGS) if lvl == 'warn' and m == msg)
                n0 = warned()
                os.environ[name] = 'on please'
                self.assertIs(fn(), False)
                self.assertIs(fn(), False)
                self.assertEqual(warned(), n0 + 1, 'one warning for an invalid value')
                os.environ.pop(name)

    def test_builds_without_register_global_fall_back_to_register(self):
        saved = self.bn.PluginCommand.__dict__['register_global']
        del self.bn.PluginCommand.register_global
        self.addCleanup(setattr, self.bn.PluginCommand, 'register_global', saved)
        glue = self.load_glue('bnmcp_glue_view')
        self.assertEqual(glue.MENU_KIND, 'view')
        self.assertEqual([r[0] for r in self.bn.PluginCommand.REGISTERED], ['register', 'register'])

    def test_close_notifications_release_the_closed_file_only(self):
        glue = self.load_glue('bnmcp_glue_close')
        ops = glue.plugin.server.binary_ops
        gc.collect()
        self.assertEqual(sorted(x['filename'] for x in ops.list_open_binaries()),
                         sorted([self.a.file.filename, self.b.file.filename]), 'the load-time sync registers the tabs')
        note = sys.modules['binaryninjaui'].UIContext.notifications[-1]
        # a is the active tab; b, a background tab, is closed
        self.assertIs(note.OnBeforeCloseFile(self.ctx, _FileContext(self.b), None), True, 'a close is never vetoed')
        gc.collect()
        self.assertEqual(len(ops.list_open_binaries()), 2, 'nothing is released before the close happens')
        self.ctx.views = [self.a]
        note.OnAfterCloseFile(self.ctx, _FileContext(self.b), None)
        gc.collect()
        self.assertEqual([x['filename'] for x in ops.list_open_binaries()], [self.a.file.filename])
        # opening a file again: OnAfterOpenFile registers it under a new id
        self.ctx.views = [self.a, self.b]
        note.OnAfterOpenFile(self.ctx, _FileContext(self.b), None)
        gc.collect()
        self.assertEqual(len(ops.list_open_binaries()), 2)


if __name__ == '__main__':
    unittest.main()
