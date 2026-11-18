# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp, upstream commit
# d8a2709df69ff475d6be6366c2eec733663b008b, 2025-12-16).
# Copyright (C) 2025 fosdickio, CX330Blake
# Copyright (C) 2026 Kazuma Matsumoto
# Modified by Kazuma Matsumoto between 2026-10-14 and 2026-11-18; see NOTICE.md and CHANGES-FROM-UPSTREAM.md.
# SPDX-License-Identifier: GPL-3.0-or-later
# This program comes with ABSOLUTELY NO WARRANTY; see the LICENSE file for details.
"""Binary Ninja glue of binja-agent-mcp.

* The server never starts by itself unless BN_MCP_AUTOSTART=1. The menu items "Plugins > MCP Server > Start MCP
  Server" / "Stop MCP Server" are registered with PluginCommand.register_global where the API has it (then they
  need no open binary; older builds fall back to PluginCommand.register, which needs one), and the "MCP: Stopped"
  status-bar button starts the server too.
* The plugin never shows a message box: messages go to the Binary Ninja log.
* MCP client configuration files are written only by the explicit installer script, or at plugin load when
  BN_MCP_AUTO_SETUP=1 is set.
* The binaries open in the UI are registered by _sync_ui_views: on the UI notifications (a file opened, a view
  changed, a file closed) and every _UI_SYNC_INTERVAL_MS on the main thread, from UIContext.getAvailableBinaryViews.
  The registry keeps a reference to each such view while its tab is open (Binary Ninja creates a new Python wrapper
  per call, so a wrapper nobody keeps would vanish) and drops it when the file is closed.

All main-thread dispatch goes through binaryninja.mainthread.execute_on_main_thread (fallback
binaryninja.execute_on_main_thread); never binaryninjaui.execute_on_main_thread and never a *_and_wait variant here.
"""

import os
import threading

import binaryninja as bn
from .core.config import Config
from .server.http_server import MCPServer


# When true, suppress auto-start while a BinaryView is open until the user
# explicitly starts the server again. This prevents immediate re-start after stop.
_mcp_user_stopped = False

_UI_SYNC_INTERVAL_MS = 2000

_WARNED_SWITCHES = set()


def _switch_on(name) -> bool:
    """A 0/1 switch of the plugin: 1 is on; unset, empty and 0 are off. Any other value is off and is logged as a
    warning (once per value), like an invalid value of the other BN_MCP_* variables (core/config.py)."""
    raw = os.environ.get(name, "")
    v = raw.strip()
    if v == "1":
        return True
    if v not in ("", "0") and (name, raw) not in _WARNED_SWITCHES:
        _WARNED_SWITCHES.add((name, raw))
        bn.log_warn("MCP config: ignoring %s=%r (use 1 or 0)" % (name, raw))
    return False


def _autostart_enabled() -> bool:
    return _switch_on("BN_MCP_AUTOSTART")


def _auto_setup_enabled() -> bool:
    return _switch_on("BN_MCP_AUTO_SETUP")


def _on_main(fn):
    """Queue fn on the Binary Ninja main thread (asynchronous; never waits)."""
    try:
        from binaryninja import mainthread as _mt
        _mt.execute_on_main_thread(fn)
        return True
    except Exception:
        try:
            bn.execute_on_main_thread(fn)
            return True
        except Exception:
            return False


class BinaryNinjaMCP:
    def __init__(self):
        self.config = Config()
        self.server = MCPServer(self.config)

    def start_server(self, bv=None):
        """Start the HTTP server. A BinaryView is optional: with one, it becomes the global selection; without one,
        the next UI sync selects the view of the active tab."""
        global _mcp_user_stopped
        try:
            if self.server and self.server.server:
                bn.log_info("MCP server already running; skip new start")
                if bv is not None:
                    try:
                        self.server.binary_ops.register_view(bv)
                        if self.server.binary_ops.current_view is None:
                            self.server.binary_ops.current_view = bv
                    except Exception:
                        pass
                return
            if bv is not None:
                try:
                    self.server.binary_ops.current_view = bv
                    self.server.binary_ops.register_view(bv)
                except Exception:
                    pass
            self.server.start()
            _mcp_user_stopped = False
            bn.log_info(
                f"MCP server started successfully on http://{self.config.server.host}:{self.config.server.port}"
            )
            _set_status_indicator(True)
            _request_ui_sync()
        except Exception as e:
            bn.log_error(f"Failed to start MCP server: {str(e)}")

    def stop_server(self, bv=None):
        global _mcp_user_stopped
        try:
            if not (self.server and self.server.server):
                bn.log_info("MCP server stop requested but server is not running")
                return
            _mcp_user_stopped = True
            self.server.binary_ops.current_view = None
            self.server.stop()
            bn.log_info("Binary Ninja MCP plugin stopped successfully")
            _set_status_indicator(False)
        except Exception as e:
            bn.log_error(f"Failed to stop server: {str(e)}")


plugin = BinaryNinjaMCP()


def _try_autostart_for_bv(bv):
    try:
        if _mcp_user_stopped or not _autostart_enabled():
            return
        plugin.start_server(bv)
    except Exception as e:
        bn.log_error(f"MCP autostart failed: {e}")


# =====================================================================================================================
# Views open in the UI (registered in the server's view registry)
# =====================================================================================================================
def _ui_open_views():
    """Every BinaryView open in a UI tab, from UIContext.getAvailableBinaryViews of each UI context, or None when the
    UI cannot list them (no UI, or a build without that call): then nothing is unregistered by a sync."""
    try:
        import binaryninjaui as ui
        contexts = list(ui.UIContext.allContexts())
    except Exception:
        return None
    views = []
    for ctx in contexts:
        get_all = getattr(ctx, "getAvailableBinaryViews", None)
        if not callable(get_all):
            return None
        try:
            for item in get_all() or []:
                bv = item[0] if isinstance(item, (tuple, list)) else item
                if bv is not None:
                    views.append(bv)
        except Exception:
            return None
    return views


def _ui_active_view():
    """The BinaryView of the active UI tab, or None."""
    try:
        import binaryninjaui as ui
        ctx = ui.UIContext.activeContext()
        vf = ctx.getCurrentViewFrame() if ctx else None
        if vf and hasattr(vf, "getCurrentBinaryView"):
            return vf.getCurrentBinaryView()
    except Exception:
        pass
    return None


def _sync_ui_views():
    """Register (and keep) every view open in the UI, unregister the ones that were closed, and select the active
    tab's view when nothing is selected. Runs on the main thread; a UI that cannot be listed registers the active
    view only (nothing is unregistered then)."""
    ops = getattr(plugin.server, "binary_ops", None)
    if ops is None:
        return
    try:
        active = _ui_active_view()
        views = _ui_open_views()
        if views is None:
            ops.sync_ui_views([active] if active is not None else [], active=active, complete=False)
        else:
            ops.sync_ui_views(views, active=active, complete=True)
    except Exception as e:
        bn.log_debug(f"MCP UI view sync failed: {e}")


def _request_ui_sync():
    _on_main(_sync_ui_views)


def _file_context_args(args):
    """(FileMetadata or None, file name or None) of the FileContext in a UIContextNotification callback's
    (context, file, frame) arguments."""
    fc = args[1] if len(args) > 1 else None
    md = fn = None
    try:
        md = fc.getMetadata() if fc is not None else None
    except Exception:
        md = None
    try:
        fn = fc.getFilename() if fc is not None else None
    except Exception:
        fn = None
    return md, (str(fn) if fn else None)


# =====================================================================================================================
# Status-bar indicator (UI code)
# =====================================================================================================================
_status_button = None
_status_container = None
_indicator_timer = None
_sync_timer = None


def _sidebar_icon_margin_default() -> int:
    try:
        import binaryninjaui as ui
        from PySide6.QtWidgets import QStyle
        ctx = ui.UIContext.activeContext()
        mw = getattr(ctx, "mainWindow", None)
        mw = mw() if callable(mw) else mw
        if mw and hasattr(mw, "style"):
            st = mw.style()
            if st:
                val = int(st.pixelMetric(QStyle.PM_ToolBarIconSize))
                if val > 0:
                    return val
    except Exception:
        pass
    return 24


def _ensure_status_indicator():
    def _create():
        global _status_button, _status_container
        if _status_button is not None:
            return
        try:
            import binaryninjaui as ui
            from PySide6.QtWidgets import QPushButton, QWidget, QHBoxLayout
            from PySide6.QtCore import Qt
            ctx = ui.UIContext.activeContext()
            if not ctx:
                return
            mw = getattr(ctx, "mainWindow", None)
            mw = mw() if callable(mw) else mw
            if mw is None or not hasattr(mw, "statusBar"):
                return
            sb = mw.statusBar()
            if sb is None:
                return
            btn = QPushButton()
            btn.setObjectName("mcpStatusButton")
            btn.setFlat(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setToolTip("Click to start/stop MCP server")
            btn.setStyleSheet("margin:0; padding:0 6px; border:0; border-radius:2px;")
            m = _sidebar_icon_margin_default()
            container = QWidget()
            container.setObjectName("mcpStatusContainer")
            lay = QHBoxLayout(container)
            lay.setContentsMargins(m, 0, 3, 0)
            lay.setSpacing(0)
            lay.addWidget(btn)

            def _on_click():
                try:
                    if plugin.server and plugin.server.server:
                        plugin.stop_server(None)
                    else:
                        plugin.start_server(None)
                finally:
                    _set_status_indicator(bool(plugin.server and plugin.server.server))
            btn.clicked.connect(_on_click)
            try:
                sb.insertWidget(1, container, 0)
            except Exception:
                sb.addWidget(container)
            _status_button = btn
            _status_container = container
            _paint_indicator(bool(plugin.server and plugin.server.server))
        except Exception:
            pass
    _on_main(_create)


def _paint_indicator(running):
    if _status_button is None:
        return
    _status_button.setText("MCP: Running" if running else "MCP: Stopped")


def _set_status_indicator(running: bool):
    def _update():
        _ensure_status_indicator()
        _paint_indicator(running)
    _on_main(_update)


def _start_indicator_watcher():
    if _indicator_timer is not None:
        return

    def _start():
        global _indicator_timer
        try:
            from PySide6.QtCore import QTimer
            t = QTimer()
            t.setInterval(500)

            def _tick():
                _ensure_status_indicator()
                _paint_indicator(bool(plugin.server and plugin.server.server))
                if _status_button is not None:
                    t.stop()
            t.timeout.connect(_tick)
            t.start()
            _indicator_timer = t
        except Exception:
            pass
    _on_main(_start)


def _start_ui_sync_timer():
    """Run _sync_ui_views every _UI_SYNC_INTERVAL_MS on the main thread (Qt timer), so a tab opened or closed
    without a notification is registered or unregistered within that interval."""
    if _sync_timer is not None:
        return

    def _start():
        global _sync_timer
        try:
            from PySide6.QtCore import QTimer
            t = QTimer()
            t.setInterval(_UI_SYNC_INTERVAL_MS)
            t.timeout.connect(_sync_ui_views)
            t.start()
            _sync_timer = t
        except Exception:
            pass
    _on_main(_start)


def _install_ui():
    """UI notifications, the status indicator, the UI view sync, the opt-in autostart and the opt-in auto-setup."""
    try:
        import binaryninjaui as ui

        class _MCPUINotification(ui.UIContextNotification):
            # Signatures (Binary Ninja C++ API, UIContextNotification): OnViewChange(context, frame, type),
            # OnAfterOpenFile(context, file, frame), bool OnBeforeCloseFile(context, file, frame),
            # OnAfterCloseFile(context, file, frame), OnContextOpen(context). *args keeps older builds working.
            def OnViewChange(self, *args):
                try:
                    _ensure_status_indicator()
                    _sync_ui_views()
                    bv = _ui_active_view()
                    if bv:
                        _try_autostart_for_bv(bv)
                except Exception as e:
                    bn.log_error(f"MCP UI notification error: {e}")

            def OnAfterOpenFile(self, *args):  # type: ignore[override]
                self.OnViewChange()

            def OnBeforeCloseFile(self, *args):  # type: ignore[override]
                return True     # never veto a close; the views of the file are released in OnAfterCloseFile

            def OnAfterCloseFile(self, *args):  # type: ignore[override]
                try:
                    md, fn = _file_context_args(args)
                    if plugin.server and plugin.server.binary_ops:
                        plugin.server.binary_ops.release_file(md, fn)
                    _sync_ui_views()
                except Exception:
                    pass

            def OnContextOpen(self, *args):  # type: ignore[override]
                _ensure_status_indicator()

        ui.UIContext.registerNotification(_MCPUINotification())
        bn.log_info("MCP UI notifications installed")
        _start_indicator_watcher()
        _start_ui_sync_timer()
        _request_ui_sync()
    except Exception as e:
        bn.log_debug(f"MCP UI notifications not installed: {e}")
    if _autostart_enabled():
        def _kick():
            try:
                from PySide6.QtCore import QTimer
                QTimer.singleShot(1500, lambda: plugin.start_server(None))
            except Exception:
                plugin.start_server(None)
        _on_main(_kick)
    if _auto_setup_enabled():
        try:
            from .utils.auto_setup import install_mcp_clients
            # Offload: this path can spawn venv/pip children (no window) and must never block the plugin-load thread.
            threading.Thread(target=lambda: install_mcp_clients(quiet=True), name="bnmcp-auto-setup",
                             daemon=True).start()
        except Exception:
            pass


def _register_menu():
    """The two menu commands. register_global (no binary needed) where the API has it; else register (the item is
    enabled only while a binary is open)."""
    reg_global = getattr(bn.PluginCommand, "register_global", None)
    if callable(reg_global):
        reg_global("MCP Server\\Start MCP Server", "Start the binja-agent-mcp server",
                   lambda: plugin.start_server(None))
        reg_global("MCP Server\\Stop MCP Server", "Stop the binja-agent-mcp server",
                   lambda: plugin.stop_server(None))
        return "global"
    bn.PluginCommand.register("MCP Server\\Start MCP Server", "Start the binja-agent-mcp server",
                              plugin.start_server)
    bn.PluginCommand.register("MCP Server\\Stop MCP Server", "Stop the binja-agent-mcp server",
                              plugin.stop_server)
    return "view"


MENU_KIND = _register_menu()
_install_ui()
bn.log_info("binja-agent-mcp plugin loaded (autostart %s, auto-setup %s)"
            % ("on" if _autostart_enabled() else "off", "on" if _auto_setup_enabled() else "off"))
