# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp, upstream commit
# d8a2709df69ff475d6be6366c2eec733663b008b, 2025-12-16).
# Copyright (C) 2025 fosdickio, CX330Blake
# Copyright (C) 2026 Kazuma Matsumoto
# Modified by Kazuma Matsumoto between 2026-10-14 and 2026-11-18; see NOTICE.md and CHANGES-FROM-UPSTREAM.md.
# SPDX-License-Identifier: GPL-3.0-or-later
# This program comes with ABSOLUTELY NO WARRANTY; see the LICENSE file for details.
"""The opt-in auto-setup (BN_MCP_AUTO_SETUP=1): when the plugin loads, add this server's entry to the supported MCP
clients, as scripts/mcp_client_installer.py --install does (plugin/utils/mcp_clients.py). It runs on a background
thread, never asks anything and writes its result to the Binary Ninja log; no configuration file is written unless
the bridge's interpreter can import mcp, requests and anyio. A marker file keeps it from running again on every
start while some client still has the entry."""
import os

from . import mcp_clients as mc


def _sentinel_path() -> str:
    return os.path.join(mc.plugin_root(), ".mcp_auto_setup_done")


def _log(level, msg):
    try:
        import binaryninja as bn
        getattr(bn, "log_" + level)(msg)
    except Exception:
        pass


def _already_installed(targets) -> bool:
    for c in targets:
        if not c.writes_file:
            continue
        cfg, _why = mc.read_config(c.config_path)
        if isinstance(cfg, dict) and mc.SERVER_KEY in (cfg.get("mcpServers") or {}):
            return True
    return False


def install_mcp_clients(quiet: bool = True) -> int:
    """Install the server entry for the supported clients (called only when BN_MCP_AUTO_SETUP=1).

    Returns the number of configuration files written."""
    targets = mc.clients()
    if not targets:
        return 0
    if os.path.exists(_sentinel_path()) and _already_installed(targets):
        return 0
    try:
        command = mc.ensure_bridge_python(create=True, stream=False,
                                          log=lambda m: _log("info", "MCP auto-setup: " + m))
    except RuntimeError as e:
        _log("error", "MCP auto-setup: no configuration file was changed: %s" % e)
        return 0
    results = mc.install(targets, command, mc.bridge_path())
    written = 0
    for name, path, what in results:
        if what.startswith("installed"):
            written += 1
            _log("info", "MCP auto-setup: %s: %s (%s)" % (name, what, path))
        elif what.startswith("run:"):
            _log("info", "MCP auto-setup: for %s, %s" % (name, what))
        elif not quiet or what.startswith("failed"):
            _log("warn", "MCP auto-setup: %s: %s (%s)" % (name, what, path))
    if written:
        try:
            with open(_sentinel_path(), "w", encoding="utf-8") as f:
                f.write("ok")
        except OSError:
            pass
    return written
