# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp, upstream commit
# d8a2709df69ff475d6be6366c2eec733663b008b, 2025-12-16).
# Copyright (C) 2025 fosdickio, CX330Blake
# Copyright (C) 2026 Kazuma Matsumoto
# Modified by Kazuma Matsumoto between 2026-10-14 and 2026-11-18; see NOTICE.md and CHANGES-FROM-UPSTREAM.md.
# SPDX-License-Identifier: GPL-3.0-or-later
# This program comes with ABSOLUTELY NO WARRANTY; see the LICENSE file for details.
"""Add or remove the binja-agent-mcp server entry in the configuration files of supported MCP clients.

  --install     add the entry to each supported client whose configuration folder exists; for Claude Code, print
                its own `claude mcp add` command instead of editing ~/.claude.json
  --uninstall   remove the entry again (for Claude Code: print `claude mcp remove`)
  --config      print an entry for other clients (read-only: creates nothing, installs nothing)
  --list        print the supported clients and their configuration files (read-only)
  --python P    run the bridge with interpreter P (it must import mcp, requests and anyio) instead of
                <plugin>/.venv; then no virtual environment is created
  --copy-python-env  also write the PYTHONHOME / PYTHONPATH / ... variables of this shell into the entries

Without --python, --install uses <plugin>/.venv and creates it when it is missing: pip then downloads the packages of
bridge/requirements.txt from PyPI and shows its output. No configuration file is written unless the interpreter can
import mcp, requests and anyio. Without a flag the script prints its usage and changes nothing.
"""
import argparse
import json
import os
import sys

# Import shared utilities
try:
    # Try relative import first (when run as module)
    from ..plugin.utils import mcp_clients as mc
    from ..plugin.utils.python_detection import copy_python_env
except ImportError:
    # Fallback for direct script execution
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "plugin"))
    from utils import mcp_clients as mc
    from utils.python_detection import copy_python_env


def _root() -> str:
    """The plugin folder (one level above this scripts directory)."""
    return os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def _env(copy_env: bool) -> dict:
    env = {}
    if copy_env:
        copy_python_env(env)
    return env


def print_config(python=None, copy_env=False) -> int:
    """Print a generic mcpServers entry (read-only)."""
    root = _root()
    command = python or mc.bridge_python(root)
    if not python and not os.path.isfile(command):
        print("Note: %s does not exist yet; create it as described in README.md (Install, step 3)." % command,
              file=sys.stderr)
    entry = mc.generic_entry(command, mc.bridge_path(root), _env(copy_env))
    print(json.dumps({"mcpServers": {mc.SERVER_KEY: entry}}, indent=2))
    return 0


def list_clients() -> int:
    for c in mc.clients():
        state = "folder exists" if os.path.isdir(c.config_dir) else "folder missing"
        how = "" if c.writes_file else " (the installer prints a command instead of editing this file)"
        print("%-15s %s  [%s]%s" % (c.name, c.config_path, state, how))
    return 0


def run(uninstall=False, python=None, copy_env=False, quiet=False) -> int:
    """Install or uninstall; -> process exit code (0: done, 1: the bridge interpreter is not usable)."""
    root = _root()
    targets = mc.clients()
    if not targets:
        print("Unsupported platform: %s" % sys.platform)
        return 1
    command = python or mc.bridge_python(root)
    if not uninstall:
        try:
            if python:
                ok, why = mc.modules_importable(python)
                if not ok:
                    raise RuntimeError(why)
            else:
                command = mc.ensure_bridge_python(root, create=True, stream=not quiet,
                                                  log=(lambda m: None) if quiet else print)
        except RuntimeError as e:
            print("Not installed: %s" % e)
            print("No configuration file was changed.")
            return 1
    results = mc.install(targets, command, mc.bridge_path(root), _env(copy_env), uninstall=uninstall)
    for name, path, what in results:
        if quiet and what.startswith("skipped"):
            continue
        print("%-15s %s\n  %s" % (name, what, path))
    if uninstall:
        sentinel = os.path.join(root, ".mcp_auto_setup_done")
        try:
            os.remove(sentinel)
            if not quiet:
                print("Removed the auto-setup marker: %s" % sentinel)
        except FileNotFoundError:
            pass
        except OSError as e:
            print("Warning: could not remove the auto-setup marker %s: %s" % (sentinel, e))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="binja-agent-mcp: add or remove the MCP server entry in the "
                                                 "configuration files of supported MCP clients")
    parser.add_argument("--install", action="store_true", help="add the entry to the supported clients")
    parser.add_argument("--uninstall", action="store_true", help="remove the entry from the supported clients")
    parser.add_argument("--config", action="store_true", help="print an entry for other clients (read-only)")
    parser.add_argument("--list", action="store_true", help="print the supported clients and their files")
    parser.add_argument("--python", default=None, help="the interpreter that runs the bridge (default: "
                                                       "<plugin>/.venv, created when missing)")
    parser.add_argument("--copy-python-env", action="store_true",
                        help="write this shell's PYTHONHOME / PYTHONPATH / ... into the entries")
    parser.add_argument("--quiet", action="store_true", help="print less")
    args = parser.parse_args(argv)
    python = os.path.abspath(args.python) if args.python else None
    if sum(bool(x) for x in (args.install, args.uninstall, args.config, args.list)) > 1:
        print("Use one of --install, --uninstall, --config, --list")
        return 2
    if args.config:
        return print_config(python, args.copy_python_env)
    if args.list:
        return list_clients()
    if args.install or args.uninstall:
        return run(uninstall=args.uninstall, python=python, copy_env=args.copy_python_env, quiet=args.quiet)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
