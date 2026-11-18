# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""MCP client configuration of binja-agent-mcp, shared by scripts/mcp_client_installer.py and the opt-in auto-setup
(plugin/utils/auto_setup.py, BN_MCP_AUTO_SETUP=1). Standard library only.

* clients(): the supported MCP clients, their configuration files and the extra keys of their server entry. A tool
  timeout is written only where the client documents the key, in its documented unit: Cline and Roo Code read
  "timeout" in seconds (Roo Code accepts 1 to 3600), so they get 60. Claude Desktop, Cursor, Windsurf and LM Studio
  get no timeout key. Claude Code's own command (claude mcp add) is printed instead of editing ~/.claude.json,
  a file Claude Code itself rewrites while it runs.
* install(): read, change and atomically replace each configuration file whose folder exists.
* bridge_python(): the interpreter of <plugin>/.venv; ensure_bridge_python() creates it when asked, installs
  bridge/requirements.txt (pip output is shown, return codes are checked) and refuses to continue unless the
  interpreter can import mcp, requests and anyio.
"""

import json
import os
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

from .python_detection import REQUIRED_MODULES, create_venv_with_system_python, venv_python_path

SERVER_KEY = "binja_agent_mcp"
# Seconds. The bridge ends every tool call within 55 s (bridge/binja_mcp_bridge.py, MCP_CALL_CAP_S = 60).
TOOL_TIMEOUT_S = 60
CLAUDE_CODE = "Claude Code"

# Every child process is started without a console window.
_NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


@dataclass(frozen=True)
class Client:
    name: str
    config_dir: str
    filename: str
    extra: dict = field(default_factory=dict)    # extra keys of the server entry
    writes_file: bool = True                     # False: the installer prints the client's own command instead

    @property
    def config_path(self):
        return os.path.join(self.config_dir, self.filename)


def plugin_root() -> str:
    """The plugin folder (the one that holds plugin/, bridge/ and plugin.json)."""
    return os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def bridge_path(root=None) -> str:
    return os.path.join(root or plugin_root(), "bridge", "binja_mcp_bridge.py")


def requirements_path(root=None) -> str:
    return os.path.join(root or plugin_root(), "bridge", "requirements.txt")


def bridge_python(root=None) -> str:
    """The interpreter of <plugin>/.venv (it may not exist yet)."""
    return venv_python_path(os.path.join(root or plugin_root(), ".venv"))


def clients(home=None, appdata=None, platform=None) -> list:
    """The supported clients on `platform` (default sys.platform), with paths under `home` / `appdata` (defaults:
    the user's home folder and %APPDATA%)."""
    platform = platform or sys.platform
    home = home or os.path.expanduser("~")
    seconds = {"timeout": TOOL_TIMEOUT_S, "disabled": False}
    if platform == "win32":
        appdata = appdata or os.getenv("APPDATA") or os.path.join(home, "AppData", "Roaming")
        code_user = os.path.join(appdata, "Code", "User")
        claude_desktop = os.path.join(appdata, "Claude")
    elif platform == "darwin":
        code_user = os.path.join(home, "Library", "Application Support", "Code", "User")
        claude_desktop = os.path.join(home, "Library", "Application Support", "Claude")
    elif platform.startswith("linux"):
        code_user = os.path.join(home, ".config", "Code", "User")
        claude_desktop = None                     # Claude Desktop has no Linux release
    else:
        return []
    out = [
        Client("Cline", os.path.join(code_user, "globalStorage", "saoudrizwan.claude-dev", "settings"),
               "cline_mcp_settings.json", dict(seconds)),
        Client("Roo Code", os.path.join(code_user, "globalStorage", "rooveterinaryinc.roo-cline", "settings"),
               "mcp_settings.json", dict(seconds)),
    ]
    if claude_desktop:
        out.append(Client("Claude Desktop", claude_desktop, "claude_desktop_config.json"))
    out += [
        Client("Cursor", os.path.join(home, ".cursor"), "mcp.json"),
        Client("Windsurf", os.path.join(home, ".codeium", "windsurf"), "mcp_config.json"),
        Client("LM Studio", os.path.join(home, ".lmstudio"), "mcp.json"),
        Client(CLAUDE_CODE, home, ".claude.json", writes_file=False),
    ]
    return out


def server_entry(client, command, bridge, env=None) -> dict:
    """The mcpServers entry of this server for `client`."""
    entry = {"command": command, "args": [bridge]}
    if env:
        entry["env"] = dict(env)
    entry.update(client.extra)
    return entry


def generic_entry(command, bridge, env=None) -> dict:
    """An entry for any client that reads an mcpServers object (no client-specific keys)."""
    return server_entry(Client("generic", "", ""), command, bridge, env)


def claude_code_command(command, bridge, env=None, platform=None) -> str:
    """The `claude mcp add` command that adds this server to Claude Code (user scope), quoted for the platform's
    shell (cmd.exe and PowerShell on Windows, a POSIX shell elsewhere). The --env pairs come first, before
    --scope: --env takes one or more values, so a server name right after the pairs would be read as one more
    KEY=value pair."""
    parts = ["claude", "mcp", "add"]
    for k, v in sorted((env or {}).items()):
        parts += ["--env", "%s=%s" % (k, v)]
    parts += ["--scope", "user", "--transport", "stdio", SERVER_KEY, "--", command, bridge]
    if (platform or sys.platform) == "win32":
        return subprocess.list2cmdline(parts)
    return " ".join(shlex.quote(p) for p in parts)


def read_config(path):
    """-> (dict, None) or (None, reason). A missing or empty file is an empty configuration."""
    if not os.path.exists(path):
        return {}, None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = f.read().strip()
    except (OSError, UnicodeDecodeError) as e:
        return None, "unreadable (%s)" % e
    if not data:
        return {}, None
    try:
        cfg = json.loads(data)
    except ValueError:
        return None, "invalid JSON"
    if not isinstance(cfg, dict):
        return None, "not a JSON object"
    servers = cfg.get("mcpServers")
    if servers is not None and not isinstance(servers, dict):
        return None, "its mcpServers value is not an object"
    return cfg, None


def write_config_atomic(path, cfg) -> None:
    """Replace `path` with `cfg` (JSON) atomically: a failed write never leaves the client's file truncated."""
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".binja-agent-mcp-", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def install(targets, command, bridge, env=None, uninstall=False):
    """Add (or remove) this server's entry in each target's configuration file. Only files whose folder exists are
    touched; Claude Code gets its command printed instead. -> [(client name, config path, result text)]."""
    results = []
    for c in targets:
        path = c.config_path
        if not c.writes_file:
            if uninstall:
                results.append((c.name, path, "run: claude mcp remove --scope user %s" % SERVER_KEY))
            else:
                results.append((c.name, path, "run: " + claude_code_command(command, bridge, env)))
            continue
        if not os.path.isdir(c.config_dir):
            results.append((c.name, path, "skipped (the client's configuration folder does not exist)"))
            continue
        cfg, why = read_config(path)
        if cfg is None:
            results.append((c.name, path, "skipped (the file is %s; it was not changed)" % why))
            continue
        servers = cfg.setdefault("mcpServers", {})
        if uninstall:
            if SERVER_KEY not in servers:
                results.append((c.name, path, "skipped (no %s entry)" % SERVER_KEY))
                continue
            del servers[SERVER_KEY]
        else:
            merged = {}
            old = servers.get(SERVER_KEY)
            if isinstance(old, dict) and isinstance(old.get("env"), dict):
                merged.update(old["env"])         # keep the user's own variables (BN_MCP_TOOLSET, ...)
            merged.update(env or {})
            servers[SERVER_KEY] = server_entry(c, command, bridge, merged)
        try:
            write_config_atomic(path, cfg)
        except OSError as e:
            results.append((c.name, path, "failed (%s)" % e))
            continue
        results.append((c.name, path, "removed" if uninstall else "installed (restart the client)"))
    return results


def modules_importable(python, timeout=120):
    """-> (True, '') when `python` can import REQUIRED_MODULES, else (False, reason)."""
    code = "import " + ", ".join(REQUIRED_MODULES)
    try:
        # not -I: the check runs the interpreter the way an MCP client runs the bridge
        r = subprocess.run([python, "-c", code], capture_output=True, text=True, timeout=timeout,
                           creationflags=_NO_WINDOW)
    except (OSError, subprocess.SubprocessError) as e:
        return False, "%s could not be run (%s)" % (python, e)
    if r.returncode != 0:
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-1:] or [""]
        return False, "%s cannot import %s (%s)" % (python, ", ".join(REQUIRED_MODULES), tail[0][:300])
    return True, ""


def ensure_bridge_python(root=None, create=True, stream=True, log=print):
    """The bridge interpreter, ready to run the bridge, or RuntimeError with the reason.

    <plugin>/.venv is created when it is missing (create=True; else RuntimeError), bridge/requirements.txt is
    installed when the interpreter cannot import mcp, requests and anyio (pip downloads from PyPI; with stream=True
    its output goes to this console, else its last lines are in the error), and the import check runs again."""
    root = root or plugin_root()
    py = bridge_python(root)
    if not os.path.isfile(py) and not create:
        raise RuntimeError("%s does not exist; create it as described in README.md (Install, step 3)" % py)
    py = create_venv_with_system_python(os.path.join(root, ".venv"), requirements_path(root), stream=stream,
                                        log=log)
    ok, why = modules_importable(py)
    if not ok:
        raise RuntimeError("the bridge's Python environment is not usable: " + why)
    return py
