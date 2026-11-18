# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""Who may talk to the plugin's HTTP server (127.0.0.1 only).

Three checks run on every request before any Binary Ninja work (MCPRequestHandler._reject_untrusted):

1. Host allowlist. The Host header must be 127.0.0.1:<port> or localhost:<port>, the port being the server's own.
   A DNS-rebinding page reaches 127.0.0.1 under its own host name, so its requests fail this check.
2. No browser requests. A request that carries an Origin or Referer header, or a Sec-Fetch-Site header other than
   "none" (a URL typed by the user), comes from a web page and is refused. The server never sends CORS headers, so a
   browser also refuses to send a cross-origin request with a custom header (the preflight fails).
3. Per-run token. When the server starts, it writes a random token (32 random bytes, URL-safe base64) to the token
   file and accepts only requests whose X-BN-MCP-Token header equals it (constant-time comparison). The bridge and
   bn_mcp_client.py read the same file. BN_MCP_REQUIRE_TOKEN=0 turns this check off; checks 1 and 2 stay.

The token file is deleted when the server stops. It is written only after the port is bound, so a second Binary
Ninja that fails to bind never replaces the token of the first. The token protects against other local users and
against browsers; it does not protect against software that runs as the same OS user (that software can read the
file, or attach to Binary Ninja directly).

Standard library only. The path rule must stay equal to token_file_path() in bridge/binja_mcp_bridge.py and in
bn_mcp_client.py (a test compares the three).
"""

import hmac
import os
import re
import secrets
import sys
import tempfile

TOKEN_HEADER = "X-BN-MCP-Token"
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,200}$")


def token_file_path() -> str:
    """BN_MCP_TOKEN_FILE, else the per-user default location of the token file."""
    explicit = (os.environ.get("BN_MCP_TOKEN_FILE") or "").strip()
    if explicit:
        return os.path.abspath(os.path.expanduser(explicit))
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
    elif sys.platform == "darwin":
        base = os.path.join(home, "Library", "Application Support")
    else:
        base = os.environ.get("XDG_STATE_HOME") or os.path.join(home, ".local", "state")
    return os.path.join(base, "binja-agent-mcp", "token")


def new_token() -> str:
    return secrets.token_urlsafe(32)


def write_token(path: str, token: str) -> None:
    """Write `token` to `path` atomically, readable by the current user only (mode 0600 on POSIX; on Windows the
    default per-user location inherits the user profile's access list). The temporary file gets a random name and
    is created exclusively (tempfile.mkstemp: O_EXCL, and O_NOFOLLOW where the system has it), so a file or link
    that another account planted in the folder is never opened or followed."""
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".", suffix=".tmp", dir=d or os.curdir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(token + "\n")
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def read_token(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            t = f.read().strip()
    except (OSError, UnicodeDecodeError):
        return ""
    return t if _TOKEN_RE.match(t) else ""


def remove_token(path: str, token: str) -> None:
    """Delete the token file, but only while it still holds `token` (never another server's token)."""
    if path and token and read_token(path) == token:
        try:
            os.remove(path)
        except OSError:
            pass


def token_matches(expected: str, presented) -> bool:
    if not expected or not isinstance(presented, str):
        return False
    return hmac.compare_digest(expected.encode("utf-8"), presented.strip().encode("utf-8"))


def allowed_hosts(port: int) -> frozenset:
    return frozenset(("127.0.0.1:%d" % port, "localhost:%d" % port))


def host_ok(host_header, port: int) -> bool:
    if not isinstance(host_header, str):
        return False
    return host_header.strip().lower() in allowed_hosts(int(port))


def browser_reason(headers):
    """Why a request looks like it comes from a web browser page, or None. `headers` is a case-insensitive mapping
    (http.client.HTTPMessage)."""
    if headers.get("Origin") is not None:
        return "an Origin header is present"
    if headers.get("Referer") is not None:
        return "a Referer header is present"
    site = headers.get("Sec-Fetch-Site")
    if site is not None and site.strip().lower() != "none":
        return "Sec-Fetch-Site is %r" % site.strip()[:40]
    return None
