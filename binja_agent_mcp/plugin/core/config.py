# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp, upstream commit
# d8a2709df69ff475d6be6366c2eec733663b008b, 2025-12-16).
# Copyright (C) 2025 fosdickio, CX330Blake
# Copyright (C) 2026 Kazuma Matsumoto
# Modified by Kazuma Matsumoto between 2026-10-14 and 2026-11-18; see NOTICE.md and CHANGES-FROM-UPSTREAM.md.
# SPDX-License-Identifier: GPL-3.0-or-later
# This program comes with ABSOLUTELY NO WARRANTY; see the LICENSE file for details.
import os
from dataclasses import dataclass
from typing import Optional

# Identity. MCP_CONTRACT must stay byte-identical to the constant CONTRACT in
# bn_mcp_client.py and to the bridge's BRIDGE_CONTRACT. It is advertised in
# /status server.contract only when the expert verbs and the per-request
# context imported successfully.
SERVER_VERSION = '1.0.0'
MCP_CONTRACT = 'binja-agent-mcp/1'

LOCK_MODES = ('global', 'per-view')


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 9009
    # Threaded HTTP server (one thread per request). BN work is still serialized
    # by the view locks below.
    threaded: bool = True
    # 'global' (DEFAULT): one re-entrant lock serializes all Binary Ninja work.
    # 'per-view': one re-entrant lock per BinaryView plus the in-flight semaphore;
    # experimental: Binary Ninja documents no thread-safety guarantee for
    # concurrent API use, and this mode is tested only against the offline fake.
    lock_mode: str = 'global'
    lock_wait_s: float = 20.0                  # requests naming `binary`: bounded wait, then 503 BUSY
    legacy_lock_wait_s: Optional[float] = None  # requests without `binary`: unbounded (upstream queueing)
    max_inflight: int = 8                      # per-view mode only
    inflight_wait_s: float = 20.0
    request_queue_size: int = 64
    legacy_text_cap_chars: int = 0             # 0 = unlimited (upstream behaviour)
    legacy_list_cap: int = 200000              # /allStrings and /strings/filter item cap
    scan_time_budget_s: float = 120.0          # budget for Python-heavy expert scans
    exclusive_bind: bool = False               # Windows: SO_EXCLUSIVEADDRUSE when True
    # Windows: SO_REUSEADDR when True (loses double-bind protection). Other systems always set SO_REUSEADDR,
    # which there keeps the protection (http_server._BindPolicyMixin).
    reuse_addr: bool = False
    # Request authentication (core/local_auth.py): every request must carry the per-run token
    # written to token_file ('' = the default per-user path) unless require_token is False. With
    # require_token False, a request without the token may still only READ (see http_server
    # _changes_state): every request that changes the analysis, the selection or the open binaries
    # needs the token.
    require_token: bool = True
    token_file: str = ""
    # A connection may stay idle (request line, headers, body) this long before the server closes it,
    # and at most max_connections connections are served at once (later ones are closed at once), so
    # local processes that open connections and send nothing cannot pile up threads inside Binary Ninja.
    request_timeout_s: float = 15.0
    max_connections: int = 256


@dataclass
class BinaryNinjaConfig:
    # patch_bytes(save_to_file=True) writes the patched image back over the
    # original file. Refused unless BN_MCP_ALLOW_SAVE=1 (safety: the analyzed
    # file is never modified by accident).
    allow_save_to_file: bool = False
    # Loads (bn_load_binary, /load) refuse UNC paths and network drives unless BN_MCP_ALLOW_NETWORK_PATHS=1:
    # opening one sends the user's Windows credentials to that server (binary_operations.check_load_path).
    allow_network_paths: bool = False
    # At most this many binaries loaded by the server are open at once (BN_MCP_MAX_OWNED); a further load
    # is refused with POLICY and the list of binaries to close.
    max_owned_views: int = 8


def _warn(msg):
    try:
        import binaryninja as _bn
        _bn.log_warn(msg)
    except Exception:
        pass


def _env_float(name, lo, hi):
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return None
    try:
        v = float(raw.strip())
    except ValueError:
        _warn("MCP config: ignoring %s=%r (not a number in %s..%s)" % (name, raw, lo, hi))
        return None
    if v != v or v < lo or v > hi:
        _warn("MCP config: ignoring %s=%r (outside %s..%s)" % (name, raw, lo, hi))
        return None
    return v


def _env_int(name, lo, hi):
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return None
    try:
        v = int(raw.strip(), 10)
    except ValueError:
        _warn("MCP config: ignoring %s=%r (not an integer in %d..%d)" % (name, raw, lo, hi))
        return None
    if v < lo or v > hi:
        _warn("MCP config: ignoring %s=%r (outside %d..%d)" % (name, raw, lo, hi))
        return None
    return v


def _env_flag(name, allowed_true=("1",), allowed_false=("0",)):
    """'1' -> True, '0' -> False, unset/empty -> None, anything else ignored with a warning."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return None
    v = raw.strip()
    if v in allowed_true:
        return True
    if v in allowed_false:
        return False
    _warn("MCP config: ignoring %s=%r (use 1 or 0)" % (name, raw))
    return None


def apply_env_overrides(cfg):
    """Apply validated BN_MCP_* environment overrides to a Config in place.

    An invalid value is ignored (with a Binary Ninja log warning) and the
    default stays. BN_MCP_URL, BN_MCP_TOOLSET, BN_MCP_TOOLS and
    BN_MCP_MAX_OUTPUT_CHARS are read by the bridge (or the client), not here.
    """
    s = cfg.server
    raw = os.environ.get("BN_MCP_LOCK_MODE")
    if raw is not None and raw.strip() != "":
        v = raw.strip().lower()
        if v in LOCK_MODES:
            s.lock_mode = v
        else:
            _warn("MCP config: ignoring BN_MCP_LOCK_MODE=%r (use global or per-view)" % raw)
    v = _env_float("BN_MCP_LOCK_WAIT_S", 1, 300)
    if v is not None:
        s.lock_wait_s = v
    v = _env_flag("BN_MCP_THREADED")
    if v is not None:
        s.threaded = v
    v = _env_int("BN_MCP_MAX_INFLIGHT", 1, 64)
    if v is not None:
        s.max_inflight = v
    v = _env_flag("BN_MCP_ALLOW_SAVE")
    if v is not None:
        cfg.binary_ninja.allow_save_to_file = v
    v = _env_flag("BN_MCP_ALLOW_NETWORK_PATHS")
    if v is not None:
        cfg.binary_ninja.allow_network_paths = v
    v = _env_int("BN_MCP_MAX_OWNED", 1, 64)
    if v is not None:
        cfg.binary_ninja.max_owned_views = v
    v = _env_flag("BN_MCP_EXCLUSIVE_BIND")
    if v is not None:
        s.exclusive_bind = v
    v = _env_flag("BN_MCP_REUSEADDR")
    if v is not None:
        s.reuse_addr = v
    v = _env_flag("BN_MCP_REQUIRE_TOKEN")
    if v is not None:
        s.require_token = v
    raw = os.environ.get("BN_MCP_TOKEN_FILE")
    if raw is not None and raw.strip() != "":
        s.token_file = os.path.abspath(os.path.expanduser(raw.strip()))
    return cfg


_ACTIVE = None


class Config:
    def __init__(self):
        global _ACTIVE
        self.server = ServerConfig()
        self.binary_ninja = BinaryNinjaConfig()
        apply_env_overrides(self)
        _ACTIVE = self


def active_config():
    """The most recently constructed Config (env overrides applied), else a fresh one."""
    return _ACTIVE if _ACTIVE is not None else Config()
