# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp, upstream commit
# d8a2709df69ff475d6be6366c2eec733663b008b, 2025-12-16).
# Copyright (C) 2025 fosdickio, CX330Blake
# Copyright (C) 2026 Kazuma Matsumoto
# Modified by Kazuma Matsumoto between 2026-10-14 and 2026-11-18; see NOTICE.md and CHANGES-FROM-UPSTREAM.md.
# SPDX-License-Identifier: GPL-3.0-or-later
# This program comes with ABSOLUTELY NO WARRANTY; see the LICENSE file for details.
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import socket
import sys
import re
import importlib
import time
import traceback
import urllib.parse
from typing import Dict, Any
import binaryninja as bn
import threading
from ..core.binary_operations import BinaryOperations
from ..core.config import Config, ServerConfig, SERVER_VERSION, MCP_CONTRACT
from ..core import local_auth
from ..core import request_context as rc
from ..api.endpoints import BinaryNinjaEndpoints
from ..utils.string_utils import parse_int_or_default
from ..utils.number_utils import convert_number as util_convert_number


# --- per-request binary scope + locking ----------------------------------------------------
# Paths that are never scoped by `binary` and take no view lock or in-flight slot (for /selectBinary, `binary` stays
# the selection TARGET). They read only the registry (file names), the platform list or the core version, or no
# Binary Ninja state at all. /status without `binary` is likewise unscoped, so health checks never queue behind
# Binary Ninja work. The two load paths are the exception: they run bn.load, so in lock_mode 'global' they take the
# global lock (_GLOBAL_LOCKED_UNSCOPED).
SCOPE_EXEMPT = frozenset({
    '/binaries',
    '/views',
    '/selectBinary',
    '/platforms',
    '/convertNumber',
    '/load',
    '/x/compute',
    '/x/serverInfo',
    '/x/loadBinary',
})
# Unscoped paths that do Binary Ninja work (bn.load, the loaded-bytes hash of an owned view): in lock_mode 'global'
# they hold the one global lock like every scoped request. /x/loadBinary waits at most lock_wait_s (503 BUSY), the
# legacy /load as long as a legacy request does.
_GLOBAL_LOCKED_UNSCOPED = frozenset({'/load', '/x/loadBinary'})

# GET-implementation paths that answer without a loaded binary.
_GET_NO_VIEW_PREFIXES = (
    "/status",
    "/convertNumber",
    "/platforms",
    "/binaries",
    "/views",
    "/selectBinary",
    "/x/compute",
    "/x/serverInfo",
    "/x/loadBinary",
)

# Type-definition verbs also accept POST (long C declarations in the body); the body is
# merged into the query parameters and served by the GET implementation.
_TYPE_POST_ROUTES = ("/defineTypes", "/declareCType", "/setFunctionPrototype")

_BASE_CAPABILITIES = (
    "per_call_binary",
    "ambiguity_errors",
    "output_caps",
    "analysis_state",
    "save_policy",
    "post_type_routes",
    "local_auth_v1",
)

_NO_BODY = object()

_REFUSAL_LOG_INTERVAL_S = 60.0

# GET routes that change the analysis or the global selection. With BN_MCP_REQUIRE_TOKEN=0 a request without the token
# is still refused on these (and on every POST / DELETE except the read-only verbs below): a GET needs no browser
# preflight, so an <img> tag or any program that fetches a URL could otherwise rename, retype or patch.
_MUTATING_GET_PATHS = frozenset({
    "/selectBinary", "/setFunctionPrototype", "/makeFunctionAt", "/setLocalVariableType", "/retypeVariable",
    "/renameVariable", "/renameVariables", "/formatValue", "/defineTypes", "/declareCType", "/patch", "/patchBytes",
})
# POST forms that only read: every GET /x/ verb (long parameters may travel in a JSON body) and the batch verb, which
# refuses the mutating verbs.
_READ_ONLY_POST_PATHS = frozenset(set(BinaryNinjaEndpoints.ROUTES_GET) | {"/x/batch"})

# Routes whose parameters are C text for Binary Ninja's type parser. The parser preprocesses its input and reads every
# file an #include names: an include of a network path makes it connect to that host (on Windows with the user's
# credentials), an include of a local file reads that file. Text that names a file this way is refused (403 POLICY).
_C_TEXT_PATHS = frozenset({"/defineTypes", "/declareCType", "/setFunctionPrototype", "/setLocalVariableType",
                           "/retypeVariable"})
_RE_FILE_DIRECTIVE = re.compile(r"#[ \t]*(?:/\*.*?\*/[ \t]*)*(?:include_next|include|import|embed)\b", re.S)


def c_text_names_a_file(text) -> bool:
    """True when C text holds a preprocessing directive that reads a file (#include, #include_next, #import, #embed)
    or the __has_include operator. Line splices and the %: digraph are normalized first; comments and string or
    character literals are skipped, and a comment before the # still leaves it at the start of its line (as in C,
    where a comment becomes one space)."""
    s = re.sub(r"\\\r?\n", "", str(text or "")).replace("%:", "#")
    if "__has_include" in s:
        return True
    i, n, line_start = 0, len(s), True
    while i < n:
        c = s[i]
        if c == "\n":
            line_start, i = True, i + 1
        elif c in " \t\r\f\v":
            i += 1
        elif s.startswith("/*", i):
            j = s.find("*/", i + 2)
            if j < 0:
                return False
            i = j + 2
        elif s.startswith("//", i):
            j = s.find("\n", i)
            i = n if j < 0 else j
        elif c == "#":
            if line_start and _RE_FILE_DIRECTIVE.match(s, i):
                return True
            line_start, i = False, i + 1
        elif c in "\"'":
            i += 1
            while i < n and s[i] != c and s[i] != "\n":
                i += 2 if s[i] == "\\" else 1
            line_start, i = False, i + 1
        else:
            line_start, i = False, i + 1
    return False

_MODULES_LOCK = threading.Lock()
_MODULES = None


def _hexdump_rows(addr: int, data: bytes) -> list:
    """Hexdump rows of `data` at `addr`: 16 bytes per row, the first row padded to the 16-byte boundary, then the
    printable ASCII column. The format of upstream's /hexdump, /hexdumpByName and /getDataDecl (one copy here instead
    of three)."""
    def _printable(b: int) -> str:
        return chr(b) if 32 <= b <= 126 else "."

    lines = []
    addr_hex = format(addr, 'x')
    total = len(data)
    offset = 0
    first_pad = addr % 16
    if first_pad != 0 and total > 0:
        take = min(16 - first_pad, total)
        chunk = data[0:take]
        hex_area = ("   " * first_pad) + "".join(f"{b:02x} " for b in chunk)
        hex_area += "   " * (16 - first_pad - take)
        ascii_area = (" " * first_pad) + "".join(_printable(b) for b in chunk)
        ascii_area += " " * (16 - first_pad - take)
        lines.append(f"{addr_hex}  {hex_area} {ascii_area}")
        offset += take
    while offset < total:
        line_addr = addr + offset
        take = min(16, total - offset)
        chunk = data[offset:offset + take]
        hex_area = "".join(f"{b:02x} " for b in chunk) + ("   " * (16 - take))
        ascii_area = "".join(_printable(b) for b in chunk) + (" " * (16 - take))
        lines.append(f"{format(line_addr, 'x')}  {hex_area} {ascii_area}")
        offset += take
    return lines


def _plugin_package():
    parts = __name__.rsplit(".", 2)
    return parts[0] if len(parts) == 3 else None


def module_status():
    """Import status of the optional plugin modules, computed ONCE per process.

    Returns {'imported': {expert_ops, request_context: bool},
             'errors': {module: message <= 200 chars}}.
    """
    global _MODULES
    with _MODULES_LOCK:
        if _MODULES is not None:
            return _MODULES
        pkg = _plugin_package()
        imported, errors = {}, {}
        for short in ("expert_ops", "request_context"):
            if not pkg:
                imported[short] = False
                errors[short] = "cannot determine the plugin package name"
                continue
            try:
                importlib.import_module(pkg + ".core." + short)
                imported[short] = True
            except Exception as e:
                imported[short] = False
                errors[short] = ("%s: %s" % (type(e).__name__, e))[:200]
        _MODULES = {"imported": imported, "errors": errors}
        return _MODULES


def reset_module_status():
    """Forget the cached module_status() result (offline tests only; the server never calls it)."""
    global _MODULES
    with _MODULES_LOCK:
        _MODULES = None


def _acquire_lock(lock, timeout) -> bool:
    """lock.acquire with timeout=None meaning 'wait forever'."""
    if timeout is None:
        return bool(lock.acquire())
    try:
        t = float(timeout)
    except (TypeError, ValueError):
        t = 20.0
    if t < 0:
        return bool(lock.acquire())
    return bool(lock.acquire(timeout=t))


def _pos_float(v, default):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return default
    return f if f > 0 else default


def _nonneg_int(v, default):
    try:
        i = int(v)
    except (TypeError, ValueError):
        return default
    return i if i >= 0 else default


class _ServerState:
    """Lock mode, in-flight semaphore and wait budgets shared by all request threads."""

    def __init__(self, cfg=None, lock_mode=None):
        cfg = cfg if cfg is not None else ServerConfig()
        m = str(lock_mode or getattr(cfg, "lock_mode", "global") or "global").strip().lower()
        self.lock_mode = m if m in ("global", "per-view") else "global"
        self.threaded = bool(getattr(cfg, "threaded", True))
        try:
            mi = int(getattr(cfg, "max_inflight", 8))
        except (TypeError, ValueError):
            mi = 8
        self.max_inflight = min(64, max(1, mi))
        self.inflight = threading.BoundedSemaphore(self.max_inflight if self.threaded else 1)
        self.lock_wait_s = _pos_float(getattr(cfg, "lock_wait_s", 20.0), 20.0)
        lw = getattr(cfg, "legacy_lock_wait_s", None)
        self.legacy_lock_wait_s = None if lw is None else _pos_float(lw, None)
        self.inflight_wait_s = _pos_float(getattr(cfg, "inflight_wait_s", 20.0), 20.0)
        self.legacy_text_cap_chars = _nonneg_int(getattr(cfg, "legacy_text_cap_chars", 0), 0)
        self.legacy_list_cap = _nonneg_int(getattr(cfg, "legacy_list_cap", 200000), 200000)
        # Request authentication (core/local_auth.py). The token is set by MCPServer.start once the port is bound;
        # until then (and for a state without a server) every request is refused while require_token is on.
        self.require_token = bool(getattr(cfg, "require_token", True))
        self.token = ""
        self.token_file = ""
        # Refusal warnings in the Binary Ninja log: at most one per reason per _REFUSAL_LOG_INTERVAL_S, with the count
        # of the refusals that were not logged in between (a local process cannot flood the log).
        self.refusal_log = {}
        self.refusal_log_lock = threading.Lock()

    def note_refusal(self, reason, detail):
        """Log a refusal warning unless one for `reason` was logged less than _REFUSAL_LOG_INTERVAL_S ago."""
        now = time.monotonic()
        with self.refusal_log_lock:
            last, quiet = self.refusal_log.get(reason, (None, 0))
            if last is not None and now - last < _REFUSAL_LOG_INTERVAL_S:
                self.refusal_log[reason] = (last, quiet + 1)
                return
            self.refusal_log[reason] = (now, 0)
        extra = (" (%d more refused for the same reason since the last warning)" % quiet) if quiet else ""
        try:
            bn.log_warn("MCP server refused %s%s" % (detail, extra))
        except Exception:
            pass


_DEFAULT_STATE_LOCK = threading.Lock()
_DEFAULT_STATE = None


def _default_state(ops):
    global _DEFAULT_STATE
    with _DEFAULT_STATE_LOCK:
        if _DEFAULT_STATE is None:
            cfg = getattr(ops, "server_config", None)
            _DEFAULT_STATE = _ServerState(cfg, getattr(ops, "lock_mode", None))
        return _DEFAULT_STATE


class MCPRequestHandler(BaseHTTPRequestHandler):
    binary_ops = None  # Will be set by the server
    server_state = None  # _ServerState; set by the server

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _state(self):
        st = getattr(self, "server_state", None)
        return st if st is not None else _default_state(self.binary_ops)

    def _begin_request(self):
        """Reset per-request caches (a handler instance may serve several requests)."""
        self._post_cache = _NO_BODY
        self._param_override = None

    @property
    def endpoints(self):
        # Create endpoints on demand to ensure binary_ops is set
        if not hasattr(self, "_endpoints"):
            if not self.binary_ops:
                raise RuntimeError("binary_ops not initialized")
            self._endpoints = BinaryNinjaEndpoints(self.binary_ops)
        return self._endpoints

    def log_request(self, code="-", size="-"):
        """One debug line per request: the method, the path and the status. Never the query string or the body:
        they carry names, C types, comments and patch bytes."""
        try:
            path = urllib.parse.urlsplit(str(self.path)).path[:200]
        except Exception:
            path = "?"
        try:
            bn.log_debug("MCP request %s %s -> %s" % (self.command, path, code))
        except Exception:
            pass

    def log_message(self, format, *args):
        # http.server's other messages (log_error: a malformed request line, an idle connection that timed out) go
        # to the debug log with their text arguments omitted (they can quote the request line); log_request above
        # covers normal requests.
        safe = tuple(a if isinstance(a, int) and not isinstance(a, bool) else "<omitted>" for a in args)
        try:
            msg = format % safe
        except Exception:
            msg = str(format)
        try:
            bn.log_debug("MCP server: " + msg)
        except Exception:
            pass

    def _safe_header(self, keyword, value):
        """send_header that drops (only) a header whose value is not latin-1 encodable."""
        try:
            self.send_header(keyword, value)
        except UnicodeEncodeError:
            try:
                bn.log_warn(f"Dropped response header {keyword}: not latin-1 encodable")
            except Exception:
                pass

    @staticmethod
    def _x_bn_binary():
        info = rc.info()
        if not isinstance(info, dict):
            return None
        return "%s;%s;%s" % (
            info.get("view_id") or "",
            urllib.parse.quote(str(info.get("basename") or ""), safe=""),
            info.get("binary_id") or "",
        )

    def _set_headers(self, content_type="application/json", status_code=200):
        # No CORS header is ever sent (upstream sent Access-Control-Allow-Origin: *, which let any web page read
        # the answers): a browser therefore never exposes an answer to a page, and refuses to send a cross-origin
        # request with a custom header such as X-BN-MCP-Token (the preflight fails).
        try:
            self.send_response(status_code)
            self._safe_header("Content-Type", content_type)
            # Encourage clients to close promptly; reduces BrokenPipe on abrupt disconnects
            self._safe_header("Connection", "close")
            # Which binary answered (scoped requests): '<view_id>;<pct-encoded basename>;<binary_id>'
            xb = self._x_bn_binary()
            if xb:
                self._safe_header("X-BN-Binary", xb)
            self.end_headers()
        except (BrokenPipeError, OSError):
            try:
                import binaryninja as _bn
                _bn.log_warn("Client disconnected while sending headers")
            except Exception:
                pass

    def _decorate_json(self, data: Dict[str, Any], status_code: int):
        """binja-agent-mcp additions to every JSON object reply (never raises):

        * an ambiguity noted during the request + an error status -> 409 AMBIGUOUS
          with candidates; `error` becomes the self-describing AmbiguousError text;
        * `_binary` (the resolved-binary echo) for scoped requests, with a fresh
          analysis_state while the view is live. When _dispatch stamped a start sample
          (analysis_state_at_start, taken under the lock just before the work), the
          response-time sample is added as analysis_state_at_end and `analysis_state` is
          IdleState only if BOTH samples are IdleState (otherwise the non-IdleState one, the
          end sample first), so a result begun during analysis is never echoed as idle;
        * request warnings merged into `warnings`;
        * binary_defaulted / open_binaries when the global selection was used with
          more than one view open.
        """
        out = dict(data)
        try:
            code = int(status_code)
        except (TypeError, ValueError):
            code = 500
        amb = rc.ambiguity()
        if amb is not None and code >= 400:
            code = 409
            out["error"] = getattr(amb, "message", None) or str(amb)
            out["error_code"] = "AMBIGUOUS"
            extra = getattr(amb, "extra", None) or {}
            out["candidates"] = list(extra.get("candidates") or [])
        info = rc.info()
        ops = self.binary_ops
        if isinstance(info, dict) and "_binary" not in out:
            echo = dict(info)
            bv = rc.override_view()
            vid = echo.get("view_id")
            try:
                if bv is not None and bv is not rc.UNSET and ops is not None and vid and ops.is_live(vid):
                    s = ops.analysis_summary(bv)
                    if not isinstance(s, dict):
                        s = {"state": "unknown"}
                    end_state = s.get("state")
                    if "analysis_state_at_start" in echo:
                        echo["analysis_state_at_end"] = end_state
                    start_state = echo.get("analysis_state_at_start", "IdleState")
                    if end_state != "IdleState" or start_state == "IdleState":
                        echo["analysis_state"] = end_state
                        echo["analysis_state_code"] = s.get("state_code")
                    else:
                        # started during analysis, idle by now: keep the (stamped) start sample
                        echo["analysis_state"] = start_state
            except Exception:
                pass
            out["_binary"] = echo
        w = rc.warnings()
        if w:
            cur = out.get("warnings")
            if cur is None:
                lst = []
            elif isinstance(cur, list):
                lst = list(cur)
            else:
                lst = [cur]
            for x in w:
                if x not in lst:
                    lst.append(x)
            out["warnings"] = lst
        if rc.defaulted() and isinstance(info, dict):
            out["binary_defaulted"] = True
            try:
                out["open_binaries"] = ops.list_open_binaries() if ops is not None else []
            except Exception:
                pass
        return out, code

    def _send_json_response(self, data: Dict[str, Any], status_code: int = 200):
        if isinstance(data, dict):
            try:
                data, status_code = self._decorate_json(data, status_code)
            except Exception:
                pass
        try:
            self._set_headers(status_code=status_code)
            # If headers failed due to disconnect, avoid writing body
            try:
                body = json.dumps(data).encode("utf-8")
            except Exception:
                body = b"{}"
            try:
                self.wfile.write(body)
            except (BrokenPipeError, OSError):
                try:
                    import binaryninja as _bn
                    _bn.log_warn("Client disconnected while sending body")
                except Exception:
                    pass
        except Exception:
            # Last-resort swallow to avoid cascading errors on disconnects
            try:
                import binaryninja as _bn
                _bn.log_debug("Suppressed exception during response write")
            except Exception:
                pass

    def _parse_query_params(self) -> Dict[str, str]:
        parsed_path = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(parsed_path.query))
        # POST /defineTypes, /declareCType, /setFunctionPrototype are served by the GET
        # implementation with the body merged over the query (body wins).
        ov = getattr(self, "_param_override", None)
        if isinstance(ov, dict) and ov:
            merged = dict(q)
            merged.update(ov)
            return merged
        return q

    def _parse_post_params(self) -> Dict[str, Any]:
        """Parse POST request parameters from various formats (cached per request).

        Supports:
        - JSON data (application/json)
        - Form data (application/x-www-form-urlencoded)
        - Raw text (text/plain)
        - Any other Content-Type: JSON, then form, then {'name': body}

        Returns:
            Dictionary containing the parsed parameters (never None; a JSON body that
            is not an object is returned as {'_json': value})
        """
        cached = getattr(self, "_post_cache", _NO_BODY)
        if cached is not _NO_BODY:
            return cached
        try:
            res = self._read_post_params()
        except Exception as e:
            bn.log_error(f"Failed to read request body: {e}")
            res = {"error": f"Failed to read request body: {e}"}
        if res is None:
            res = {}
        if not isinstance(res, dict):
            res = {"_json": res}
        self._post_cache = res
        return res

    def _read_post_params(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            return {"error": "Invalid Content-Length"}
        if content_length < 0 or content_length > 16 * 1024 * 1024:   # reject malformed / oversized bodies
            return {"error": "Body too large"}
        if content_length == 0:
            return {}

        content_type = self.headers.get("Content-Type", "") or ""
        post_data = self.rfile.read(content_length).decode("utf-8", errors="replace")

        n_chars = len(post_data)
        bn.log_debug(f"POST body ({n_chars} characters, Content-Type {content_type!r})")

        # Handle JSON data
        if "application/json" in content_type.lower():
            try:
                return json.loads(post_data)
            except json.JSONDecodeError as e:
                bn.log_error(f"Failed to parse JSON: {e}")
                return {"error": "Invalid JSON format"}

        # Handle form data
        if "application/x-www-form-urlencoded" in content_type.lower():
            try:
                return dict(urllib.parse.parse_qsl(post_data))
            except Exception as e:
                bn.log_error(f"Failed to parse form data: {e}")
                return {"error": "Invalid form data format"}

        # Handle raw text
        if "text/plain" in content_type.lower() or not content_type:
            return {"name": post_data.strip()}

        # Any other Content-Type: try all formats as fallback
        try:
            return json.loads(post_data)
        except (json.JSONDecodeError, ValueError):
            try:
                parsed = dict(urllib.parse.parse_qsl(post_data))
                if parsed:
                    return parsed
            except (ValueError, TypeError):
                pass

            return {"name": post_data.strip()}

    # ---------- Helpers ----------
    def _resolve_name_to_address(self, ident: str):
        """Resolve a symbol name or hex address string to (address:int, label:str).

        Tries, in order:
        - Parse hex address (with or without 0x)
        - get_symbol_by_raw_name
        - get_symbol_by_name
        - scan data_vars for matching symbol name/raw_name
        """
        bv = getattr(self.binary_ops, "current_view", None)
        if not bv:
            return None, None
        s = (ident or "").strip()
        # Hex address
        try:
            if s.lower().startswith("0x"):
                return int(s, 16), s
            # bare hex
            if all(c in "0123456789abcdefABCDEF" for c in s):
                return int(s, 16), s
        except Exception:
            pass
        # Raw name
        try:
            get_raw = getattr(bv, "get_symbol_by_raw_name", None)
            sym = get_raw(s) if callable(get_raw) else None
            if sym and hasattr(sym, "address"):
                return int(sym.address), getattr(sym, "name", s)
        except Exception:
            pass
        # Pretty name
        try:
            get_by_name = getattr(bv, "get_symbol_by_name", None)
            sym = get_by_name(s) if callable(get_by_name) else None
            if sym and hasattr(sym, "address"):
                return int(sym.address), getattr(sym, "name", s)
        except Exception:
            pass
        # Heuristic: BN auto-generated data labels like data_100003f66, byte_..., word_..., dword_..., qword_..., off_..., unk_...
        try:
            # (an inline (?i) after '^' is a re.error on Python 3.11+; use the flag argument)
            m = re.match(r'(?:data|byte|word|dword|qword|off|unk)_(?:0x)?([0-9a-fA-F]+)$', s, re.IGNORECASE)
            if m:
                a = int(m.group(1), 16)
                return a, s
        except Exception:
            pass
        # Scan data vars
        try:
            for var in list(bv.data_vars):
                try:
                    sy = bv.get_symbol_at(var)
                    if not sy:
                        continue
                    if getattr(sy, "name", None) == s or getattr(sy, "raw_name", None) == s:
                        return int(var), getattr(sy, "name", s)
                except Exception:
                    continue
        except Exception:
            pass
        return None, None

    def _c_escape(self, raw: bytes, limit: int | None = None) -> str:
        """Escape bytes as a C string literal."""
        try:
            b = raw if limit is None else raw[:limit]
            out = []
            for ch in b:
                if ch == 0x22:  # '"'
                    out.append('\\"')
                elif ch == 0x5c:  # '\\'
                    out.append('\\\\')
                elif 32 <= ch <= 126:
                    out.append(chr(ch))
                elif ch == 0x0a:
                    out.append('\\n')
                elif ch == 0x0d:
                    out.append('\\r')
                elif ch == 0x09:
                    out.append('\\t')
                else:
                    out.append(f"\\x{ch:02x}")
            return '"' + ''.join(out) + '"'
        except Exception:
            return '""'

    def _check_binary_loaded(self):
        """Check if a binary is loaded and return appropriate error response if not"""
        if not self.binary_ops or not self.binary_ops.current_view:
            self._send_json_response({"error": "No binary loaded"}, 400)
            return False
        return True

    # ---------------- server info, output caps, routing, dispatch ----------------
    def _server_block(self) -> Dict[str, Any]:
        """The /status `server` object (always present)."""
        st = self._state()
        mods = module_status()
        imported = mods.get("imported", {})
        caps = list(_BASE_CAPABILITIES)
        if imported.get("expert_ops"):
            caps.append("expert_v1")
        if st.threaded and st.lock_mode == "per-view":
            caps.append("threaded_per_view")
        try:
            core = bn.core_version()
        except Exception:
            core = None
        contract = MCP_CONTRACT if (imported.get("expert_ops") and imported.get("request_context")) else ""
        out = {
            "version": SERVER_VERSION,
            "contract": contract,
            "lock_mode": st.lock_mode,
            "threaded": st.threaded,
            "max_inflight": st.max_inflight,
            "bn_core_version": core,
            "capabilities": caps,
            "import_errors": dict(mods.get("errors", {})),
            "pid": os.getpid(),
            "auth": {"host_check": True, "browser_check": True, "require_token": bool(st.require_token)},
        }
        return out

    @staticmethod
    def _cap_lines(text, line_offset=0, max_lines=0, max_chars=0):
        """Cut a text reply on a LINE boundary -> (text, meta).

        meta = {total_lines, line_offset, returned_lines, truncated (always present),
        next_line_offset (None when nothing follows)}. With no offset and no caps the
        text is returned unchanged (byte-identical to upstream). If a single line is
        longer than max_chars it is cut (meta line_cut=True) so paging always advances.
        """
        s = "" if text is None else str(text)
        lines = s.split("\n") if s != "" else []
        total = len(lines)
        try:
            lo = max(0, int(line_offset or 0))
        except (TypeError, ValueError):
            lo = 0
        lo = min(lo, total)
        try:
            ml = max(0, int(max_lines or 0))
        except (TypeError, ValueError):
            ml = 0
        try:
            mc = max(0, int(max_chars or 0))
        except (TypeError, ValueError):
            mc = 0
        if lo == 0 and ml == 0 and (mc == 0 or len(s) <= mc):
            return s, {"total_lines": total, "line_offset": 0, "returned_lines": total,
                       "truncated": False, "next_line_offset": None}
        end = total if ml == 0 else min(total, lo + ml)
        out = []
        used = 0
        line_cut = False
        for i in range(lo, end):
            ln = lines[i]
            add = len(ln) + (1 if out else 0)
            if mc and used + add > mc:
                if not out:
                    out.append(ln[:mc])
                    line_cut = True
                break
            out.append(ln)
            used += add
        nxt = lo + len(out)
        meta = {
            "total_lines": total,
            "line_offset": lo,
            "returned_lines": len(out),
            "truncated": bool(nxt < total or line_cut),
            "next_line_offset": nxt if nxt < total else None,
        }
        if line_cut:
            meta["line_cut"] = True
        return "\n".join(out), meta

    def _text_opts(self, params):
        """(line_offset, max_lines, max_chars, render, force_analysis) for /decompile, /il, /assembly.

        Deliberately separate from limit/offset (whose defaults are 100/0)."""
        st = self._state()
        lo = max(0, parse_int_or_default(params.get("line_offset"), 0))
        ml = max(0, parse_int_or_default(params.get("max_lines"), 0))
        mc_raw = params.get("max_chars")
        mc = st.legacy_text_cap_chars if mc_raw is None else parse_int_or_default(mc_raw, st.legacy_text_cap_chars)
        mc = max(0, mc)
        render = str(params.get("render") or "legacy").strip().lower()
        if render not in ("legacy", "ast"):
            render = "legacy"
        fa_raw = params.get("force_analysis", "1")
        fa = str(fa_raw).strip().lower() not in ("0", "false", "no", "off")
        return lo, ml, mc, render, fa

    def _binary_ident(self):
        """The request's `binary` selector: query binary/binary_id, else the body's."""
        try:
            q = self._parse_query_params()
        except Exception:
            q = {}
        for k in ("binary", "binary_id"):
            v = q.get(k)
            if v is not None and str(v).strip() != "":
                return str(v).strip()
        if str(getattr(self, "command", "") or "").upper() != "GET":
            body = self._parse_post_params()
            if isinstance(body, dict):
                for k in ("binary", "binary_id"):
                    v = body.get(k)
                    if v is not None and str(v).strip() != "":
                        return str(v).strip()
        return ""

    @staticmethod
    def _busy_payload(what):
        return {
            "error": f"BUSY: {what}; retry after a short wait",
            "error_code": "BUSY",
            "retry_after_s": 5,
        }

    def _try_route(self, method) -> bool:
        """Generic route hook (endpoints.route_for, the expert verb routes).

        route_for(method, path) returns None or a callable(params) -> payload dict, or
        (payload dict, http status). An rc.ApiError maps to its status; any other
        exception to 500 INTERNAL. GET params = query; POST params = query merged with
        the body (body wins). Returns True when the request was answered.
        """
        try:
            ep = self.endpoints
        except Exception:
            return False
        rf = getattr(ep, "route_for", None)
        if not callable(rf):
            return False
        path = urllib.parse.urlparse(self.path).path
        try:
            handler = rf(method, path)
        except Exception as e:
            bn.log_error(f"route_for({method} {path}) failed: {e}")
            handler = None
        if handler is None:
            return False
        if method == "GET":
            params = self._parse_query_params()
        else:
            params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.path).query))
            body = self._parse_post_params()
            if isinstance(body, dict):
                params.update(body)
        try:
            res = handler(params)
            if isinstance(res, tuple) and len(res) == 2:
                payload, status = res
            else:
                payload, status = res, 200
            status = int(status)
            if not isinstance(payload, dict):
                payload = {"ok": True, "result": payload}
        except rc.ApiError as e:
            payload = dict(e.payload())
            payload["ok"] = False
            status = e.http_status
        except Exception as e:
            bn.log_error(f"Error handling {method} {path}: {e}")
            bn.log_error(traceback.format_exc())
            payload = {"ok": False, "error": "INTERNAL: " + str(e)[:500], "error_code": "INTERNAL"}
            status = 500
        self._send_json_response(payload, status)
        return True

    @staticmethod
    def _start_sampled(info):
        """A copy of the `_binary` echo `info` with analysis_state_at_start = its own analysis_state (never raises).

        _dispatch builds the echo (describe_view) under the request lock, right before `impl` runs, so its
        analysis sample IS the start sample. A failed sample is 'unknown' (describe_view), never IdleState, so it
        can never vouch for an idle view. A non-dict `info` is returned unchanged.
        """
        if not isinstance(info, dict):
            return info
        out = dict(info)
        out["analysis_state_at_start"] = out.get("analysis_state")
        return out

    @staticmethod
    def _locked_reader(ops, wait_s):
        """`read_locked` for ops.locate_binary: run fn under the request lock of a view (ops.view_lock), each
        lock acquired within ONE shared budget of wait_s seconds from now (None: unbounded) -> fn(), or None
        when the lock was not acquired in time. Locks are taken one at a time, never nested."""
        deadline = None if wait_s is None else time.monotonic() + max(0.0, float(wait_s))

        def read(view_id, fn):
            lk = ops.view_lock(view_id)
            left = None if deadline is None else max(0.0, deadline - time.monotonic())
            if not _acquire_lock(lk, left):
                return None
            try:
                return fn()
            finally:
                lk.release()
        return read

    def _dispatch(self, impl):
        """Locate the request's binary, take its lock(s), THEN describe it, and run `impl` in a request scope.

        * SCOPE_EXEMPT paths, and /status without `binary`: no slot, no scope, and no lock except for the load
          paths in lock_mode 'global' (_GLOBAL_LOCKED_UNSCOPED: they hold the global lock).
        * Lock before any Binary Ninja read. Resolution only LOCATES the view (ops.locate_binary for
          `binary`, else the global selection): registry facts (view ids, filenames, view classes) and, for
          a sha256 selector, the on-disk files' sha256. The `_binary` echo (ops.describe_view: the analysis
          state and, once per file session, the sha256 of the loaded bytes) is built only once the view
          lock (and, in 'per-view', the in-flight slot) is held. So in lock_mode 'global' the one lock
          serializes ALL Binary Ninja work of a scoped request, and in 'per-view' the view's lock covers
          all of it. A 409 AMBIGUOUS reads each candidate's start address under that candidate's lock (one
          shared lock_wait_s budget; a candidate not acquired in time is listed with start None).
        * With `binary`: strict resolution (409 AMBIGUOUS / 404 NOT_FOUND / 400 BAD_ARGUMENT), then the view
          lock (bounded by lock_wait_s -> 503 BUSY).
        * Without `binary` (legacy): the global selection (registered first when it is not), unbounded
          wait (upstream queueing); `binary_defaulted` is reported when more than one view is open.
        * Lock ORDER: view lock first, then (lock_mode 'per-view' only) an in-flight slot. Once both are
          held, the view id must still be registered, alive, not closing and hold the located view's file
          session (ops.live_view), else 410 GONE; the request runs on the id's REGISTERED view.
        * The echo's analysis state is sampled under the lock just before `impl` runs
          (analysis_state_at_start); see _decorate_json for how it combines with the response-time sample.
        """
        try:
            path = urllib.parse.urlparse(self.path).path
        except Exception:
            path = ""
        ops = self.binary_ops
        st = self._state()
        if ops is None or path in SCOPE_EXEMPT:
            rc.reset_notes()
            if ops is not None and path in _GLOBAL_LOCKED_UNSCOPED and st.lock_mode == "global":
                lock = ops.view_lock("")                # lock_mode 'global': the one lock of every view id
                wait = st.lock_wait_s if path == "/x/loadBinary" else st.legacy_lock_wait_s
                if not _acquire_lock(lock, wait):
                    self._send_json_response(
                        dict(self._busy_payload("another request holds the global Binary Ninja lock"), ok=False), 503)
                    return None
                try:
                    return impl()
                finally:
                    lock.release()
            return impl()
        try:
            ident = self._binary_ident()
        except Exception:
            ident = ""
        if not ident and path == "/status":
            rc.reset_notes()
            return impl()
        if ident:
            resolved_by = "explicit"
            wait_lock, wait_slot = st.lock_wait_s, st.inflight_wait_s
        else:
            resolved_by = "global"
            wait_lock, wait_slot = st.legacy_lock_wait_s, None
        try:
            if ident:
                try:
                    bv, vid = ops.locate_binary(ident, self._locked_reader(ops, wait_lock))
                except rc.ApiError as e:
                    self._send_json_response(e.payload(), e.http_status)
                    return None
                defaulted = False
            else:
                bv = ops.global_view()
                vid = ops.view_id_of(bv) if bv is not None else ""
                if bv is not None and not vid:
                    vid = ops.register_view(bv)
                defaulted = bool(bv is not None and ops.open_view_count() > 1)
        except Exception as e:
            bn.log_error(f"Binary resolution failed for {path}: {e}")
            self._send_json_response(
                {"error": f"binary resolution failed: {e}", "error_code": "INTERNAL"}, 500
            )
            return None

        if bv is None:
            # Nothing selected (legacy request): no view to lock; the impl reports
            # "No binary loaded" (or serves a view-less route).
            with rc.scope(None, None, False):
                return impl()

        vid = str(vid or "")
        lock = ops.view_lock(vid)
        if not _acquire_lock(lock, wait_lock):
            self._send_json_response(self._busy_payload(f"view {vid or '?'} is busy (another request holds its lock)"), 503)
            return None
        slot = False
        try:
            if st.lock_mode == "per-view":
                if not _acquire_lock(st.inflight, wait_slot):
                    self._send_json_response(self._busy_payload("the server is at its in-flight request limit"), 503)
                    return None
                slot = True
            live = ops.live_view(vid, bv)
            if live is None:
                self._send_json_response(rc.GoneError("binary", vid or "(unregistered)").payload(), 410)
                return None
            try:
                info = ops.describe_view(live, resolved_by)
            except Exception as e:
                bn.log_error(f"Binary resolution failed for {path}: {e}")
                self._send_json_response(
                    {"error": f"binary resolution failed: {e}", "error_code": "INTERNAL"}, 500
                )
                return None
            info = self._start_sampled(info)
            with rc.scope(live, info, defaulted):
                return impl()
        finally:
            if slot:
                try:
                    st.inflight.release()
                except ValueError:
                    pass
            lock.release()

    # ---------------- who may call (core/local_auth.py) ----------------
    def _changes_state(self) -> bool:
        """True for a request that can change the analysis, the global selection or the set of open binaries: a GET
        of _MUTATING_GET_PATHS, and every POST / DELETE except _READ_ONLY_POST_PATHS."""
        try:
            path = urllib.parse.urlsplit(str(self.path)).path
        except Exception:
            return True
        method = str(self.command or "").upper()
        if method == "GET":
            return path in _MUTATING_GET_PATHS
        if method == "POST":
            return path not in _READ_ONLY_POST_PATHS
        return True

    def _reject_untrusted(self) -> bool:
        """Refuse a request that fails the Host allowlist, comes from a browser page, or lacks the per-run token (with
        BN_MCP_REQUIRE_TOKEN=0: only a request that changes state needs it). Runs before the body is parsed and before
        any Binary Ninja work. Returns True when the request was answered."""
        st = self._state()
        try:
            port = int(self.server.server_address[1])
        except Exception:
            port = -1
        status, code, msg = None, None, None
        if not local_auth.host_ok(self.headers.get("Host"), port):
            status, code = 403, "FORBIDDEN_HOST"
            msg = ("the Host header must be 127.0.0.1:%d or localhost:%d (DNS-rebinding protection)" % (port, port))
        else:
            why = local_auth.browser_reason(self.headers)
            if why is not None:
                status, code = 403, "BROWSER_REQUEST"
                msg = "requests from web pages are refused (%s)" % why
            elif not local_auth.token_matches(st.token, self.headers.get(local_auth.TOKEN_HEADER)):
                if st.require_token:
                    status, code = 401, "UNAUTHORIZED"
                    msg = ("missing or wrong %s header. The server writes its token to its token file when it starts "
                           "(BN_MCP_TOKEN_FILE, or the default per-user location in README.md); use the bridge or "
                           "bn_mcp_client.py from the same installation" % local_auth.TOKEN_HEADER)
                elif self._changes_state():
                    status, code = 401, "UNAUTHORIZED"
                    msg = ("this request changes the analysis, the selection or the open binaries, and needs the %s "
                           "header even with BN_MCP_REQUIRE_TOKEN=0 (that setting only lets requests that read "
                           "through without it)" % local_auth.TOKEN_HEADER)
        if status is None:
            return False
        try:
            path = urllib.parse.urlsplit(str(self.path)).path[:200]
        except Exception:
            path = "?"
        st.note_refusal(code, "%s %s: %s" % (self.command, path, code))
        self._discard_body()
        self._send_json_response({"ok": False, "error": "%s: %s" % (code, msg), "error_code": code}, status)
        return True

    _DISCARD_LIMIT = 1024 * 1024

    def _discard_body(self):
        """Read (and drop) a refused request's body of at most _DISCARD_LIMIT bytes, so that closing the connection
        does not reset it before the client has read the refusal (unread data makes Windows send a RST). A larger or
        malformed body is not read; that client may then see a reset instead of the answer."""
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            return
        if 0 < n <= self._DISCARD_LIMIT:
            try:
                self.rfile.read(n)
            except OSError:
                pass

    def do_GET(self):
        self._begin_request()
        if self._reject_untrusted():
            return
        self._dispatch(self._do_GET_impl)

    def do_POST(self):
        self._begin_request()
        if self._reject_untrusted():
            return
        try:
            body = self._parse_post_params()
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            meth = body.get("_method") if isinstance(body, dict) else None
            if meth is None:
                meth = dict(urllib.parse.parse_qsl(parsed.query)).get("_method")
            if str(meth or "").strip().upper() == "DELETE" and path in ("/comment", "/comment/function"):
                self.command = "DELETE"
            if path in _TYPE_POST_ROUTES:
                self._param_override = body if isinstance(body, dict) else {}
                self._dispatch(self._do_GET_impl)
                return
        except Exception as e:
            bn.log_error(f"Error handling POST request: {e}")
            self._send_json_response({"error": str(e)}, 500)
            return
        self._dispatch(self._do_POST_impl)

    def do_DELETE(self):
        self._begin_request()
        if self._reject_untrusted():
            return
        try:
            self._parse_post_params()
        except Exception:
            pass
        self._dispatch(self._do_POST_impl)

    def _do_GET_impl(self):
        try:
            # Generic routes (expert verbs) are served before any loaded-binary check
            if self._try_route("GET"):
                return
            # For all endpoints except /status, /convertNumber, /platforms, /binaries, /views, /selectBinary
            # (and the view-less /x routes), check loaded
            if not self.path.startswith(_GET_NO_VIEW_PREFIXES) and not self._check_binary_loaded():
                return

            params = self._parse_query_params()
            path = urllib.parse.urlparse(self.path).path
            if path in _C_TEXT_PATHS and any(c_text_names_a_file(v) for v in params.values()):
                self._send_json_response({
                    "ok": False, "error_code": "POLICY",
                    "error": "POLICY: C text sent to the server may not contain #include, #include_next, #import, "
                             "#embed or __has_include: Binary Ninja's type parser would open the named file (a "
                             "network path would make it connect to that host). Declare the types themselves."}, 403)
                return
            offset = parse_int_or_default(params.get("offset"), 0)
            # Support both `limit` and `count` (alias) for pagination
            if params.get("count") is not None:
                limit = parse_int_or_default(params.get("count"), 100)
            else:
                limit = parse_int_or_default(params.get("limit"), 100)

            if path == "/status":
                cv = self.binary_ops.current_view if self.binary_ops else None
                status = {
                    "loaded": self.binary_ops
                    and cv is not None,
                    "filename": cv.file.filename
                    if self.binary_ops and cv
                    else None,
                }
                # Scoped (/status?binary=...): the named view's analysis state (enum NAME)
                if rc.info() is not None and cv is not None:
                    summ = self.binary_ops.analysis_summary(cv)
                    status["analysis_state"] = summ.get("state")
                    status["analysis_state_code"] = summ.get("state_code")
                    status["analysis_progress"] = summ.get("progress")
                status["server"] = self._server_block()
                self._send_json_response(status)

            elif path == "/functions" or path == "/methods":
                functions = self.binary_ops.get_function_names(offset, limit)
                bn.log_debug(f"Found {len(functions)} functions")
                self._send_json_response({"functions": functions})

            elif path == "/classes":
                classes = self.binary_ops.get_class_names(offset, limit)
                self._send_json_response({"classes": classes})

            elif path == "/segments":
                segments = self.binary_ops.get_segments(offset, limit)
                self._send_json_response({"segments": segments})

            elif path == "/imports":
                imports = self.endpoints.get_imports(offset, limit)
                self._send_json_response({"imports": imports})

            elif path == "/binaries" or path == "/views":
                # List managed/open binaries
                self._send_json_response(self.endpoints.list_binaries())

            elif path == "/selectBinary":
                ident = params.get("view") or params.get("binary") or params.get("id") or params.get("file")
                if not ident:
                    self._send_json_response({"error": "Missing parameter", "help": "Use ?view=<id|filename>"}, 400)
                else:
                    self._send_json_response(self.endpoints.select_binary(ident))

            elif path == "/exports":
                exports = self.endpoints.get_exports(offset, limit)
                self._send_json_response({"exports": exports})
            elif path == "/sections":
                try:
                    sections = self.binary_ops.get_sections(offset, limit)
                    self._send_json_response({"sections": sections})
                except Exception as e:
                    bn.log_error(f"Error getting sections: {e}")
                    self._send_json_response({"error": str(e)}, 500)
            elif path == "/entryPoints":
                try:
                    eps = self.endpoints.get_entry_points()
                    self._send_json_response({"entry_points": eps})
                except Exception as e:
                    bn.log_error(f"Error handling entryPoints: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/namespaces":
                namespaces = self.endpoints.get_namespaces(offset, limit)
                self._send_json_response({"namespaces": namespaces})

            elif path == "/data":
                try:
                    # length: desired byte count to read for preview; negative means "read exact defined size"
                    length_param = params.get("length")
                    preview_param = params.get("previewLen")
                    if length_param is not None:
                        read_len = parse_int_or_default(length_param, 32)
                    elif preview_param is not None:
                        read_len = parse_int_or_default(preview_param, 32)
                    else:
                        # Default: read exact defined size when available
                        read_len = -1
                    data_items = self.binary_ops.get_defined_data(offset, limit, read_len)
                    self._send_json_response({"data": data_items})
                except Exception as e:
                    bn.log_error(f"Error getting data items: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/localTypes":
                try:
                    include_libs = params.get("includeLibraries") in ("1","true","True")
                    types = self.binary_ops.list_local_types(offset, limit, include_libraries=include_libs)
                    bn.log_debug(f"/localTypes returned {len(types)} entries (offset={offset}, limit={limit})")
                    self._send_json_response({"types": types})
                except Exception as e:
                    bn.log_error(f"Error listing local types: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/searchTypes":
                try:
                    term = params.get("query") or params.get("q")
                    if not term:
                        self._send_json_response(
                            {"error": "Missing query parameter", "help": "Required: query or q"},
                            400,
                        )
                        return
                    # support count=-1 to return all
                    eff_limit = -1 if (params.get("count") == "-1" or params.get("limit") == "-1") else limit
                    include_libs = params.get("includeLibraries") in ("1","true","True")
                    # First compute total
                    all_matches = self.binary_ops.search_local_types(term, 0, -1, include_libraries=include_libs)
                    page = all_matches[offset:] if eff_limit < 0 else all_matches[offset:offset+eff_limit]
                    self._send_json_response({"types": page, "query": term, "total": len(all_matches), "offset": offset, "limit": eff_limit, "includeLibraries": include_libs})
                except Exception as e:
                    bn.log_error(f"Error searching local types: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/strings":
                try:
                    bn.log_debug(f"/strings request: offset={offset}, limit={limit}")
                    strings = self.binary_ops.get_strings(offset, limit)
                    self._send_json_response({"strings": strings})
                except Exception as e:
                    bn.log_error(f"Error getting strings: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/allStrings":
                try:
                    # Return all strings without pagination
                    bn.log_debug("/allStrings request received")
                    strings = self.binary_ops.get_strings(0, 2147483647)
                    total = len(strings)
                    cap = self._state().legacy_list_cap
                    truncated = bool(cap and total > cap)
                    self._send_json_response({
                        "strings": strings[:cap] if truncated else strings,
                        "truncated": truncated,
                        "total": total,
                    })
                except Exception as e:
                    bn.log_error(f"Error getting all strings: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/hexdump":
                try:
                    address_str = params.get("address")
                    if not address_str:
                        self._set_headers(content_type="text/plain", status_code=400)
                        self.wfile.write(b"Missing address parameter\n")
                        return
                    # Parse address
                    try:
                        addr = int(address_str, 16) if address_str.startswith("0x") else int(address_str, 16 if all(c in "0123456789abcdefABCDEF" for c in address_str) else 10)
                    except Exception:
                        self._set_headers(content_type="text/plain", status_code=400)
                        self.wfile.write(b"Invalid address format; use hex like 0x401000\n")
                        return

                    # Determine length
                    length_param = params.get("length")
                    read_len = None
                    if length_param is not None:
                        try:
                            read_len = int(length_param)
                        except Exception:
                            read_len = None
                    # Default to exact defined size when available
                    if read_len is None:
                        read_len = -1

                    # If negative, try to use exact defined size at this address
                    if read_len < 0:
                        try:
                            inferred = self.binary_ops.infer_data_size(addr)
                            if inferred is not None and inferred > 0:
                                read_len = int(inferred)
                        except Exception:
                            pass
                    # Fallback default length
                    if read_len is None or read_len < 0:
                        read_len = 64

                    # Read bytes
                    try:
                        data = self.binary_ops.current_view.read(addr, read_len)
                        if data is None:
                            data = b""
                    except Exception:
                        data = b""

                    # Resolve symbol name for header label
                    label = None
                    try:
                        sym = self.binary_ops.current_view.get_symbol_at(addr)
                        if sym and hasattr(sym, "name"):
                            label = sym.name
                    except Exception:
                        label = None

                    # Build hexdump
                    addr_hex = format(addr, 'x')
                    lines = [f"{addr_hex}  {label}:" if label else f"{addr_hex}:"]
                    lines.extend(_hexdump_rows(addr, data))

                    text = "\n".join(lines) + "\n"
                    self._set_headers(content_type="text/plain", status_code=200)
                    self.wfile.write(text.encode("utf-8", errors="replace"))
                except Exception as e:
                    bn.log_error(f"Error handling hexdump: {e}")
                    self._set_headers(content_type="text/plain", status_code=500)
                    self.wfile.write(f"Error: {e}\n".encode("utf-8"))

            elif path == "/hexdumpByName":
                try:
                    name = params.get("name") or params.get("symbol") or params.get("raw_name")
                    if not name:
                        self._set_headers(content_type="text/plain", status_code=400)
                        self.wfile.write(b"Missing name parameter\n")
                        return

                    addr, label = self._resolve_name_to_address(name)
                    if addr is None:
                        self._set_headers(content_type="text/plain", status_code=404)
                        self.wfile.write(b"Symbol not found\n")
                        return

                    # Determine length
                    length_param = params.get("length")
                    try:
                        read_len = int(length_param) if length_param is not None else -1
                    except Exception:
                        read_len = -1
                    if read_len < 0:
                        try:
                            inferred = self.binary_ops.infer_data_size(addr)
                            if inferred is not None and inferred > 0:
                                read_len = int(inferred)
                        except Exception:
                            pass
                    if read_len is None or read_len < 0:
                        read_len = 64

                    # Read and format
                    try:
                        data = self.binary_ops.current_view.read(addr, read_len) or b""
                    except Exception:
                        data = b""

                    addr_hex = format(addr, 'x')
                    lines = [f"{addr_hex}  {label}:"]
                    lines.extend(_hexdump_rows(addr, data))

                    text = "\n".join(lines) + "\n"
                    self._set_headers(content_type="text/plain", status_code=200)
                    self.wfile.write(text.encode("utf-8", errors="replace"))
                except Exception as e:
                    bn.log_error(f"Error handling hexdumpByName: {e}")
                    self._set_headers(content_type="text/plain", status_code=500)
                    self.wfile.write(f"Error: {e}\n".encode("utf-8"))

            elif path == "/getDataDecl":
                try:
                    ident = params.get("name") or params.get("symbol") or params.get("raw_name") or params.get("address")
                    if not ident:
                        self._send_json_response({"error": "Missing name/address parameter", "help": "Provide name, symbol, raw_name, or address"}, 400)
                        return
                    addr, label = self._resolve_name_to_address(ident)
                    if addr is None:
                        self._send_json_response({"error": "Symbol not found", "ident": ident}, 404)
                        return

                    # Determine exact size and type
                    size = None
                    type_text = None
                    try:
                        bv = self.binary_ops.current_view
                        dv = bv.get_data_var_at(addr) if hasattr(bv, "get_data_var_at") else None
                        typ_obj = dv.type if (dv is not None and hasattr(dv, "type")) else (bv.get_type_at(addr) if hasattr(bv, "get_type_at") else None)
                        if typ_obj is not None:
                            type_text = str(typ_obj)
                            if hasattr(typ_obj, "width") and typ_obj.width:
                                size = int(typ_obj.width)
                    except Exception:
                        pass
                    if size is None:
                        try:
                            inferred = self.binary_ops.infer_data_size(addr)
                            if inferred and inferred > 0:
                                size = int(inferred)
                        except Exception:
                            pass
                    if size is None:
                        size = 64

                    # Read bytes
                    try:
                        raw = self.binary_ops.current_view.read(addr, size) or b""
                    except Exception:
                        raw = b""

                    # Build a declaration string (best-effort)
                    decl = None
                    try:
                        # Prefer explicit char[] initialization when printable
                        is_char_array = (type_text or "").lower().startswith("char") or "char [" in (type_text or "").lower()
                        if is_char_array and raw:
                            esc = self._c_escape(raw.rstrip(b"\x00"))
                            decl = f"{type_text} {label} = {esc};"
                        else:
                            if type_text:
                                decl = f"{type_text} {label};"
                            else:
                                decl = f"/* size={size} */ {label};"
                    except Exception:
                        decl = f"/* size={size} */ {label};"

                    # Also include a hexdump for convenience
                    addr_hex = format(addr, 'x')
                    lines = [f"{addr_hex}  {label}:"]
                    lines.extend(_hexdump_rows(addr, raw))
                    hexdump_text = "\n".join(lines) + "\n"

                    self._send_json_response({
                        "address": hex(addr),
                        "name": label,
                        "size": size,
                        "type": type_text,
                        "decl": decl,
                        "hexdump": hexdump_text,
                    })
                except Exception as e:
                    bn.log_error(f"Error handling getDataDecl: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/strings/filter":
                try:
                    pattern = params.get("filter", "")
                    bn.log_debug(f"/strings/filter request: offset={offset}, limit={limit}")
                    # Get all strings first, then filter and paginate
                    all_strings = self.binary_ops.get_strings(0, 2147483647)
                    if pattern:
                        pl = pattern.lower()
                        filtered = [s for s in all_strings if isinstance(s.get("value"), str) and pl in s.get("value", "").lower()]
                    else:
                        filtered = all_strings
                    page = filtered[offset : offset + limit]
                    cap = self._state().legacy_list_cap
                    truncated = bool(cap and len(page) > cap)
                    if truncated:
                        page = page[:cap]
                    self._send_json_response({"strings": page, "total": len(filtered), "truncated": truncated})
                except Exception as e:
                    bn.log_error(f"Error filtering strings: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/searchFunctions":
                search_term = params.get("query", "")
                matches = self.endpoints.search_functions(search_term, offset, limit)
                self._send_json_response({"matches": matches})

            elif path == "/decompile":
                function_name = params.get("name") or params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {
                            "error": "Missing function name parameter. Use ?name=function_name or ?functionName=function_name"
                        },
                        400,
                    )
                    return

                lo, ml, mc, render, fa = self._text_opts(params)
                self._handle_decompile(
                    function_name,
                    line_offset=lo,
                    max_lines=ml,
                    max_chars=mc,
                    render=render,
                    force_analysis=fa,
                )

            elif path == "/assembly":
                function_name = params.get("name") or params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {
                            "error": "Missing function name parameter. Use ?name=function_name or ?functionName=function_name"
                        },
                        400,
                    )
                    return

                try:
                    func_info = self.binary_ops.get_function_info(function_name)
                    if not func_info:
                        bn.log_error(f"Function not found: {function_name}")
                        self._send_json_response(
                            {
                                "error": "Function not found",
                                "requested_name": function_name,
                                "available_functions": self.binary_ops.get_function_names(
                                    0, 10
                                ),
                            },
                            404,
                        )
                        return

                    bn.log_debug(f"Found function for assembly: {func_info}")
                    assembly = self.binary_ops.get_assembly_function(function_name)

                    if assembly is None:
                        self._send_json_response(
                            {
                                "error": "Assembly retrieval failed",
                                "function": func_info,
                                "reason": "Function assembly could not be retrieved. Check the Binary Ninja log for detailed error information.",
                            },
                            500,
                        )
                    else:
                        lo, ml, mc, _render, _fa = self._text_opts(params)
                        assembly, cap_meta = self._cap_lines(assembly, lo, ml, mc)
                        resp = {"assembly": assembly, "function": func_info}
                        resp.update(cap_meta)
                        self._send_json_response(resp)
                except Exception as e:
                    bn.log_error(f"Error handling assembly request: {str(e)}")
                    import traceback
                    bn.log_error(traceback.format_exc())
                    self._send_json_response(
                        {
                            "error": "Assembly retrieval failed",
                            "requested_name": function_name,
                            "exception": str(e),
                        },
                        500,
                    )

            elif path == "/il":
                # Return IL by view (hlil/mlil/llil) and optional SSA form
                ident = params.get("name") or params.get("functionName") or params.get("address")
                if not ident:
                    self._send_json_response(
                        {
                            "error": "Missing function identifier",
                            "help": "Use ?name=<func> or ?address=<hex> with optional &view=hlil|mlil|llil&ssa=0|1",
                            "received": params,
                        },
                        400,
                    )
                    return

                view = (params.get("view") or params.get("il") or "hlil").strip()
                ssa_param = (params.get("ssa") or params.get("isSSA") or "0").strip().lower()
                ssa = ssa_param in ("1", "true", "yes", "on")

                try:
                    func_info = self.binary_ops.get_function_info(ident)
                    if not func_info:
                        self._send_json_response(
                            {
                                "error": "Function not found",
                                "requested": ident,
                                "available_functions": self.binary_ops.get_function_names(0, 10),
                            },
                            404,
                        )
                        return

                    lo, ml, mc, render, fa = self._text_opts(params)
                    il_text = self.binary_ops.get_function_il(
                        ident, view=view, ssa=ssa, render=render, force_analysis=fa
                    )
                    if il_text is None:
                        self._send_json_response(
                            {
                                "error": "Failed to get IL",
                                "function": func_info,
                                "view": view,
                                "ssa": ssa,
                                "reason": "Unsupported IL view or unavailable instructions",
                            },
                            500,
                        )
                        return

                    il_text, cap_meta = self._cap_lines(il_text, lo, ml, mc)
                    resp = {"il": il_text, "function": func_info, "view": view, "ssa": ssa}
                    resp.update(cap_meta)
                    self._send_json_response(resp)
                except Exception as e:
                    bn.log_error(f"Error handling IL request: {str(e)}")
                    self._send_json_response(
                        {
                            "error": "IL retrieval failed",
                            "requested": ident,
                            "view": view,
                            "ssa": ssa,
                            "exception": str(e),
                        },
                        500,
                    )

            elif path == "/functionAt":
                address_str = params.get("address")
                if not address_str:
                    self._send_json_response(
                        {
                            "error": "Missing address parameter",
                            "help": "Required parameter: address (in hex format, e.g., 0x41d100) the address of an insruction",
                            "received": params,
                        },
                        400,
                    )
                    return
                    
                try:
                    # Convert hex string to integer
                    if isinstance(address_str, str) and address_str.startswith("0x"):
                        offset = int(address_str, 16)
                    else:
                        offset = int(address_str)
                        
                    # Add function to binary_operations.py
                    function_names = self.binary_ops.get_functions_containing_address(offset)
                    
                    self._send_json_response(
                        {
                            "address": hex(offset),
                            "functions": function_names
                        }
                    )
                except ValueError:
                    self._send_json_response(
                        {
                            "error": "Invalid address format",
                            "help": "Address must be a valid hexadecimal (0x...) or decimal number",
                            "received": address_str,
                        },
                        400,
                    )
                except Exception as e:
                    bn.log_error(f"Error handling function_at request: {e}")
                    self._send_json_response(
                        {
                            "error": str(e),
                            "address": address_str,
                        },
                        500,
                    )
            
                    
            elif path == "/getUserDefinedType":
                type_name = params.get("name")
                if not type_name:
                    self._send_json_response(
                        {
                            "error": "Missing name parameter",
                            "help": "Required parameter: name (name of the user-defined type to retrieve)",
                            "received": params,
                        },
                        400,
                    )
                    return
                    
                try:
                    # Get the user-defined type definition
                    type_info = self.binary_ops.get_user_defined_type(type_name)
                    
                    if type_info:
                        self._send_json_response(type_info)
                    else:
                        # If type not found, list available types for reference
                        available_types = {}
                        
                        try:
                            if (hasattr(self.binary_ops._current_view, "user_type_container") and 
                                self.binary_ops._current_view.user_type_container):
                                for type_id in self.binary_ops._current_view.user_type_container.types.keys():
                                    current_type = self.binary_ops._current_view.user_type_container.types[type_id]
                                    available_types[current_type[0]] = str(current_type[1].type) if hasattr(current_type[1], "type") else "unknown"
                        except Exception as e:
                            bn.log_error(f"Error listing available types: {e}")
                            
                        self._send_json_response(
                            {
                                "error": "Type not found",
                                "requested_type": type_name,
                                "available_types": available_types
                            },
                            404,
                        )
                except Exception as e:
                    bn.log_error(f"Error handling getUserDefinedType request: {e}")
                    self._send_json_response(
                        {
                            "error": str(e),
                            "type_name": type_name,
                        },
                        500,
                    )
                    
            elif path == "/comment":
                if self.command == "GET":
                    address = params.get("address")
                    if not address:
                        self._send_json_response(
                            {
                                "error": "Missing address parameter",
                                "help": "Required parameter: address",
                                "received": params,
                            },
                            400,
                        )
                        return

                    try:
                        address_int = int(address, 16) if isinstance(address, str) else int(address)
                        comment = self.binary_ops.get_comment(address_int)
                        if comment is not None:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "address": hex(address_int),
                                    "comment": comment,
                                }
                            )
                        else:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "address": hex(address_int),
                                    "comment": None,
                                    "message": "No comment found at this address",
                                }
                            )
                    except ValueError:
                        self._send_json_response({"error": "Invalid address format"}, 400)
                elif self.command == "DELETE":
                    address = params.get("address")
                    if not address:
                        self._send_json_response(
                            {
                                "error": "Missing address parameter",
                                "help": "Required parameter: address",
                                "received": params,
                            },
                            400,
                        )
                        return

                    try:
                        address_int = int(address, 16) if isinstance(address, str) else int(address)
                        success = self.binary_ops.delete_comment(address_int)
                        if success:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "message": f"Successfully deleted comment at {hex(address_int)}",
                                }
                            )
                        else:
                            self._send_json_response(
                                {
                                    "error": "Failed to delete comment",
                                    "message": "The comment could not be deleted at the specified address.",
                                },
                                500,
                            )
                    except ValueError:
                        self._send_json_response({"error": "Invalid address format"}, 400)
                else:  # POST
                    address = params.get("address")
                    comment = params.get("comment")
                    if not address or comment is None:
                        self._send_json_response(
                            {
                                "error": "Missing parameters",
                                "help": "Required parameters: address and comment",
                                "received": params,
                            },
                            400,
                        )
                        return

                    try:
                        address_int = int(address, 16) if isinstance(address, str) else int(address)
                        success = self.binary_ops.set_comment(address_int, comment)
                        if success:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "message": f"Successfully set comment at {hex(address_int)}",
                                    "comment": comment,
                                }
                            )
                        else:
                            self._send_json_response(
                                {
                                    "error": "Failed to set comment",
                                    "message": "The comment could not be set at the specified address.",
                                },
                                500,
                            )
                    except ValueError:
                        self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/comment/function":
                if self.command == "GET":
                    function_name = params.get("name") or params.get("functionName")
                    if not function_name:
                        self._send_json_response(
                            {
                                "error": "Missing function name parameter",
                                "help": "Required parameter: name (or functionName)",
                                "received": params,
                            },
                            400,
                        )
                        return

                    comment = self.binary_ops.get_function_comment(function_name)
                    if comment is not None:
                        self._send_json_response(
                            {
                                "success": True,
                                "function": function_name,
                                "comment": comment,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "success": True,
                                "function": function_name,
                                "comment": None,
                                "message": "No comment found for this function",
                            }
                        )
                elif self.command == "DELETE":
                    function_name = params.get("name") or params.get("functionName")
                    if not function_name:
                        self._send_json_response(
                            {
                                "error": "Missing function name parameter",
                                "help": "Required parameter: name (or functionName)",
                                "received": params,
                            },
                            400,
                        )
                        return

                    success = self.binary_ops.delete_function_comment(function_name)
                    if success:
                        self._send_json_response(
                            {
                                "success": True,
                                "message": f"Successfully deleted comment for function {function_name}",
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "error": "Failed to delete function comment",
                                "message": "The comment could not be deleted for the specified function.",
                            },
                            500,
                        )
                else:  # POST
                    function_name = params.get("name") or params.get("functionName")
                    comment = params.get("comment")
                    if not function_name or comment is None:
                        self._send_json_response(
                            {
                                "error": "Missing parameters",
                                "help": "Required parameters: name (or functionName) and comment",
                                "received": params,
                            },
                            400,
                        )
                        return

                    success = self.binary_ops.set_function_comment(function_name, comment)
                    if success:
                        self._send_json_response(
                            {
                                "success": True,
                                "message": f"Successfully set comment for function {function_name}",
                                "comment": comment,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "error": "Failed to set function comment",
                                "message": "The comment could not be set for the specified function.",
                            },
                            500,
                        )

            elif path == "/getComment":
                address = params.get("address")
                if not address:
                    self._send_json_response(
                        {
                            "error": "Missing address parameter",
                            "help": "Required parameter: address",
                            "received": params,
                        },
                        400,
                    )
                    return

                try:
                    address_int = int(address, 16) if isinstance(address, str) else int(address)
                    comment = self.binary_ops.get_comment(address_int)
                    if comment is not None:
                        self._send_json_response(
                            {
                                "success": True,
                                "address": hex(address_int),
                                "comment": comment,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "success": True,
                                "address": hex(address_int),
                                "comment": None,
                                "message": "No comment found at this address",
                            }
                        )
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/getFunctionComment":
                function_name = params.get("name") or params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {
                            "error": "Missing function name parameter",
                            "help": "Required parameter: name (or functionName)",
                            "received": params,
                        },
                        400,
                    )
                    return

                comment = self.binary_ops.get_function_comment(function_name)
                if comment is not None:
                    self._send_json_response(
                        {
                            "success": True,
                            "function": function_name,
                            "comment": comment,
                        }
                    )
                else:
                    self._send_json_response(
                        {
                            "success": True,
                            "function": function_name,
                            "comment": None,
                            "message": "No comment found for this function",
                        }
                    )
            elif path == "/setFunctionPrototype":
                # Accept both GET and POST to support long prototypes via POST body
                address_str = (
                    params.get("address")
                    or params.get("functionAddress")
                    or params.get("addr")
                    or params.get("name")
                )
                proto = params.get("prototype") or params.get("signature") or params.get("type")
                if not address_str or proto is None:
                    self._send_json_response(
                        {
                            "error": "Missing parameters",
                            "help": "Required: address (or functionAddress/addr) and prototype (or signature/type)",
                            "received": params,
                        },
                        400,
                    )
                    return
                try:
                    # Do minimal validation here; the endpoint will resolve name or address
                    result = self.endpoints.set_function_prototype(address_str, proto)
                    self._send_json_response(result)
                except ValueError as ve:
                    self._send_json_response({"error": str(ve)}, 400)
                except Exception as e:
                    bn.log_error(f"Error handling setFunctionPrototype request: {e}")
                    self._send_json_response({"error": str(e)}, 500)
            elif path == "/makeFunctionAt":
                # Create a function at an address (idempotent if already exists)
                address_str = params.get("address") or params.get("addr")
                arch = params.get("platform") or params.get("arch") or params.get("architecture")
                if not address_str:
                    self._send_json_response(
                        {"error": "Missing address parameter", "help": "Required: address (hex like 0x401000 or decimal). Optional: platform (e.g., linux-x86_64; use 'default' for view default)"},
                        400,
                    )
                    return
                try:
                    res = self.endpoints.make_function_at(address_str, arch)
                    # If the endpoint signals an error, forward with 400 so clients can react properly
                    if isinstance(res, dict) and res.get("error"):
                        self._send_json_response(res, 400)
                    else:
                        self._send_json_response(res)
                except ValueError as ve:
                    self._send_json_response({"error": str(ve)}, 400)
                except Exception as e:
                    bn.log_error(f"Error handling makeFunctionAt: {e}")
                    self._send_json_response({"error": str(e)}, 500)
            elif path == "/platforms":
                try:
                    self._send_json_response(self.endpoints.list_platforms())
                except Exception as e:
                    bn.log_error(f"Error listing platforms: {e}")
                    self._send_json_response({"error": str(e)}, 500)
            elif path == "/setLocalVariableType":
                fn_ident = (
                    params.get("functionAddress")
                    or params.get("address")
                    or params.get("function")
                    or params.get("functionName")
                    or params.get("name")
                )
                var_name = params.get("variableName") or params.get("variable") or params.get("nameOrVar")
                new_type = params.get("newType") or params.get("type") or params.get("signature")
                if not fn_ident or not var_name or new_type is None:
                    self._send_json_response(
                        {
                            "error": "Missing parameters",
                            "help": "Required: functionAddress (or address/name), variableName, newType (or type/signature)",
                            "received": params,
                        },
                        400,
                    )
                    return
                try:
                    res = self.endpoints.set_local_variable_type(fn_ident, var_name, new_type)
                    self._send_json_response(res)
                except ValueError as ve:
                    self._send_json_response({"error": str(ve)}, 400)
                except Exception as e:
                    bn.log_error(f"Error handling setLocalVariableType request: {e}")
                    self._send_json_response({"error": str(e)}, 500)
            elif path == "/retypeVariable":
                function_name =  params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing function name parameter"}, 400
                    )
                    return
                
                variable_name = params.get("variableName")
                if not variable_name:
                    self._send_json_response(
                        {"error": "Missing variable name parameter"}, 400
                    )
                    return
                
                type_str = params.get("type")
                if not type_str:
                    self._send_json_response(
                        {"error": "Missing type parameter"}, 400
                    )
                    return
                
                try:
                    self._send_json_response(self.endpoints.retype_variable(function_name, variable_name, type_str))
                except Exception as e:
                    bn.log_error(f"Error handling retypeVariable request: {e}")
                    self._send_json_response(
                        {"error": str(e)},
                        500,
                    )
            elif path == "/renameVariable":
                function_name = params.get("functionName")
                if not function_name:
                    self._send_json_response(
                        {"error": "Missing function name parameter"}, 400
                    )
                    return
                
                variable_name = params.get("variableName")
                if not variable_name:
                    self._send_json_response(
                        {"error": "Missing variable name parameter"}, 400
                    )
                    return
                
                new_name = params.get("newName")
                if not new_name:
                    self._send_json_response(
                        {"error": "Missing new name parameter"}, 400
                    )
                    return
                
                try:
                    self._send_json_response(self.endpoints.rename_variable(function_name, variable_name, new_name))
                except Exception as e:
                    bn.log_error(f"Error handling renameVariable request: {e}")
                    self._send_json_response(
                        {"error": str(e)},
                        500,
                    )

            elif path == "/renameVariables":
                # Batch rename local variables in a function
                # Accept flexible identifiers and payload formats (GET/POST)
                fn_ident = (
                    params.get("functionAddress")
                    or params.get("address")
                    or params.get("function")
                    or params.get("functionName")
                    or params.get("name")
                )
                if not fn_ident:
                    self._send_json_response(
                        {
                            "error": "Missing function identifier",
                            "help": "Provide functionAddress/address or functionName/name",
                            "received": params,
                        },
                        400,
                    )
                    return

                raw_renames = None
                # Prefer explicit 'renames' in JSON when POSTed
                if isinstance(params, dict) and "renames" in params:
                    raw_renames = params.get("renames")
                # Or a JSON mapping under 'mapping'
                if raw_renames is None and "mapping" in params:
                    try:
                        m = params.get("mapping")
                        if isinstance(m, str):
                            raw_renames = json.loads(m)
                        else:
                            raw_renames = m
                    except Exception:
                        raw_renames = None
                # Or a compact 'pairs' string: old1:new1,old2:new2
                if raw_renames is None and "pairs" in params:
                    pairs_str = params.get("pairs") or ""
                    mapping = {}
                    try:
                        for item in pairs_str.split(","):
                            if not item.strip():
                                continue
                            if ":" in item:
                                o, n = item.split(":", 1)
                                mapping[o.strip()] = n.strip()
                    except Exception:
                        mapping = {}
                    raw_renames = mapping

                if raw_renames is None:
                    self._send_json_response(
                        {
                            "error": "Missing renames payload",
                            "help": "Provide 'renames' (array of {old,new}) or 'mapping' (JSON object old->new) or 'pairs' (old:new,...)",
                            "received": params,
                        },
                        400,
                    )
                    return

                try:
                    result = self.endpoints.rename_variables(fn_ident, raw_renames)
                    self._send_json_response(result)
                except ValueError as ve:
                    self._send_json_response({"error": str(ve)}, 400)
                except Exception as e:
                    bn.log_error(f"Error handling renameVariables request: {e}")
                    self._send_json_response({"error": str(e)}, 500)
                    
            elif path == "/getXrefsTo":
                address_str = params.get("address")
                if not address_str:
                    self._send_json_response(
                        {
                            "error": "Missing address parameter",
                            "help": "Required parameter: address (hex like 0x401000 or decimal)",
                            "received": params,
                        },
                        400,
                    )
                    return
                try:
                    result = self.binary_ops.get_xrefs_to_address(address_str)
                    self._send_json_response(result)
                except ValueError as ve:
                    self._send_json_response({"error": str(ve)}, 400)
                except Exception as e:
                    bn.log_error(f"Error handling getXrefsTo request: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/getXrefsToField":
                struct_name = params.get("struct") or params.get("structName")
                field_name = params.get("field") or params.get("fieldName")
                if not struct_name or not field_name:
                    self._send_json_response(
                        {
                            "error": "Missing parameters",
                            "help": "Required: struct (or structName), field (or fieldName)",
                            "received": params,
                        },
                        400,
                    )
                    return
                try:
                    refs = self.binary_ops.get_xrefs_to_field(struct_name, field_name)
                    self._send_json_response({
                        "struct": struct_name,
                        "field": field_name,
                        "references": refs
                    })
                except Exception as e:
                    bn.log_error(f"Error handling getXrefsToField: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/getXrefsToStruct":
                struct_name = params.get("name") or params.get("struct") or params.get("structName")
                if not struct_name:
                    self._send_json_response(
                        {
                            "error": "Missing struct name parameter",
                            "help": "Required: name (or struct/structName)",
                            "received": params,
                        },
                        400,
                    )
                    return
                try:
                    refs = self.binary_ops.get_xrefs_to_struct(struct_name)
                    self._send_json_response(refs)
                except Exception as e:
                    bn.log_error(f"Error handling getXrefsToStruct: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/getXrefsToType":
                type_name = params.get("name") or params.get("type") or params.get("typeName")
                if not type_name:
                    self._send_json_response(
                        {
                            "error": "Missing type name parameter",
                            "help": "Required: name (or type/typeName)",
                            "received": params,
                        },
                        400,
                    )
                    return
                try:
                    refs = self.binary_ops.get_xrefs_to_type(type_name)
                    self._send_json_response(refs)
                except Exception as e:
                    bn.log_error(f"Error handling getXrefsToType: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/getTypeInfo":
                type_name = params.get("name") or params.get("type") or params.get("typeName")
                if not type_name:
                    self._send_json_response(
                        {"error": "Missing type name parameter", "help": "Required: name (or type/typeName)"},
                        400,
                    )
                    return
                try:
                    info = self.binary_ops.get_type_info(type_name)
                    self._send_json_response(info)
                except Exception as e:
                    bn.log_error(f"Error handling getTypeInfo: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            

            elif path == "/getXrefsToEnum":
                enum_name = params.get("name") or params.get("enum") or params.get("enumName")
                if not enum_name:
                    self._send_json_response(
                        {
                            "error": "Missing enum name parameter",
                            "help": "Required: name (or enum/enumName)",
                            "received": params,
                        },
                        400,
                    )
                    return
                try:
                    refs = self.binary_ops.get_xrefs_to_enum(enum_name)
                    self._send_json_response(refs)
                except Exception as e:
                    bn.log_error(f"Error handling getXrefsToEnum: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            # '/displayAs' endpoint removed per request

            elif path == "/formatValue":
                # Compute representations and annotate BN at an address
                text = params.get("text")
                size_param = params.get("size")
                address_str = params.get("address")
                if not text or not address_str:
                    self._send_json_response(
                        {
                            "error": "Missing parameters",
                            "help": "Required: address, text. Optional: size",
                            "received": params,
                        },
                        400,
                    )
                    return
                try:
                    # Parse address
                    if isinstance(address_str, str) and address_str.startswith("0x"):
                        addr = int(address_str, 16)
                    else:
                        addr = int(address_str)
                except Exception:
                    self._send_json_response({"error": "Invalid address format"}, 400)
                    return

                try:
                    conv = util_convert_number(text, size_param)
                    # Create a concise annotation
                    bases = conv.get("bases", {})
                    c_lit = conv.get("c_literal")
                    c_str = conv.get("c_string")
                    parts = []
                    if "hex" in bases:
                        parts.append(f"hex={bases['hex']}")
                    if "dec" in bases:
                        parts.append(f"dec={bases['dec']}")
                    if c_lit:
                        parts.append(f"char={c_lit}")
                    if c_str:
                        # Trim long strings for comments
                        s = c_str
                        if len(s) > 64:
                            s = s[:61] + '"…'
                        parts.append(f"str={s}")
                    annot = "Converted: " + ", ".join(parts) if parts else f"Converted: {conv}"

                    applied = self.binary_ops.set_comment(addr, annot)
                    self._send_json_response({
                        "address": hex(addr),
                        "converted": conv,
                        "applied_comment": bool(applied),
                        "comment": annot,
                    })
                except Exception as e:
                    bn.log_error(f"Error handling formatValue: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/convertNumber":
                # Compute number/string representations (bases, LE/BE, C literals)
                try:
                    text = params.get("text")
                    size_param = params.get("size")
                    if text is None:
                        self._send_json_response(
                            {
                                "error": "Missing text parameter",
                                "help": "Required: text. Optional: size (1,2,4,8 or 0 for auto)",
                                "received": params,
                            },
                            400,
                        )
                        return
                    conv = util_convert_number(text, size_param)
                    self._send_json_response(conv)
                except Exception as e:
                    bn.log_error(f"Error handling convertNumber: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/getXrefsToUnion":
                union_name = params.get("name") or params.get("union") or params.get("unionName")
                if not union_name:
                    self._send_json_response(
                        {
                            "error": "Missing union name parameter",
                            "help": "Required: name (or union/unionName)",
                            "received": params,
                        },
                        400,
                    )
                    return
                try:
                    refs = self.binary_ops.get_xrefs_to_union(union_name)
                    self._send_json_response(refs)
                except Exception as e:
                    bn.log_error(f"Error handling getXrefsToUnion: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/defineTypes":
                c_code = params.get("cCode")
                if not c_code:
                    self._send_json_response(
                        {"error": "Missing cCode parameter"}, 400
                    )
                    return
                
                try:
                    self._send_json_response(self.endpoints.define_types(c_code))
                except Exception as e:
                    bn.log_error(f"Error handling defineTypes request: {e}")
                    self._send_json_response(
                        {"error": str(e)},
                        500,
                    )
            elif path == "/declareCType":
                c_decl = (
                    params.get("declaration")
                    or params.get("cDecl")
                    or params.get("cDeclaration")
                    or params.get("decl")
                )
                if not c_decl:
                    self._send_json_response(
                        {"error": "Missing declaration parameter", "help": "Use 'declaration' with a single C type declaration"},
                        400,
                    )
                    return
                try:
                    self._send_json_response(self.endpoints.declare_c_type(c_decl))
                except ValueError as ve:
                    self._send_json_response({"error": str(ve)}, 400)
                except Exception as e:
                    bn.log_error(f"Error handling declareCType request: {e}")
                    self._send_json_response({"error": str(e)}, 500)
            elif path == "/patch" or path == "/patchBytes":
                address = params.get("address") or params.get("addr")
                data = params.get("data") or params.get("bytes")
                # Parse save_to_file parameter (default True for backwards compatibility)
                save_to_file_param = params.get("save_to_file", True)
                if isinstance(save_to_file_param, bool):
                    save_to_file = save_to_file_param
                else:
                    save_to_file = str(save_to_file_param).lower() not in ("false", "0", "no")
                
                if not address:
                    self._send_json_response(
                        {
                            "error": "Missing address parameter",
                            "help": "Required: address (hex like 0x401000 or decimal). Optional: data (hex string like '90 90' or '9090'), save_to_file (bool, default true; save_to_file is refused unless BN_MCP_ALLOW_SAVE=1 - the in-memory patch still applies)",
                            "received": params,
                        },
                        400,
                    )
                    return
                
                if not data:
                    self._send_json_response(
                        {
                            "error": "Missing data parameter",
                            "help": "Required: data (hex string like '90 90' or '9090', or list of integers)",
                            "received": params,
                        },
                        400,
                    )
                    return
                
                try:
                    # Parse data if it's a JSON string (for list format)
                    if isinstance(data, str):
                        try:
                            # Try to parse as JSON array
                            parsed = json.loads(data)
                            if isinstance(parsed, list):
                                data = parsed
                        except (json.JSONDecodeError, ValueError):
                            # Not JSON, treat as hex string
                            pass
                    
                    result = self.endpoints.patch_bytes(address, data, save_to_file)
                    self._send_json_response(result)
                except ValueError as ve:
                    self._send_json_response({"error": str(ve)}, 400)
                except Exception as e:
                    bn.log_error(f"Error handling patch request: {e}")
                    self._send_json_response({"error": str(e)}, 500)
            else:
                self._send_json_response({"error": "Not found"}, 404)

        except Exception as e:
            bn.log_error(f"Error handling GET request: {e}")
            self._send_json_response({"error": str(e)}, 500)

    def _handle_decompile(self, function_name: str, line_offset: int = 0, max_lines: int = 0,
                          max_chars: int = 0, render: str = "legacy", force_analysis: bool = True):
        """Handle function decompilation requests.

        Args:
            function_name: Name or address of the function to decompile
            line_offset / max_lines / max_chars: optional line-boundary output caps
                (defaults: none; the reply always carries total_lines, line_offset,
                returned_lines, truncated and next_line_offset)
            render: 'legacy' (default) or 'ast'
            force_analysis: True (default, upstream behaviour) or False

        Sends JSON response with either:
        - Decompiled function code and metadata
        - Error message with available functions list
        """
        try:
            func_info = self.binary_ops.get_function_info(function_name)
            if not func_info:
                bn.log_error(f"Function not found: {function_name}")
                self._send_json_response(
                    {
                        "error": "Function not found",
                        "requested_name": function_name,
                        "available_functions": self.binary_ops.get_function_names(
                            0, 10
                        ),
                    },
                    404,
                )
                return

            bn.log_debug(f"Found function for decompilation: {func_info}")
            decompiled = self.binary_ops.decompile_function(
                function_name, render=render, force_analysis=force_analysis
            )

            if decompiled is None:
                self._send_json_response(
                    {
                        "error": "Decompilation failed",
                        "function": func_info,
                        "reason": "Function could not be decompiled. This might be due to missing debug information or unsupported function type.",
                    },
                    500,
                )
            else:
                decompiled, cap_meta = self._cap_lines(decompiled, line_offset, max_lines, max_chars)
                resp = {"decompiled": decompiled, "function": func_info}
                resp.update(cap_meta)
                self._send_json_response(resp)
        except Exception as e:
            bn.log_error(f"Error during decompilation: {e}")
            self._send_json_response(
                {
                    "error": f"Decompilation error: {str(e)}",
                    "requested_name": function_name,
                },
                500,
            )

    def _do_POST_impl(self):
        try:
            # Generic routes (expert verbs) are served before any loaded-binary check
            if self._try_route(str(self.command or "POST").upper()):
                return

            body = self._parse_post_params()
            path = urllib.parse.urlparse(self.path).path
            # Body parameters, with query parameters filling keys the body lacks
            # (DELETE requests commonly carry them in the query string).
            params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.path).query))
            if isinstance(body, dict):
                params.update(body)

            # /load opens the first binary, so it must not require one
            if path != "/load" and not self._check_binary_loaded():
                return

            n_params = len(params)
            bn.log_debug(f"POST {path} with {n_params} parameter(s)")

            if path == "/load":
                filepath = params.get("filepath")
                if not filepath:
                    self._send_json_response(
                        {"error": "Missing filepath parameter"}, 400
                    )
                    return

                try:
                    self.binary_ops.load_binary(filepath)
                    self._send_json_response(
                        {"success": True, "message": f"Binary loaded: {filepath}"}
                    )
                except rc.ApiError as e:
                    self._send_json_response(e.payload(), e.http_status)
                except Exception as e:
                    self._send_json_response({"error": str(e)}, 500)

            elif path == "/rename/function" or path == "/renameFunction":
                old_name = params.get("oldName") or params.get("old_name")
                new_name = params.get("newName") or params.get("new_name")

                if not old_name or not new_name:
                    self._send_json_response(
                        {
                            "error": "Missing parameters",
                            "help": "Required parameters: oldName (or old_name) and newName (or new_name)",
                            "received": params,
                        },
                        400,
                    )
                    return

                # Handle address format (both 0x... and plain number)
                if isinstance(old_name, str):
                    if old_name.startswith("0x"):
                        try:
                            old_name = int(old_name, 16)
                        except ValueError:
                            pass
                    elif old_name.isdigit():
                        old_name = int(old_name)


                # Get function info for validation
                func_info = self.binary_ops.get_function_info(old_name)
                if func_info:
                    bn.log_debug(f"Found function: {func_info}")
                    success = self.binary_ops.rename_function(old_name, new_name)
                    if success:
                        self._send_json_response(
                            {
                                "success": True,
                                "message": f"Successfully renamed function from {old_name} to {new_name}",
                                "function": func_info,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "error": "Failed to rename function",
                                "message": "The function was found but could not be renamed. This might be due to permissions or binary restrictions.",
                                "function": func_info,
                            },
                            500,
                        )
                else:
                    available_funcs = self.binary_ops.get_function_names(0, 10)
                    bn.log_error(f"Function not found: {old_name}")
                    self._send_json_response(
                        {
                            "error": "Function not found",
                            "requested": old_name,
                            "help": "Make sure the function exists. You can use either the function name or its address.",
                            "available_functions": available_funcs,
                        },
                        404,
                    )

            elif path == "/rename/data" or path == "/renameData":
                address = params.get("address")
                new_name = params.get("newName") or params.get("new_name")
                if not address or not new_name:
                    self._send_json_response({"error": "Missing parameters"}, 400)
                    return

                try:
                    address_int = (
                        int(address, 16) if isinstance(address, str) else int(address)
                    )
                    success = self.binary_ops.rename_data(address_int, new_name)
                    self._send_json_response({"success": success})
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/comment":
                if self.command == "GET":
                    address = params.get("address")
                    if not address:
                        self._send_json_response(
                            {
                                "error": "Missing address parameter",
                                "help": "Required parameter: address",
                                "received": params,
                            },
                            400,
                        )
                        return

                    try:
                        address_int = int(address, 16) if isinstance(address, str) else int(address)
                        comment = self.binary_ops.get_comment(address_int)
                        if comment is not None:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "address": hex(address_int),
                                    "comment": comment,
                                }
                            )
                        else:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "address": hex(address_int),
                                    "comment": None,
                                    "message": "No comment found at this address",
                                }
                            )
                    except ValueError:
                        self._send_json_response({"error": "Invalid address format"}, 400)
                elif self.command == "DELETE":
                    address = params.get("address")
                    if not address:
                        self._send_json_response(
                            {
                                "error": "Missing address parameter",
                                "help": "Required parameter: address",
                                "received": params,
                            },
                            400,
                        )
                        return

                    try:
                        address_int = int(address, 16) if isinstance(address, str) else int(address)
                        success = self.binary_ops.delete_comment(address_int)
                        if success:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "message": f"Successfully deleted comment at {hex(address_int)}",
                                }
                            )
                        else:
                            self._send_json_response(
                                {
                                    "error": "Failed to delete comment",
                                    "message": "The comment could not be deleted at the specified address.",
                                },
                                500,
                            )
                    except ValueError:
                        self._send_json_response({"error": "Invalid address format"}, 400)
                else:  # POST
                    address = params.get("address")
                    comment = params.get("comment")
                    if not address or comment is None:
                        self._send_json_response(
                            {
                                "error": "Missing parameters",
                                "help": "Required parameters: address and comment",
                                "received": params,
                            },
                            400,
                        )
                        return

                    try:
                        address_int = int(address, 16) if isinstance(address, str) else int(address)
                        success = self.binary_ops.set_comment(address_int, comment)
                        if success:
                            self._send_json_response(
                                {
                                    "success": True,
                                    "message": f"Successfully set comment at {hex(address_int)}",
                                    "comment": comment,
                                }
                            )
                        else:
                            self._send_json_response(
                                {
                                    "error": "Failed to set comment",
                                    "message": "The comment could not be set at the specified address.",
                                },
                                500,
                            )
                    except ValueError:
                        self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/comment/function":
                if self.command == "GET":
                    function_name = params.get("name") or params.get("functionName")
                    if not function_name:
                        self._send_json_response(
                            {
                                "error": "Missing function name parameter",
                                "help": "Required parameter: name (or functionName)",
                                "received": params,
                            },
                            400,
                        )
                        return

                    comment = self.binary_ops.get_function_comment(function_name)
                    if comment is not None:
                        self._send_json_response(
                            {
                                "success": True,
                                "function": function_name,
                                "comment": comment,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "success": True,
                                "function": function_name,
                                "comment": None,
                                "message": "No comment found for this function",
                            }
                        )
                elif self.command == "DELETE":
                    function_name = params.get("name") or params.get("functionName")
                    if not function_name:
                        self._send_json_response(
                            {
                                "error": "Missing function name parameter",
                                "help": "Required parameter: name (or functionName)",
                                "received": params,
                            },
                            400,
                        )
                        return

                    success = self.binary_ops.delete_function_comment(function_name)
                    if success:
                        self._send_json_response(
                            {
                                "success": True,
                                "message": f"Successfully deleted comment for function {function_name}",
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "error": "Failed to delete function comment",
                                "message": "The comment could not be deleted for the specified function.",
                            },
                            500,
                        )
                else:  # POST
                    function_name = params.get("name") or params.get("functionName")
                    comment = params.get("comment")
                    if not function_name or comment is None:
                        self._send_json_response(
                            {
                                "error": "Missing parameters",
                                "help": "Required parameters: name (or functionName) and comment",
                                "received": params,
                            },
                            400,
                        )
                        return

                    success = self.binary_ops.set_function_comment(function_name, comment)
                    if success:
                        self._send_json_response(
                            {
                                "success": True,
                                "message": f"Successfully set comment for function {function_name}",
                                "comment": comment,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "error": "Failed to set function comment",
                                "message": "The comment could not be set for the specified function.",
                            },
                            500,
                        )

            elif path == "/getComment":
                address = params.get("address")
                if not address:
                    self._send_json_response(
                        {
                            "error": "Missing address parameter",
                            "help": "Required parameter: address",
                            "received": params,
                        },
                        400,
                    )
                    return

                try:
                    address_int = int(address, 16) if isinstance(address, str) else int(address)
                    comment = self.binary_ops.get_comment(address_int)
                    if comment is not None:
                        self._send_json_response(
                            {
                                "success": True,
                                "address": hex(address_int),
                                "comment": comment,
                            }
                        )
                    else:
                        self._send_json_response(
                            {
                                "success": True,
                                "address": hex(address_int),
                                "comment": None,
                                "message": "No comment found at this address",
                            }
                        )
                except ValueError:
                    self._send_json_response({"error": "Invalid address format"}, 400)

            elif path == "/getFunctionComment":
                function_name = params.get("functionName") or params.get("name")
                if not function_name:
                    self._send_json_response(
                        {
                            "error": "Missing function name parameter",
                            "help": "Required parameter: name (or functionName)",
                            "received": params,
                        },
                        400,
                    )
                    return

                comment = self.binary_ops.get_function_comment(function_name)
                if comment is not None:
                    self._send_json_response(
                        {
                            "success": True,
                            "function": function_name,
                            "comment": comment,
                        }
                    )
                else:
                    self._send_json_response(
                        {
                            "success": True,
                            "function": function_name,
                            "comment": None,
                            "message": "No comment found for this function",
                        }
                    )

            elif path == "/patch" or path == "/patchBytes":
                address = params.get("address") or params.get("addr")
                data = params.get("data") or params.get("bytes")
                # Parse save_to_file parameter (default True for backwards compatibility)
                save_to_file_param = params.get("save_to_file", True)
                if isinstance(save_to_file_param, bool):
                    save_to_file = save_to_file_param
                else:
                    save_to_file = str(save_to_file_param).lower() not in ("false", "0", "no")
                
                if not address:
                    self._send_json_response(
                        {
                            "error": "Missing address parameter",
                            "help": "Required: address (hex like 0x401000 or decimal). Optional: data (hex string like '90 90' or '9090'), save_to_file (bool, default true; save_to_file is refused unless BN_MCP_ALLOW_SAVE=1 - the in-memory patch still applies)",
                            "received": params,
                        },
                        400,
                    )
                    return
                
                if not data:
                    self._send_json_response(
                        {
                            "error": "Missing data parameter",
                            "help": "Required: data (hex string like '90 90' or '9090', or list of integers)",
                            "received": params,
                        },
                        400,
                    )
                    return
                
                try:
                    # Parse data if it's a JSON string (for list format)
                    if isinstance(data, str):
                        try:
                            # Try to parse as JSON array
                            parsed = json.loads(data)
                            if isinstance(parsed, list):
                                data = parsed
                        except (json.JSONDecodeError, ValueError):
                            # Not JSON, treat as hex string
                            pass
                    
                    result = self.endpoints.patch_bytes(address, data, save_to_file)
                    self._send_json_response(result)
                except ValueError as ve:
                    self._send_json_response({"error": str(ve)}, 400)
                except Exception as e:
                    bn.log_error(f"Error handling patch request: {e}")
                    self._send_json_response({"error": str(e)}, 500)

            else:
                self._send_json_response({"error": "Not found"}, 404)
        except Exception as e:
            bn.log_error(f"Error handling POST request: {e}")
            self._send_json_response({"error": str(e)}, 500)


class _BindPolicyMixin:
    """Explicit socket bind policy: by default a second server cannot share the port of a listening one.

    Windows: no SO_REUSEADDR by default (http.server.HTTPServer sets allow_reuse_address=1), because on
    Windows it lets a second socket bind a port that another socket is listening on. SO_REUSEADDR only
    with BN_MCP_REUSEADDR=1; SO_EXCLUSIVEADDRUSE only with BN_MCP_EXCLUSIVE_BIND=1 (it takes precedence;
    the two options cannot be combined on Windows).
    Other systems (Linux, macOS): SO_REUSEADDR always. There it does not let a second socket listen on the
    same address and port (that needs SO_REUSEPORT, which is never set); it lets a restarted server bind
    while connections of the previous one are in TIME_WAIT. The server closes each connection first, so
    without it a Stop then Start would fail for up to a minute after any request.
    """

    allow_reuse_address = False
    allow_reuse_port = False
    _bn_cfg = None

    def server_bind(self):
        cfg = getattr(self, "_bn_cfg", None)
        exclusive = bool(getattr(cfg, "exclusive_bind", False))
        reuse = bool(getattr(cfg, "reuse_addr", False))
        if sys.platform != "win32":
            if hasattr(socket, "SO_REUSEADDR"):
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        elif exclusive and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            if reuse:
                bn.log_warn("BN_MCP_REUSEADDR ignored: BN_MCP_EXCLUSIVE_BIND=1 (SO_EXCLUSIVEADDRUSE) is set")
        elif reuse and hasattr(socket, "SO_REUSEADDR"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()


class _MCPHTTPServer(_BindPolicyMixin, ThreadingHTTPServer):
    """Threaded server: one daemon thread per connection; BN work is serialized by view locks.

    At most `_conn_slots` connections are served at once: a connection that arrives while all slots are taken is
    closed at once (before a thread starts), and the refusal is logged at most once a minute. Together with the
    handler's idle timeout (ServerConfig.request_timeout_s) this bounds the threads that processes on this computer
    can hold inside Binary Ninja by opening connections and sending nothing."""

    daemon_threads = True
    request_queue_size = 64
    allow_reuse_address = False
    _conn_slots = None
    _state = None

    def process_request(self, request, client_address):
        slots = self._conn_slots
        if slots is not None and not slots.acquire(blocking=False):
            st = self._state
            if st is not None:
                st.note_refusal("MAX_CONNECTIONS", "a connection: %d connections are open (the limit)"
                                % getattr(self, "_max_connections", 0))
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            if slots is not None:
                slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            if self._conn_slots is not None:
                self._conn_slots.release()


class _MCPSerialHTTPServer(_BindPolicyMixin, HTTPServer):
    """BN_MCP_THREADED=0: upstream's one-request-at-a-time server with the same bind policy."""

    request_queue_size = 64
    allow_reuse_address = False


class MCPServer:
    """HTTP server for Binary Ninja MCP plugin.

    Provides REST API endpoints for:
    - Binary analysis and manipulation
    - Function decompilation
    - Symbol renaming
    - Data inspection
    """

    def __init__(self, config: Config):
        self.config = config
        self.server = None
        self.thread = None
        self.state = None
        self.binary_ops = BinaryOperations(config.binary_ninja, server_config=config.server)

    def start(self):
        """Start the HTTP server in a background thread."""
        cfg = self.config.server
        server_address = (cfg.host, cfg.port)
        try:
            if getattr(self.binary_ops, "server_config", None) is None:
                self.binary_ops.server_config = cfg
        except Exception:
            pass
        state = _ServerState(cfg, getattr(self.binary_ops, "lock_mode", None))

        # Create handler with access to binary operations. `timeout` (socketserver.StreamRequestHandler) is the idle
        # limit of a connection: a client that sends nothing for that long is disconnected.
        handler_class = type(
            "MCPRequestHandlerWithOps",
            (MCPRequestHandler,),
            {"binary_ops": self.binary_ops, "server_state": state,
             "timeout": _pos_float(getattr(cfg, "request_timeout_s", 15.0), 15.0)},
        )

        server_cls = _MCPHTTPServer if state.threaded else _MCPSerialHTTPServer
        srv = server_cls(server_address, handler_class, bind_and_activate=False)
        srv._bn_cfg = cfg
        if state.threaded:
            try:
                max_conn = max(1, int(getattr(cfg, "max_connections", 256)))
            except (TypeError, ValueError):
                max_conn = 256
            srv._conn_slots = threading.BoundedSemaphore(max_conn)
            srv._max_connections = max_conn
            srv._state = state
        try:
            srv.request_queue_size = max(1, int(getattr(cfg, "request_queue_size", 64)))
        except (TypeError, ValueError):
            pass
        try:
            srv.server_bind()
            srv.server_activate()
        except Exception as e:
            try:
                srv.server_close()
            except Exception:
                pass
            bn.log_error(
                f"MCP server could NOT bind/listen on {cfg.host}:{cfg.port}: {e}. "
                "Another Binary Ninja instance or MCP server is probably listening on this port "
                "(close it first). Knobs: "
                f"BN_MCP_REUSEADDR={int(bool(getattr(cfg, 'reuse_addr', False)))}, "
                f"BN_MCP_EXCLUSIVE_BIND={int(bool(getattr(cfg, 'exclusive_bind', False)))}, "
                f"BN_MCP_THREADED={int(state.threaded)}, BN_MCP_LOCK_MODE={state.lock_mode}"
            )
            raise
        # The port is ours: only now write the per-run token (a server that failed to bind must never replace the
        # token of the server that holds the port).
        state.token_file = getattr(cfg, "token_file", "") or local_auth.token_file_path()
        state.token = local_auth.new_token()
        try:
            local_auth.write_token(state.token_file, state.token)
        except Exception as e:
            bn.log_error(f"MCP server: could not write the token file {state.token_file}: {e}. Clients cannot "
                         "authenticate (set BN_MCP_TOKEN_FILE to a writable path)")
        self.server = srv
        self.state = state
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        try:
            port = self.server.server_address[1]
        except Exception:
            port = cfg.port
        bn.log_info(
            f"Server started on {cfg.host}:{port} "
            f"(binja-agent-mcp {SERVER_VERSION}, threaded={state.threaded}, lock_mode={state.lock_mode}, "
            f"token {'required' if state.require_token else 'NOT required (BN_MCP_REQUIRE_TOKEN=0)'}, "
            f"token file {state.token_file})"
        )

    def stop(self):
        """Stop the HTTP server and clean up resources."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            if self.thread:
                self.thread.join()
            # Clear references so callers can reliably detect stopped state
            self.thread = None
            self.server = None
            st = self.state
            if st is not None:
                local_auth.remove_token(st.token_file, st.token)
                st.token = ""
            bn.log_info("Server stopped")
