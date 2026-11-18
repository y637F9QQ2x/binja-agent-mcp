# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp, upstream commit
# d8a2709df69ff475d6be6366c2eec733663b008b, 2025-12-16).
# Copyright (C) 2025 fosdickio, CX330Blake
# Copyright (C) 2026 Kazuma Matsumoto
# Modified by Kazuma Matsumoto between 2026-10-14 and 2026-11-18; see NOTICE.md and CHANGES-FROM-UPSTREAM.md.
# SPDX-License-Identifier: GPL-3.0-or-later
# This program comes with ABSOLUTELY NO WARRANTY; see the LICENSE file for details.
import os as _os
import sys as _sys
import traceback as _tb

# Install a very-early excepthook so any ImportError at module import time is captured.
def _bridge_excepthook(exc_type, exc, tb):
    # Print to stderr for interactive runs
    _tb.print_exception(exc_type, exc, tb, file=_sys.stderr)

_sys.excepthook = _bridge_excepthook

import functools
import inspect as _inspect
import json as _json
import re as _re
import threading as _threading
import time as _time
import urllib.parse as _urlparse
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import Field
import requests

try:
    import anyio
    import anyio.lowlevel
    import anyio.to_thread
except Exception:  # pragma: no cover - anyio ships with mcp; without it the tools stay synchronous
    anyio = None


def _cancelled_exc_class():
    try:
        return anyio.get_cancelled_exc_class()
    except Exception:  # pragma: no cover - anyio missing or no async library detected
        import asyncio
        return asyncio.CancelledError


def _install_respond_once_guard():
    """A client-cancelled request must never be answered twice (tested against mcp 1.27.2).

    With threaded tools the session reads notifications/cancelled while a call is still running (an MCP
    client sends one when it gives up on a call, for example after its tool timeout).
    RequestResponder.cancel() then sends the 'Request cancelled' error and marks the request completed.
    Two mcp paths then kill the whole server TaskGroup, so every later call goes unanswered:
      1. the worker thread returns and the server calls respond() again: `assert not self._completed`;
      2. the cancel lands while respond() is still sending (the stdout writer is busy): the CancelledError
         is raised OUTSIDE the server's own 'duplicate response suppressed' try, and
         RequestResponder.__exit__ ignores its cancel scope's decision to swallow it.
    The guard ends respond() quietly in exactly those cases (the request was cancelled by the client and
    cancel() already sent its error response); every other call, and every other cancellation (e.g. a
    transport close), goes through the original method unchanged. If mcp's internals differ, the guard
    is not installed (one line on stderr says so), and _threaded's checkpoint still routes a call cancelled
    while its thread ran into the server's own suppression branch. requirements.txt pins the tested mcp version.
    """
    try:
        from mcp.shared import session as _mcp_session
        responder = _mcp_session.RequestResponder
        orig = responder.respond
        if getattr(orig, "_bnmcp_respond_once", False):
            return
        if not (hasattr(responder, "cancel") and _inspect.iscoroutinefunction(orig)):
            raise AttributeError("RequestResponder.respond / cancel have an unexpected shape")
    except Exception as e:  # pragma: no cover - mcp layout changed; nothing to guard
        print("binja-agent-mcp bridge: the respond-once guard is not installed (%s: %s); a tool call that the MCP "
              "client cancels may stop the server. requirements.txt names the tested mcp version."
              % (type(e).__name__, e), file=_sys.stderr)
        return

    def _client_cancelled(r):
        try:
            return bool(r._completed) and bool(r.cancelled)
        except Exception:  # pragma: no cover
            return False

    @functools.wraps(orig)
    async def _respond_once(self, response):
        if _client_cancelled(self):
            return None   # responder.cancel() already sent the error response for this request id
        try:
            return await orig(self, response)
        except _cancelled_exc_class():
            if _client_cancelled(self):
                return None
            raise

    _respond_once._bnmcp_respond_once = True
    responder.respond = _respond_once


_install_respond_once_guard()


# --- binja-agent-mcp bridge --------------------------------------------------------------------------------
# * Every HTTP call goes through _req(): the query string is encoded by requests (identifiers containing
#   '+', '&', '#', spaces or non-ASCII arrive intact), an optional `binary` selector is added per call, and the
#   per-run token of the plugin (X-BN-MCP-Token, read from the token file) is sent with every request.
# * Tools run in worker threads (_threaded), so concurrent MCP calls do not queue on the event loop; the
#   plugin serializes Binary Ninja work itself (its view locks). HTTP concurrency is bounded per server by
#   _HttpGate: a server whose /status has no `server` block (the upstream plugin: single-threaded HTTPServer,
#   listen backlog 5) or reports server.threaded false gets ONE request at a time, so a burst can never
#   overflow its backlog and be refused (WinError 10061).
# * Only the tools of the selected tool set are registered (BN_MCP_TOOLSET / BN_MCP_TOOLS, see select_tools at
#   the end of this file), so an MCP client that loads every tool definition upfront pays only for those.
# * Every answer is at most MCP_OUTPUT_CAP_CHARS characters (see _emit and _cap_result).
# * Every tool call ends inside MCP_CALL_CAP_S (below): one call deadline bounds all of its waits, and the scanning
#   bn_* verbs carry a server time_budget_s, so a slow call answers with an explicit partial result or TIMEOUT.
# * HTTP goes only to the loopback server named by BN_MCP_URL (checked at start) and never through a proxy
#   (_session: trust_env is off, so HTTP_PROXY / HTTPS_PROXY / .netrc are ignored and the token never leaves the
#   loopback connection).
BRIDGE_CONTRACT = 'binja-agent-mcp/1'
BRIDGE_VERSION = '1.0.0'
DEFAULT_SERVER_URL = "http://127.0.0.1:9009"
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost")


def server_url_from_env(raw=None):
    """-> (base URL, error). BN_MCP_URL may name only http://127.0.0.1:<port> or http://localhost:<port> (the plugin
    binds 127.0.0.1 and accepts only those Host values; every request carries the token, which must not travel to
    another host). Anything else is an error, and the bridge then refuses to start."""
    raw = _os.environ.get("BN_MCP_URL") if raw is None else raw
    u = (raw or "").strip() or DEFAULT_SERVER_URL
    try:
        p = _urlparse.urlsplit(u)
        port = p.port
    except ValueError as e:
        return DEFAULT_SERVER_URL, "BN_MCP_URL=%r is not a valid URL (%s)" % (u, e)
    host = (p.hostname or "").lower()
    if (p.scheme != "http" or host not in _LOOPBACK_HOSTS or not port or p.username or p.password
            or p.path not in ("", "/") or p.query or p.fragment):
        return DEFAULT_SERVER_URL, ("BN_MCP_URL=%r: use http://127.0.0.1:<port> or http://localhost:<port> (the "
                                    "plugin listens on the loopback address only)" % u)
    return "http://%s:%d" % (host, port), ""


binja_server_url, URL_ERROR = server_url_from_env()


_SESSIONS = _threading.local()


def _session():
    """This thread's requests.Session. trust_env is off: no proxy from HTTP_PROXY / HTTPS_PROXY / ALL_PROXY (requests
    would otherwise send the token and every answer through a configured proxy), no .netrc credentials."""
    s = getattr(_SESSIONS, "s", None)
    if s is None:
        s = requests.Session()
        s.trust_env = False
        _SESSIONS.s = s
    return s

# Sent once per session in the MCP initialize result. Clients with on-demand tool loading use it to decide when to
# search this server's tools, so it names the task area and the main entry points only.
SERVER_INSTRUCTIONS = (
    "Reverse engineering with a running Binary Ninja: open a binary (bn_load_binary), find functions "
    "(search_functions_by_name), read code (bn_decompile), follow cross-references and calls (bn_xrefs, "
    "bn_callers, bn_callees), read types and data, and add names, comments and types. Tools that read a binary "
    "take an optional `binary` selector from list_binaries. Results come from static analysis; verify "
    "conclusions before acting on them."
)
mcp = FastMCP("binja-agent-mcp", instructions=SERVER_INSTRUCTIONS)

# Per-call time ceiling. The installer and the auto-setup write a 60-second tool timeout for this server where a
# client documents one in seconds (Cline, Roo Code: "timeout": 60; see plugin/utils/mcp_clients.py). So no wait of
# one tool call may outlast 60 s: every HTTP timeout is at most CALL_DEADLINE_S, a registered (threaded) tool call
# carries one deadline CALL_DEADLINE_S after it arrived (limiter queue, gate wait and its /status probe, retries,
# follow-up pages and every HTTP read count against it, see _run_bounded / _req), and the scanning bn_* verbs ask the
# server for a time_budget_s of X_SCAN_BUDGET_S (the plugin stops its Python-heavy loops there and answers with
# explicit truncated / warnings / complete=false). The budget leaves room for the server's lock_wait_s (20 s) before
# the verb starts. A call cut here answers TIMEOUT / 'Request failed: ...' in time and frees its tool thread and gate
# slot; Binary Ninja may still finish the request it already received. The requests timeout bounds each socket
# operation, not a whole response, so a server that sends its answer slowly can extend a call; the plugin writes each
# answer at once. If the per-server timeout is raised, MCP_CALL_CAP_S may be raised with it (never above it).
MCP_CALL_CAP_S = 60.0
CALL_DEADLINE_S = MCP_CALL_CAP_S - 5.0   # 5 s for the bridge's own work and the stdio reply
DEFAULT_TIMEOUT = 30.0                   # seconds; upstream used 5
LONG_TIMEOUT = CALL_DEADLINE_S           # former timeout=None (unbounded) calls
X_TIMEOUT = CALL_DEADLINE_S              # new bn_* verbs
X_LONG_TIMEOUT = CALL_DEADLINE_S         # scanning bn_* verbs
X_SCAN_BUDGET_S = 30.0                   # time_budget_s sent with the scanning verbs (_X_BUDGETED)
_MIN_ATTEMPT_S = 1.0                     # an attempt needs at least this much of the call deadline left

_CAND_SHOW = 20


# Tool threads get their OWN limiter. mcp's stdio transport reads stdin and writes stdout through anyio
# worker threads of the DEFAULT limiter (40 tokens, one held permanently by the blocking stdin readline);
# sharing it let 40 in-flight tool calls starve the transport, so no request, cancel or response moved
# until a tool thread finished. 40 tool calls may run at once; the HTTP gate below bounds the requests.
_TOOL_THREADS = 40
_TOOL_LIMITER = anyio.lowlevel.RunVar("bnmcp_tool_limiter") if anyio is not None else None


def _tool_limiter():
    """The tool-thread limiter of the running event loop (created on first use)."""
    lim = _TOOL_LIMITER.get(None)
    if lim is None:
        lim = anyio.CapacityLimiter(_TOOL_THREADS)
        _TOOL_LIMITER.set(lim)
    return lim


class _CallDeadline(requests.exceptions.Timeout):
    """The per-call deadline (CALL_DEADLINE_S) passed before a request could be sent; nothing was sent."""


_CALL = _threading.local()   # .deadline: the monotonic deadline of the tool call this thread is running


def _call_deadline():
    """The deadline of the tool call running on this thread, or None (a direct, unregistered call)."""
    return getattr(_CALL, "deadline", None)


def _deadline_error(where: str) -> _CallDeadline:
    return _CallDeadline(
        f"the bridge's per-call time limit ({CALL_DEADLINE_S:g} s, inside the MCP client's {MCP_CALL_CAP_S:g} s tool "
        f"timeout) was reached {where}; nothing was sent. Binary Ninja may still be busy with an earlier request: "
        f"retry later or narrow the request (offset/limit, max_lines, depth)")


def _run_bounded(deadline, fn, args, kw):
    """Run one tool body with its call deadline visible to _req (restored afterwards: worker threads are reused)."""
    prev = getattr(_CALL, "deadline", None)
    _CALL.deadline = deadline
    try:
        return fn(*args, **kw)
    finally:
        _CALL.deadline = prev


def _threaded(fn):
    """Async wrapper that runs the synchronous tool body in a worker thread (schema follows __wrapped__)."""
    @functools.wraps(fn)
    async def _w(*args, **kw):
        # The deadline starts when the call arrives, so a wait for a tool thread counts against the client's timeout.
        deadline = _time.monotonic() + CALL_DEADLINE_S
        result = await anyio.to_thread.run_sync(functools.partial(_run_bounded, deadline, fn, args, kw),
                                                limiter=_tool_limiter())
        # run_sync is shielded while the thread runs, so a client cancel is raised only at the next
        # checkpoint: it lands in the server's 'duplicate response suppressed' branch instead of a
        # second respond() (see _install_respond_once_guard).
        await anyio.lowlevel.checkpoint()
        return result
    return _w


# Every tool function, in definition order (name -> the plain synchronous function). Registration with the MCP
# server happens once, at the end of this file, for the tools of the selected tool set only (register_tools).
ALL_TOOLS = {}

# The `binary` parameter of every tool that works on a binary. Its syntax is described once, in the list_binaries
# description (and in SERVER_INSTRUCTIONS); each input schema carries only this short description. Empty: the
# globally selected binary.
Binary = Annotated[str, Field(description="selector from list_binaries")]


def _tool(fn):
    """Record `fn` as a tool and return the ORIGINAL synchronous function.

    The module-level name stays the plain function so tools that call each other (hexdump_data ->
    hexdump_address) and offline tests get a value, not a coroutine. register_tools() registers the
    selected tools; their registered callable is the async _threaded wrapper around _capped(fn).
    """
    ALL_TOOLS[fn.__name__] = fn
    return fn


def _active_filename() -> str:
    """Return the currently active filename as known by the server."""
    try:
        st = get_json("status")
        if isinstance(st, dict) and st.get("filename"):
            return str(st.get("filename"))
    except Exception:
        pass
    return "(none)"


# ---------- per-run token of the plugin's HTTP server ----------
# The plugin writes a random token to this file when its server starts and deletes it when the server stops;
# every request must carry it in the X-BN-MCP-Token header (unless the plugin runs with BN_MCP_REQUIRE_TOKEN=0).
# The same path rule is implemented in plugin/core/local_auth.py and bn_mcp_client.py (a test keeps them equal).
TOKEN_HEADER = "X-BN-MCP-Token"
_TOKEN_RE = _re.compile(r"^[A-Za-z0-9_-]{20,200}$")


def token_file_path() -> str:
    """BN_MCP_TOKEN_FILE, else the per-user default location of the token file."""
    explicit = (_os.environ.get("BN_MCP_TOKEN_FILE") or "").strip()
    if explicit:
        return _os.path.abspath(_os.path.expanduser(explicit))
    home = _os.path.expanduser("~")
    if _sys.platform == "win32":
        base = _os.environ.get("LOCALAPPDATA") or _os.path.join(home, "AppData", "Local")
    elif _sys.platform == "darwin":
        base = _os.path.join(home, "Library", "Application Support")
    else:
        base = _os.environ.get("XDG_STATE_HOME") or _os.path.join(home, ".local", "state")
    return _os.path.join(base, "binja-agent-mcp", "token")


def _read_token() -> str:
    """The current token, or '' when the file is missing or does not hold a token (read on every request: the
    plugin writes a new token each time its server starts)."""
    try:
        with open(token_file_path(), "r", encoding="utf-8") as f:
            t = f.read().strip()
    except (OSError, UnicodeDecodeError):
        return ""
    return t if _TOKEN_RE.match(t) else ""


def _auth_headers() -> dict:
    t = _read_token()
    return {TOKEN_HEADER: t} if t else {}


def _query(params: dict = None, binary: str = "") -> dict:
    """Query parameters for requests: None values dropped, dict/list values sent as JSON text,
    `binary` added only when non-empty."""
    out = {}
    for k, v in (params or {}).items():
        if v is None:
            continue
        if isinstance(v, (dict, list, tuple)):
            v = _json.dumps(v, ensure_ascii=False)
        out[k] = v
    b = str(binary or "").strip()
    if b:
        out["binary"] = b
    return out


# ---------- HTTP concurrency gate ----------
# This plugin runs a ThreadingHTTPServer (listen backlog 64, plugin/server/http_server.py _MCPHTTPServer) and
# reports `server.threaded` in /status. The upstream plugin is a single-threaded HTTPServer with socketserver's
# backlog of 5 and no `server` block: with threaded tools, a burst of concurrent calls overflows that backlog and
# the extra connections are REFUSED. Every request therefore takes a slot from the gate of
# its server URL; the gate classifies the server once (GET /status, unscoped) and again after a transport
# error, and grants ONE slot to a serial or unknown server and up to _GATE_THREADED_CAP to a threaded one.
_GATE_THREADED_CAP = 64          # = the plugin server's request_queue_size (its listen backlog)
# (connect, read) seconds. On Windows a refused loopback connect is reported only after the TCP retries (2.0 s in
# each of 3 tries on Windows 11 with Python 3.14, measured 2026-11-18); the 1 s connect timeout ends the probe first
# (requests ConnectTimeout, a ConnectionError: 'down'), and a call's deadline shortens both values (_probe_timeout).
_PROBE_TIMEOUT = (1.0, 10.0)
_RETRY_DELAYS = (0.5, 1.0, 2.0)  # backoff before each retry of a read-only request after a transport error

# Read-only GET routes (legacy names + the bn_* read verbs). Only these are retried after a transport error;
# every mutating route (patch, selectBinary, rename*/retype*/set*/make*/define*/declare*, formatValue, which
# writes a comment, and every POST) fails once, as before.
_READ_ONLY_GET = frozenset((
    "status", "binaries", "views", "platforms", "convertNumber", "methods", "functions", "entryPoints",
    "classes", "segments", "sections", "imports", "exports", "namespaces", "data", "localTypes", "searchTypes",
    "strings", "allStrings", "strings/filter", "hexdump", "hexdumpByName", "getDataDecl", "searchFunctions",
    "decompile", "assembly", "il", "functionAt", "getUserDefinedType", "comment", "comment/function",
    "getComment", "getFunctionComment", "getXrefsTo", "getXrefsToField", "getXrefsToStruct", "getXrefsToType",
    "getXrefsToEnum", "getXrefsToUnion", "getTypeInfo",
))
_MUTATING_X = frozenset(("x/batch", "x/closeBinary"))


def _read_only(method: str, endpoint: str) -> bool:
    if method != "GET":
        return False
    ep = str(endpoint).strip("/")
    return ep in _READ_ONLY_GET or (ep.startswith("x/") and ep not in _MUTATING_X)


def _probe_timeout(deadline):
    """_PROBE_TIMEOUT, each value cut to the time left before `deadline` (None: no deadline)."""
    if deadline is None:
        return _PROBE_TIMEOUT
    left = max(0.05, deadline - _time.monotonic())
    return (min(_PROBE_TIMEOUT[0], left), min(_PROBE_TIMEOUT[1], left))


class _ProbeCut(Exception):
    """The /status probe ran out of the call's deadline before it could classify the server (nothing is concluded)."""


def _probe_server(base: str, deadline=None):
    """Classify the server at `base` -> (state, cap): 'threaded' (cap <= 64), 'serial' (1) or 'down' (1). Raises
    _ProbeCut when a deadline shortened the probe's timeouts and the probe timed out."""
    timeout = _probe_timeout(deadline)
    try:
        r = _session().get(f"{base}/status", timeout=timeout, headers=_auth_headers())
    except requests.exceptions.ConnectionError as e:   # refused / reset / connect timeout: nothing usable listens
        if isinstance(e, requests.exceptions.Timeout) and timeout != _PROBE_TIMEOUT:
            raise _ProbeCut(str(e))
        return "down", 1
    except requests.exceptions.Timeout as e:     # a read timeout (busy single-threaded server)
        if timeout != _PROBE_TIMEOUT:
            raise _ProbeCut(str(e))
        return "serial", 1
    except Exception:                            # anything odd
        return "serial", 1
    try:
        data = r.json()
    except Exception:
        data = None
    srv = data.get("server") if isinstance(data, dict) else None
    if r.ok and isinstance(srv, dict) and srv.get("threaded") is True:
        cap = _GATE_THREADED_CAP
        q = srv.get("request_queue_size")
        if isinstance(q, int) and not isinstance(q, bool) and q >= 1:
            cap = min(cap, q)
        return "threaded", cap
    return "serial", 1


class _HttpGate(object):
    """Per-server-URL request slots. state: 'unprobed' -> (probe) -> 'serial' | 'threaded' | 'down'.

    * 'unprobed': the first acquirer probes /status (outside the lock); everyone else waits for the result.
    * 'serial' and 'down' grant one slot, 'threaded' grants `cap` slots. A registered tool call waits at most until
      its call deadline (then _CallDeadline: the client has given up, so nothing is sent); a direct call without a
      deadline waits unbounded, exactly like the old bridge's one-call-at-a-time event loop.
    * A transport error under the CURRENT classification (same generation) resets 'serial'/'threaded' to
      'unprobed' (Binary Ninja may have restarted with another plugin build); a request that gets ANY answer
      while 'down' resets 'down' to 'unprobed'. A failure while 'down' keeps 'down', so a dead server costs no
      extra probe per call.
    """

    def __init__(self, base: str):
        self.base = base
        self.cv = _threading.Condition()
        self.state = "unprobed"
        self.cap = 1
        self.inflight = 0
        self.gen = 0
        self.probing = False

    def acquire(self, deadline=None):
        """Block until a slot is free -> (state, generation) the slot was granted under. With a monotonic
        `deadline`, raise _CallDeadline (holding no slot) when it passes first; the /status probe a thread makes
        here is bounded by the same deadline (_probe_timeout), and a thread with less than _MIN_ATTEMPT_S left does
        not start a probe."""
        while True:
            with self.cv:
                while True:
                    if self.state == "unprobed":
                        if not self.probing:
                            if deadline is not None and deadline - _time.monotonic() < _MIN_ATTEMPT_S:
                                raise _deadline_error("before the server could be probed")
                            self.probing = True
                            break                 # this thread probes
                    elif self.inflight < self.cap:
                        self.inflight += 1
                        return self.state, self.gen
                    if deadline is None:
                        self.cv.wait()
                    else:
                        left = deadline - _time.monotonic()
                        if left <= 0:
                            raise _deadline_error("before a request slot to the server was free")
                        self.cv.wait(left)
            state, cap = "serial", 1
            cut = None
            try:
                state, cap = _probe_server(self.base, deadline)
            except _ProbeCut as e:
                cut = e
            except Exception:
                state, cap = "serial", 1
            finally:
                with self.cv:
                    if cut is None:
                        self.state, self.cap = state, max(1, int(cap))
                        self.gen += 1
                    self.probing = False          # a cut probe leaves 'unprobed': the next caller probes again
                    self.cv.notify_all()
            if cut is not None:
                raise _deadline_error("while the server was probed (%s)" % cut)

    def release(self, gen: int, outcome):
        """outcome: True = the server answered, False = transport error, None = neither (no state change)."""
        with self.cv:
            self.inflight = max(0, self.inflight - 1)
            if gen == self.gen and self.state != "unprobed":
                if outcome is False and self.state in ("serial", "threaded"):
                    self.state = "unprobed"
                elif outcome is True and self.state == "down":
                    self.state = "unprobed"
            self.cv.notify_all()


_GATES = {}
_GATES_LOCK = _threading.Lock()


def _gate_for(base: str) -> _HttpGate:
    with _GATES_LOCK:
        g = _GATES.get(base)
        if g is None:
            g = _GATES[base] = _HttpGate(base)
        return g


def _req(method: str, endpoint: str, params: dict = None, data=None, json_body=None,
         timeout: float | None = DEFAULT_TIMEOUT, binary: str = "", gate=None):
    """The single HTTP entry point. Returns the requests.Response (raises on transport errors).

    Every attempt holds a slot of the server's _HttpGate. A read-only GET that hits a transport error
    (refused / reset / aborted connection) is retried up to len(_RETRY_DELAYS) times while the re-probe still
    finds a server; the last transport error is raised otherwise, so callers report it exactly as before.
    Inside a registered tool call every wait (gate slot, retry backoff, the HTTP timeout itself) ends by the
    call deadline; _CallDeadline (a requests Timeout) is raised when too little of it is left to send.
    """
    base = binja_server_url
    url = f"{base}/{str(endpoint).lstrip('/')}"
    req_timeout = LONG_TIMEOUT if timeout is None else timeout
    kw = {"params": _query(params, binary), "timeout": req_timeout}
    hdrs = _auth_headers()
    if hdrs:
        kw["headers"] = hdrs
    if json_body is not None:
        kw["json"] = json_body
    elif data is not None:
        kw["data"] = data.encode("utf-8") if isinstance(data, str) else data
    m = str(method).upper()
    retryable = _read_only(m, endpoint)
    if gate is None:
        gate = _gate_for(base)
    deadline = _call_deadline()
    attempt, last_exc = 0, None
    while True:
        state, gen = gate.acquire(deadline)
        if last_exc is not None and state == "down":
            gate.release(gen, None)
            raise last_exc                        # the re-probe found no server: report the transport error
        if deadline is not None:
            left = deadline - _time.monotonic()
            if left < _MIN_ATTEMPT_S:
                gate.release(gen, None)
                raise _deadline_error("before the request could be sent")
            kw["timeout"] = min(req_timeout, left)
        try:
            response = _session().request(m, url, **kw)
        except requests.exceptions.ConnectionError as e:
            gate.release(gen, False)
            if not retryable or state == "down" or attempt >= len(_RETRY_DELAYS):
                raise
            if deadline is not None and _time.monotonic() + _RETRY_DELAYS[attempt] + _MIN_ATTEMPT_S > deadline:
                raise                             # no time left for the backoff and another attempt
            last_exc = e
            _time.sleep(_RETRY_DELAYS[attempt])
            attempt += 1
            continue
        except BaseException:
            gate.release(gen, None)
            raise
        gate.release(gen, True)
        response.encoding = "utf-8"
        return response


def _json_of(response):
    """get_json() semantics for one response: parsed JSON on 2xx; on 4xx/5xx the parsed error object
    (with `status` added) or {'error': 'Error <code>: <text>'}."""
    try:
        data = response.json()
    except Exception:
        data = None
    if response.ok:
        return data
    if isinstance(data, dict):
        if "error" not in data:
            data = {"error": str(data)}
        data.setdefault("status", response.status_code)
        return data
    text = (response.text or "").strip()
    return {"error": f"Error {response.status_code}: {text}"}


def safe_get(endpoint: str, params: dict = None, timeout: float | None = DEFAULT_TIMEOUT, binary: str = "") -> list:
    """
    Perform a GET request and return the response text split into lines (or one error line).
    """
    try:
        response = _req("GET", endpoint, params=params, timeout=timeout, binary=binary)
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]


def get_json(endpoint: str, params: dict = None, timeout: float | None = DEFAULT_TIMEOUT, binary: str = ""):
    """
    Perform a GET and return parsed JSON.
    - On 2xx: returns parsed JSON.
    - On 4xx/5xx: attempts to parse JSON body and return it; if not JSON, returns {'error': 'Error <code>: <text>'}.
    Transport errors return {'error': 'Request failed: ...'}.
    """
    try:
        return _json_of(_req("GET", endpoint, params=params, timeout=timeout, binary=binary))
    except Exception as e:
        return {"error": f"Request failed: {str(e)}"}


def get_text(endpoint: str, params: dict = None, timeout: float | None = DEFAULT_TIMEOUT, binary: str = "") -> str:
    """Perform a GET and return raw text (or an error string)."""
    try:
        response = _req("GET", endpoint, params=params, timeout=timeout, binary=binary)
        if response.ok:
            return response.text
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"


def safe_post(endpoint: str, data: dict | str, timeout: float | None = DEFAULT_TIMEOUT, binary: str = "") -> str:
    """POST form data (dict) or a raw text body (str); return the response text or an error string."""
    try:
        response = _req("POST", endpoint, data=data, timeout=timeout, binary=binary)
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"


def _post_json_or_get(endpoint: str, params: dict, binary: str = "", timeout: float | None = DEFAULT_TIMEOUT):
    """POST the parameters as a JSON body (long C text travels safely); an older server that has no
    POST form of the route answers 404/405, and the GET form is retried with the same parameters."""
    try:
        response = _req("POST", endpoint, json_body=dict(params), timeout=timeout, binary=binary)
    except Exception as e:
        return {"error": f"Request failed: {str(e)}"}
    if response.status_code in (404, 405):
        return get_json(endpoint, params, timeout=timeout, binary=binary)
    return _json_of(response)


# ---------- legacy formatting helpers ----------
def _cand_label(c) -> str:
    if isinstance(c, dict):
        name = c.get("name")
        if name is None:
            name = c.get("basename") or c.get("filename") or c.get("view_id") or "?"
        start = c.get("start")
        if start is None or start == "":
            label = str(name)
        else:
            if isinstance(start, int) and not isinstance(start, bool):
                start = hex(start)
            label = f"{name}@{start}"
        # a binary candidate carries its exact selector: the same file open twice has the same name@start
        sel = c.get("selector")
        if sel:
            label += f" (binary={sel})"
        return label
    return str(c)


def _cand_block(data: dict) -> str:
    """For an AMBIGUOUS answer: '\\nCandidates (...):' plus the candidate list (name@start, at most 20); else ''."""
    if data.get("error_code") == "AMBIGUOUS":
        cands = data.get("candidates") or []
        if isinstance(cands, list) and cands:
            shown = [f"  {_cand_label(c)}" for c in cands[:_CAND_SHOW]]
            more = [f"  ... ({len(cands) - _CAND_SHOW} more)"] if len(cands) > _CAND_SHOW else []
            return "\nCandidates (re-call with the address of the one you mean):\n" + "\n".join(shown + more)
    return ""


def _error_str(data: dict) -> str:
    """'Error: <error>' plus, for an AMBIGUOUS answer, the candidate list (name@start, at most 20)."""
    return f"Error: {data.get('error')}" + _cand_block(data)


def _trailer(data) -> str:
    """Visible truncation trailer for legacy text replies (the server adds truncated/next_line_offset)."""
    if not isinstance(data, dict) or not data.get("truncated"):
        return ""
    nxt = data.get("next_line_offset")
    if nxt is None:
        return (f"\n[TRUNCATED: returned {data.get('returned_lines')} of {data.get('total_lines')} lines; "
                f"a line was cut at max_chars; re-call with a larger max_chars]")
    return (f"\n[TRUNCATED: returned {data.get('returned_lines')} of {data.get('total_lines')} lines; "
            f"re-call with line_offset={nxt}]")


def _file_name(data, binary: str = "") -> str:
    """The binary that answered: the server's `_binary` echo, else the requested selector (marked
    unconfirmed), else the server's selected binary."""
    if isinstance(data, dict):
        echo = data.get("_binary")
        if isinstance(echo, dict) and echo.get("filename"):
            return str(echo.get("filename"))
    b = str(binary or "").strip()
    if b:
        return f"{b} (requested; the server did not confirm which binary answered)"
    return _active_filename()


def _file_line(data, binary: str = "") -> str:
    return f"File: {_file_name(data, binary)}\n\n"


def _lines_json(lines):
    try:
        obj = _json.loads("\n".join(lines or []))
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def _text_caps(params: dict, line_offset: int, max_lines: int, max_chars: int) -> dict:
    """Add the optional legacy text caps; zero/absent values are not sent (server default = uncapped)."""
    for k, v in (("line_offset", line_offset), ("max_lines", max_lines), ("max_chars", max_chars)):
        try:
            n = int(v or 0)
        except (TypeError, ValueError):
            n = 0
        if n > 0:
            params[k] = n
    return params


# =====================================================================================================
# Legacy tools (upstream names and behaviour; `binary` added as the last parameter where it applies)
# =====================================================================================================

@_tool
def list_methods(offset: int = 0, limit: int = 100, binary: Binary = "") -> list:
    """List function names, paged by offset and limit.
    See also: search_functions_by_name (find a function by part of its name)."""
    body = safe_get("methods", {"offset": offset, "limit": limit}, binary=binary)
    header = f"File: {_file_name(_lines_json(body), binary)}"
    return [header] + (body or [])

@_tool
def get_entry_points(binary: Binary = "") -> list:
    """List the entry point addresses and names of the binary."""
    data = get_json("entryPoints", binary=binary)
    if isinstance(data, dict) and data.get("error") and "entry_points" not in data:
        return [_error_str(data)]
    if not data or "entry_points" not in data:
        return ["Error: no response"]
    out: list[str] = []
    for ep in data.get("entry_points", []) or []:
        addr = ep.get("address")
        name = ep.get("name") or "(unknown)"
        out.append(f"{addr}\t{name}")
    return out

@_tool
def retype_variable(function_name: str, variable_name: str, type_str: str, binary: Binary = "") -> str:
    """Set the C type of a local variable. function_name: a function name or 0x address.
    See also: set_local_variable_type (same effect)."""
    data = get_json("retypeVariable", {"functionName": function_name, "variableName": variable_name, "type": type_str}, binary=binary)
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and "error" in data:
        return _error_str(data)
    if isinstance(data, dict) and "status" in data:
        return str(data["status"])
    return str(data)

@_tool
def rename_single_variable(function_name: str, variable_name: str, new_name: str, binary: Binary = "") -> str:
    """Rename one local variable of a function.
    See also: rename_multi_variables (several in one call)."""
    data = get_json("renameVariable", {"functionName": function_name, "variableName": variable_name, "newName": new_name}, binary=binary)
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and "error" in data:
        return _error_str(data)
    if isinstance(data, dict) and "status" in data:
        return str(data["status"])
    return str(data)

@_tool
def rename_multi_variables(function_identifier: str, mapping_json: str = "", pairs: str = "", renames_json: str = "", binary: Binary = "") -> str:
    """Rename several local variables of one function in one call. function_identifier: name or
    0x address. Give one of mapping_json (JSON object old -> new), renames_json (JSON list of
    {old, new}) or pairs ("old1:new1,old2:new2").
    See also: rename_single_variable (one variable)."""
    params: dict[str, object] = {}
    ident = (function_identifier or "").strip()
    if ident.lower().startswith("0x") or ident.isdigit():
        params["address"] = ident
    else:
        params["functionName"] = ident

    payload = None
    if renames_json:
        try:
            payload = _json.loads(renames_json)
        except Exception:
            return "Error: renames_json is not valid JSON"
        params["renames"] = payload
    elif mapping_json:
        try:
            payload = _json.loads(mapping_json)
        except Exception:
            return "Error: mapping_json is not valid JSON"
        params["mapping"] = payload
    elif pairs:
        params["pairs"] = pairs
    else:
        return "Error: provide mapping_json, renames_json, or pairs"

    data = get_json("renameVariables", params, binary=binary)
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("error"):
        return _error_str(data)
    try:
        total = data.get("total")
        renamed = data.get("renamed")
        return f"Batch rename: {renamed}/{total} applied"
    except Exception:
        return str(data)

@_tool
def define_types(c_code: str, binary: Binary = "") -> str:
    """Parse C type definitions and add them as user types; returns the type names.
    See also: declare_c_type (same effect)."""
    data = _post_json_or_get("defineTypes", {"cCode": c_code}, binary=binary)
    if not data:
        return "Error: no response"
    # Expect a list of defined type names or a dict; normalize to string
    if isinstance(data, dict) and "error" in data:
        return _error_str(data)
    if isinstance(data, (list, tuple)):
        return "Defined types: " + ", ".join(map(str, data))
    return str(data)

@_tool
def list_classes(offset: int = 0, limit: int = 100, binary: Binary = "") -> list:
    """List namespace and class names, paged by offset and limit."""
    return safe_get("classes", {"offset": offset, "limit": limit}, binary=binary)


@_tool
def hexdump_address(address: str, length: int = -1, binary: Binary = "") -> str:
    """Hex dump of memory at an address. length < 0: the size of the data defined there.
    See also: bn_bytes_at (up to 256 bytes, with patch information)."""
    params = {"address": address}
    if length is not None:
        params["length"] = length
    return get_text("hexdump", params, timeout=None, binary=binary)


@_tool
def hexdump_data(name_or_address: str, length: int = -1, binary: Binary = "") -> str:
    """Hex dump of a data symbol, by name or 0x address. length < 0: its defined size."""
    ident = (name_or_address or "").strip()
    if ident.startswith("0x"):
        return hexdump_address(ident, length, binary=binary)
    return get_text("hexdumpByName", {"name": ident, "length": length}, timeout=None, binary=binary)


@_tool
def get_data_decl(name_or_address: str, length: int = -1, binary: Binary = "") -> str:
    """C-like declaration and hex dump of a data symbol, by name or 0x address."""
    ident = (name_or_address or "").strip()
    params = {"name": ident} if not ident.startswith("0x") else {"address": ident}
    if length is not None:
        params["length"] = length
    data = get_json("getDataDecl", params, timeout=None, binary=binary)
    if not data:
        return "Error: no response"
    if "error" in data:
        return _error_str(data)
    decl = data.get("decl") or "(no declaration)"
    hexdump = data.get("hexdump") or ""
    addr = data.get("address", "")
    name = data.get("name", ident)
    return f"Declaration ({addr} {name}):\n{decl}\n\nHexdump:\n{hexdump}" + _trailer(data)


@_tool
def decompile_function(name: str, line_offset: int = 0, max_lines: int = 0, max_chars: int = 0, binary: Binary = "") -> str:
    """Decompile one function to HLIL text.
    line_offset / max_lines / max_chars page the text (0 = no limit); a paged reply ends with a
    [TRUNCATED: ...] line naming the next line_offset.
    See also: bn_decompile (paged by default, other IL levels, JSON output)."""
    params = _text_caps({"name": name}, line_offset, max_lines, max_chars)
    data = get_json("decompile", params, timeout=None, binary=binary)
    file_line = _file_line(data, binary)
    if not data:
        return file_line + "Error: no response"
    if "decompiled" in data:
        return file_line + str(data["decompiled"]) + _trailer(data)
    if "error" in data:
        return file_line + _error_str(data)
    return file_line + str(data)

@_tool
def get_il(name_or_address: str, view: str = "hlil", ssa: bool = False, line_offset: int = 0, max_lines: int = 0, max_chars: int = 0, binary: Binary = "") -> str:
    """Text of one function at IL level view = hlil | mlil | llil; ssa=true gives the SSA form (MLIL and
    LLIL only).
    line_offset / max_lines / max_chars page the text (0 = no limit); a paged reply ends with a
    [TRUNCATED: ...] line naming the next line_offset.
    See also: bn_decompile (the same levels, paged by default)."""
    ident = (name_or_address or "").strip()
    params = {"view": view, "ssa": int(bool(ssa))}
    if ident.lower().startswith("0x") or ident.isdigit():
        params["address"] = ident
    else:
        params["name"] = ident
    _text_caps(params, line_offset, max_lines, max_chars)
    data = get_json("il", params, timeout=None, binary=binary)
    file_line = _file_line(data, binary)
    if not data:
        return file_line + "Error: no response"
    if "il" in data:
        return file_line + str(data["il"]) + _trailer(data)
    if "error" in data:
        if data.get("error_code") == "AMBIGUOUS":
            return file_line + _error_str(data)
        return file_line + _json.dumps(data, indent=2, ensure_ascii=False)
    return file_line + str(data)

@_tool
def fetch_disassembly(name: str, line_offset: int = 0, max_lines: int = 0, max_chars: int = 0, binary: Binary = "") -> str:
    """Disassembly of one function.
    line_offset / max_lines / max_chars page the text (0 = no limit); a paged reply ends with a
    [TRUNCATED: ...] line naming the next line_offset.
    See also: bn_decompile with il=asm (the same, paged by default)."""
    params = _text_caps({"name": name}, line_offset, max_lines, max_chars)
    data = get_json("assembly", params, timeout=None, binary=binary)
    file_line = _file_line(data, binary)
    if not data:
        return file_line + "Error: no response"
    if "assembly" in data:
        return file_line + str(data["assembly"]) + _trailer(data)
    if "error" in data:
        return file_line + _error_str(data)
    return file_line + str(data)

@_tool
def rename_function(old_name: str, new_name: str, binary: Binary = "") -> str:
    """Rename a function. old_name: its current name or 0x address."""
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name}, binary=binary)


@_tool
def rename_data(address: str, new_name: str, binary: Binary = "") -> str:
    """Set the name of the data variable at an address."""
    return safe_post("renameData", {"address": address, "newName": new_name}, binary=binary)


@_tool
def set_comment(address: str, comment: str, binary: Binary = "") -> str:
    """Set the comment at an address."""
    return safe_post("comment", {"address": address, "comment": comment}, binary=binary)


@_tool
def set_function_comment(function_name: str, comment: str, binary: Binary = "") -> str:
    """Set the comment of a function."""
    return safe_post("comment/function", {"name": function_name, "comment": comment}, binary=binary)


@_tool
def get_comment(address: str, binary: Binary = "") -> str:
    """Read the comment at an address."""
    return (safe_get("comment", {"address": address}, binary=binary) or ["(no comment)"])[0]


@_tool
def get_function_comment(function_name: str, binary: Binary = "") -> str:
    """Read the comment of a function."""
    return (safe_get("comment/function", {"name": function_name}, binary=binary) or ["(no comment)"])[0]


@_tool
def list_segments(offset: int = 0, limit: int = 100, binary: Binary = "") -> list:
    """List memory segments, paged by offset and limit."""
    return safe_get("segments", {"offset": offset, "limit": limit}, binary=binary)


@_tool
def list_sections(offset: int = 0, limit: int = 100, binary: Binary = "") -> list:
    """List sections (start-end, size, name, semantics), paged by offset and limit."""
    data = get_json("sections", {"offset": offset, "limit": limit}, binary=binary)
    if not data or not isinstance(data, dict):
        return ["Error: no response"]
    if data.get("error"):
        return [_error_str(data)]
    sections = data.get("sections", []) or []
    out: list[str] = [f"File: {_file_name(data, binary)}"]
    for s in sections:
        try:
            start = s.get("start") or ""
            end = s.get("end") or ""
            size = s.get("size")
            name = s.get("name") or "(unnamed)"
            sem = s.get("semantics") or s.get("type") or ""
            tail = f"\t{sem}" if sem else ""
            out.append(f"{start}-{end}\t{size}\t{name}{tail}")
        except Exception:
            continue
    return out

@_tool
def list_imports(offset: int = 0, limit: int = 100, binary: Binary = "") -> list:
    """List imported symbols, paged by offset and limit."""
    return safe_get("imports", {"offset": offset, "limit": limit}, binary=binary)


@_tool
def list_strings(offset: int = 0, count: int = 100, binary: Binary = "") -> list:
    """List the strings found in the binary, paged by offset and count.
    See also: list_strings_filter (with a substring filter), list_all_strings (every page)."""
    return safe_get("strings", {"offset": offset, "limit": count}, timeout=None, binary=binary)

@_tool
def list_strings_filter(offset: int = 0, count: int = 100, filter: str = "", binary: Binary = "") -> list:
    """List the strings that contain `filter` (case-insensitive), paged by offset and count.
    See also: list_strings (no filter)."""
    return safe_get("strings/filter", {"offset": offset, "limit": count, "filter": filter}, timeout=None, binary=binary)

@_tool
def list_local_types(offset: int = 0, count: int = 200, include_libraries: bool = False, binary: Binary = "") -> list:
    """List local types, paged by offset and count; include_libraries adds type-library types."""
    return safe_get("localTypes", {"offset": offset, "limit": count, "includeLibraries": int(bool(include_libraries))}, timeout=None, binary=binary)

@_tool
def search_types(query: str, offset: int = 0, count: int = 200, include_libraries: bool = False, binary: Binary = "") -> list:
    """Find local types whose name or declaration contains `query`, paged by offset and count."""
    return safe_get("searchTypes", {"query": query, "offset": offset, "limit": count, "includeLibraries": int(bool(include_libraries))}, timeout=None, binary=binary)

@_tool
def list_all_strings(batch_size: int = 500, binary: Binary = "") -> list:
    """List every string by reading list_strings page by page. Stops at the bridge's
    output cap with an [INCOMPLETE: ...] line that names the list_strings call to continue with.
    See also: list_strings (one page)."""
    try:
        bs = int(batch_size)
    except (TypeError, ValueError):
        return [f"Error: batch_size must be an integer (got {batch_size!r})"]
    if bs < 1:
        return [f"Error: batch_size must be at least 1 (got {bs})"]
    results: list[str] = []
    offset = 0
    used, budget = 0, MCP_OUTPUT_CAP_CHARS - 400      # 400 characters stay free for the [INCOMPLETE ...] line
    while True:
        data = get_json("strings", {"offset": offset, "limit": bs}, timeout=None, binary=binary)
        items = data.get("strings") if isinstance(data, dict) else None
        if not isinstance(items, list):
            # an error answer or a reply without a 'strings' list: never a silent [] or a short list that looks whole
            is_err = isinstance(data, dict) and bool(data.get("error"))
            if is_err:
                err = str(data.get("error"))
                code = str(data.get("error_code") or "").strip()
                why, cands = (f"{code} {err}" if code and not err.startswith(code) else err), _cand_block(data)
            elif not data:
                why, cands = "no response", ""
            else:
                why, cands = "unexpected /strings reply (no 'strings' list): " + _json.dumps(data, default=str)[:300], ""
            if offset == 0:
                return [_error_str(data) if is_err else f"Error: {why}"]
            results.append(f"[INCOMPLETE: stopped at offset {offset} after {len(results)} string(s): {why}; continue with "
                           f"list_strings(offset={offset}, count={bs})]" + cands)
            break
        if not items:
            break
        for i, s in enumerate(items):
            addr = s.get("address")
            length = s.get("length")
            stype = s.get("type")
            value = s.get("value")
            line = f"{addr}\t{length}\t{stype}\t{value}"
            n = _clen(line) + 1
            if used + n > budget:
                # the output cap: stop here, never cut a line, and name the exact call that continues
                results.append(f"[INCOMPLETE: stopped at offset {offset + i} after {len(results)} string(s): the "
                               f"bridge's output cap of {MCP_OUTPUT_CAP_CHARS} characters; continue with "
                               f"list_strings(offset={offset + i}, count={bs})]")
                return results
            used += n
            results.append(line)
        if len(items) < bs:
            break
        offset += bs
    return results

@_tool
def list_exports(offset: int = 0, limit: int = 100, binary: Binary = "") -> list:
    """List exported functions and symbols, paged by offset and limit."""
    return safe_get("exports", {"offset": offset, "limit": limit}, binary=binary)


@_tool
def list_namespaces(offset: int = 0, limit: int = 100, binary: Binary = "") -> list:
    """List non-global namespaces, paged by offset and limit."""
    return safe_get("namespaces", {"offset": offset, "limit": limit}, binary=binary)


@_tool
def list_data_items(offset: int = 0, limit: int = 100, binary: Binary = "") -> list:
    """List defined data variables and their values, paged by offset and limit."""
    return safe_get("data", {"offset": offset, "limit": limit}, binary=binary)


@_tool
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100, binary: Binary = "") -> list:
    """Find functions whose name contains `query`, paged by offset and limit."""
    if not query:
        return ["Error: query string is required"]
    return safe_get(
        "searchFunctions", {"query": query, "offset": offset, "limit": limit}, binary=binary
    )


@_tool
def get_binary_status(binary: Binary = "") -> str:
    """The plugin's /status as JSON (loaded binary, file name, server version, lock mode,
    capabilities) plus this bridge's version and tool set.
    See also: bn_binary_info (one binary in detail)."""
    data = get_json("status", binary=binary)
    if isinstance(data, dict):
        out = dict(data)
    elif data is None:
        out = {"error": "no response"}
    else:
        out = {"error": "unexpected /status reply", "reply": data}
    out['bridge'] = {'contract': BRIDGE_CONTRACT, 'version': BRIDGE_VERSION, 'toolset': ACTIVE_TOOLSET,
                     'tools': len(ACTIVE_TOOLS), 'output_cap_chars': MCP_OUTPUT_CAP_CHARS}
    return _json.dumps(out, ensure_ascii=False, separators=(",", ":"))


@_tool
def list_binaries() -> list:
    """List the binaries open in Binary Ninja (UI tabs and binaries this server loaded) with their selectors.
    The `binary` parameter of the other tools takes view:<id> (valid while the binary stays open), a sha256
    or a unique sha256 prefix of 12 or more hex digits, an absolute path, a unique file name, or a unique file
    name without its extension. Empty: the globally selected binary (select_binary)."""
    data = get_json("binaries")
    if not data:
        return ["Error: no response"]
    if isinstance(data, dict) and data.get("error"):
        return [data.get("error")]
    items = data.get("binaries", [])
    out = []
    for it in items:
        vid = it.get("id")
        view_id = it.get("view_id")
        fn = it.get("filename")
        basename = it.get("basename") or ""
        selectors = it.get("selectors") or []
        active = it.get("active")
        label = basename or fn or "(unknown)"
        full = fn or "(no filename)"
        selector_text = ", ".join(str(s) for s in selectors if s)
        mark = " *active*" if active else ""
        view_part = f" view={view_id}" if view_id else ""
        out.append(f"{vid}. {label}{view_part}{mark}\n    path: {full}\n    selectors: {selector_text}")
    return out

@_tool
def select_binary(view: str) -> str:
    """Change the globally selected binary, used by tools called without `binary`. view: a selector
    from list_binaries, or an upstream-style ordinal, path or basename."""
    data = get_json("selectBinary", {"view": view})
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("error"):
        return _json.dumps(data, indent=2, ensure_ascii=False)
    sel = data.get("selected") if isinstance(data, dict) else None
    if sel:
        ordinal = sel.get("id") or "?"
        view_id = sel.get("view_id") or ""
        fn = sel.get("filename") or ""
        basename = sel.get("basename") or ""
        selectors = sel.get("selectors") or []
        selector_text = ", ".join(str(s) for s in selectors if s)
        display_name = basename or fn or "(unknown)"
        view_part = f" (view {view_id})" if view_id else ""
        path_part = f"\nFull path: {fn}" if fn else ""
        return f"Selected {ordinal}: {display_name}{view_part}{path_part}\nSelectors: {selector_text}"
    return str(data)


@_tool
def delete_comment(address: str, binary: Binary = "") -> str:
    """Delete the comment at an address."""
    return safe_post("comment", {"address": address, "_method": "DELETE"}, binary=binary)


@_tool
def delete_function_comment(function_name: str, binary: Binary = "") -> str:
    """Delete the comment of a function."""
    return safe_post("comment/function", {"name": function_name, "_method": "DELETE"}, binary=binary)

@_tool
def function_at(address: str, binary: Binary = "") -> str:
    """Name of the function that contains an address.
    See also: bn_resolve_entity (also accepts symbols; returns the section)."""
    return "\n".join(safe_get("functionAt", {"address": address}, binary=binary))

@_tool
def get_user_defined_type(type_name: str, binary: Binary = "") -> str:
    """Definition of a user-defined struct, enum, typedef or union.
    See also: get_type_info (more detail)."""
    return "\n".join(safe_get("getUserDefinedType", {"name": type_name}, binary=binary))

@_tool
def get_xrefs_to(address: str, binary: Binary = "") -> list:
    """All code and data references to an address (not paged).
    See also: bn_xrefs (paged)."""
    return safe_get("getXrefsTo", {"address": address}, binary=binary)

@_tool
def get_xrefs_to_field(struct_name: str, field_name: str, binary: Binary = "") -> list:
    """References to one field of a struct."""
    return safe_get("getXrefsToField", {"struct": struct_name, "field": field_name}, binary=binary)

@_tool
def get_xrefs_to_struct(struct_name: str, binary: Binary = "") -> list:
    """References to and uses of a struct type."""
    return safe_get("getXrefsToStruct", {"name": struct_name}, binary=binary)

@_tool
def get_xrefs_to_type(type_name: str, binary: Binary = "") -> list:
    """Uses of a type: global instances, code references to them, HLIL matches and functions whose
    signature mentions the type."""
    return safe_get("getXrefsToType", {"name": type_name}, binary=binary)

@_tool
def get_xrefs_to_enum(enum_name: str, binary: Binary = "") -> list:
    """Uses of an enum, found by its member values."""
    return safe_get("getXrefsToEnum", {"name": enum_name}, binary=binary)

@_tool
def get_xrefs_to_union(union_name: str, binary: Binary = "") -> list:
    """References to and uses of a union type."""
    return safe_get("getXrefsToUnion", {"name": union_name}, binary=binary)


@_tool
def format_value(address: str, text: str, size: int = 0, binary: Binary = "") -> list:
    """Convert a value and add a comment at an address that shows it as hex, decimal and C literal
    (this changes the comment at that address)."""
    return safe_get("formatValue", {"address": address, "text": text, "size": size}, timeout=None, binary=binary)

@_tool
def convert_number(text: str, size: int = 0) -> str:
    """Convert a number or string to hex, decimal, binary, little and big endian and C literals.
    Accepts 123, 0x7b, 7Bh, 0b1111011, 0o173, 'A' or "ABC" (escapes such as \\x41). Needs no binary."""
    data = get_json("convertNumber", {"text": text, "size": size}, timeout=None)
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("error"):
        return f"Error: {data['error']}"
    return _json.dumps(data, indent=2, ensure_ascii=False)

@_tool
def get_type_info(type_name: str, binary: Binary = "") -> str:
    """Declaration and details of a type by name: kind, struct members with offsets, enum values,
    typedef target.
    See also: get_user_defined_type (the definition only)."""
    data = get_json("getTypeInfo", {"name": type_name}, timeout=None, binary=binary)
    if not data:
        return "Error: no response"
    if "error" in data:
        return _error_str(data)
    return _json.dumps(data, indent=2, ensure_ascii=False)

@_tool
def set_function_prototype(name_or_address: str, prototype: str, binary: Binary = "") -> str:
    """Set the type of a function from a C prototype string. name_or_address: name or 0x address."""
    # POST (long prototypes travel in the body); an older server falls back to the GET form
    ident = (name_or_address or "").strip()
    params = {"prototype": prototype}
    # Choose param name based on identifier format
    if ident.lower().startswith("0x") or ident.isdigit():
        params["address"] = ident
    else:
        params["name"] = ident
    data = _post_json_or_get("setFunctionPrototype", params, binary=binary)
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and "error" in data:
        return _error_str(data)
    if isinstance(data, dict) and "status" in data:
        return f"Applied prototype at {data.get('address')}: {data.get('applied_type')}"
    return str(data)

@_tool
def make_function_at(address: str, platform: str = "", binary: Binary = "") -> str:
    """Create a function at an address (no change when one exists). platform: optional platform name
    from list_platforms, or "default"."""
    params = {"address": address}
    if platform:
        params["platform"] = platform
    data = get_json("makeFunctionAt", params, binary=binary)
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("error"):
        if data.get("error_code") == "AMBIGUOUS":
            return _error_str(data)
        return _json.dumps(data, indent=2, ensure_ascii=False)
    if isinstance(data, dict) and data.get("status") == "exists":
        return f"Function already exists at {data.get('address')}: {data.get('name')}"
    if isinstance(data, dict) and data.get("status") == "ok":
        return f"Created function at {data.get('address')}: {data.get('name')}"
    return str(data)

@_tool
def list_platforms() -> str:
    """List the platform names Binary Ninja knows. Needs no binary."""
    data = get_json("platforms")
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("error"):
        return _json.dumps(data, indent=2, ensure_ascii=False)
    plats = data.get("platforms") if isinstance(data, dict) else None
    if not plats:
        return "(no platforms)"
    return "\n".join(plats)

@_tool
def declare_c_type(c_declaration: str, binary: Binary = "") -> str:
    """Parse a C declaration (struct, union, enum, typedef or function type) and add or update the
    named user types.
    See also: define_types (same effect)."""
    data = _post_json_or_get("declareCType", {"declaration": c_declaration}, binary=binary)
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("defined_types"):
        names = ", ".join(data["defined_types"].keys())
        return f"Declared types ({data.get('count', 0)}): {names}"
    if isinstance(data, dict) and "error" in data:
        return _error_str(data)
    return str(data)

@_tool
def set_local_variable_type(function_address: str, variable_name: str, new_type: str, binary: Binary = "") -> str:
    """Set the C type of a local variable and report the applied type. function_address: 0x
    address or name.
    See also: retype_variable (same effect)."""
    data = get_json(
        "setLocalVariableType",
        {"functionAddress": function_address, "variableName": variable_name, "newType": new_type},
        binary=binary,
    )
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("status") == "ok":
        return f"Retyped {data.get('variable')} in {data.get('function')} to {data.get('applied_type')}"
    if isinstance(data, dict) and "error" in data:
        return _error_str(data)
    return str(data)

@_tool
def patch_bytes(address: str, data: str, save_to_file: bool = False, binary: Binary = "") -> str:
    """Write bytes into the analysis view in memory, for example data="90 90". The file on disk changes
    only with save_to_file=true AND a server started with BN_MCP_ALLOW_SAVE=1; otherwise the save is
    refused and reported, and the in-memory patch stays."""
    # Handle boolean type conversion (MCP may pass as string)
    if isinstance(save_to_file, str):
        save_to_file = save_to_file.lower() not in ("false", "0", "no")

    params = {"address": address, "data": data, "save_to_file": save_to_file}
    result = get_json("patch", params, binary=binary)
    if not result:
        return "Error: no response"

    status = result.get("status") if isinstance(result, dict) else None
    if status in ("ok", "partial"):
        orig = result.get("original_bytes", "")
        patched = result.get("patched_bytes", "")
        written = result.get("bytes_written", 0)
        requested = result.get("bytes_requested", 0)
        addr = result.get("address", address)
        saved = result.get("saved_to_file", False)
        saved_path = result.get("saved_path", "")
        save_error = result.get("save_error", "")
        codesign = result.get("codesign", {})
        warning = result.get("warning", "")

        msg = f"Patched {written}/{requested} bytes at {addr}"
        if status == "partial":
            msg += " (PARTIAL WRITE)"
        if warning:
            msg += f"\nWarning: {warning}"
        if orig:
            msg += f"\nOriginal: {orig}"
        if patched:
            msg += f"\nPatched:  {patched}"
        if saved:
            msg += f"\nSaved to file: {saved_path}"
        elif save_error:
            msg += f"\nWarning: File not saved - {save_error}"

        # Show codesign status for macOS
        if codesign:
            if codesign.get("success"):
                msg += f"\nCode signing: {codesign.get('message', 'Re-signed successfully')}"
            elif codesign.get("attempted"):
                msg += f"\nCode signing: Failed - {codesign.get('error', 'Unknown error')}"

        return msg
    if isinstance(result, dict) and "error" in result:
        return _error_str(result)
    return str(result)


# =====================================================================================================
# bn_* tools (contract binja-agent-mcp/1): structured JSON, explicit per-call binary, never guess.
# Each returns the server envelope as compact JSON: success {ok:true, verb, result, truncated, next_offset,
# warnings, limits, _binary}; failure {ok:false, verb?, error, error_code, candidates?, available?}.
# 409 AMBIGUOUS lists candidates (pick by address; never guess), 404 NOT_FOUND is an answer, 400 means a
# malformed argument or selector (path selectors must be ABSOLUTE), 503 BUSY means wait and retry.
# Check the `_binary` echo of every answer: it names the binary that actually answered.
# Every call ends within CALL_DEADLINE_S (inside the per-server tool timeout): error_code TIMEOUT means the bridge
# stopped waiting (Binary Ninja may still be working); the scanning verbs (_X_BUDGETED) stop at X_SCAN_BUDGET_S and
# say so in warnings ('time-budget') / truncated / complete=false.
# Every answer is emitted small-fields-first and is at most MCP_OUTPUT_CAP_CHARS characters; a bigger one is refused
# explicitly (error_code REFUSED_SIZE, bridge_refused true) instead of being cut or moved to a file (see _emit).
# =====================================================================================================

def _dump(obj) -> str:
    return _json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)


def _xparams(params: dict) -> dict:
    """bn_* query parameters: empty strings and None dropped (= the verb default), booleans as 1/0."""
    out = {}
    for k, v in (params or {}).items():
        if v is None:
            continue
        if isinstance(v, str) and v == "":
            continue
        if isinstance(v, bool):
            v = 1 if v else 0
        out[k] = v
    return out


# The verbs whose plugin default time budget exceeds X_SCAN_BUDGET_S (expert_ops.py _Ctx defaults: decompile 60,
# il_search 90, call_paths 60, sinks 60, undominated_sinks 60, handler_slice 120, batch 600 clamped to
# scan_time_budget_s 120). They are asked for X_SCAN_BUDGET_S so they answer inside the client's tool timeout; every
# other verb's default is already <= 30 s and is not overridden. The plugin clamps time_budget_s to
# [1, scan_time_budget_s] and reports a stopped scan (warnings 'time-budget', truncated / next_offset, complete=false,
# batch items 'not run'). A batch budget only stops STARTING items; each item runs on its own verb default.
_X_BUDGETED = frozenset(("x/decompile", "x/ilSearch", "x/callPaths", "x/sinks", "x/undominatedSinks",
                         "x/handlerSlice", "x/batch"))


# ---------- answer size: the MCP client's tool-result limit ----------
# Claude Code documents two limits for an MCP tool result (https://code.claude.com/docs/en/mcp, "MCP output limits
# and warnings", read 2026-11-18): a text result longer than 50,000 characters is saved to a file and replaced in
# the conversation by a reference to that file, and a result above MAX_MCP_OUTPUT_TOKENS (default 25,000 tokens)
# is handled the same way; its transcript viewer also warns above 10,000 tokens. An agent that gets a file reference
# loses the inline envelope, its `_binary` echo included. So every answer of this bridge is kept at or below
# MCP_OUTPUT_CAP_CHARS characters (default 48,000, under the 50,000-character limit; BN_MCP_MAX_OUTPUT_CHARS changes
# it, and a cap above 50,000 is declared to the client per tool, see _tool_meta). The character cap does not bound
# tokens: text that is dense in tokens (non-Latin strings, hex) can still pass 25,000 tokens under it. The default
# page sizes of the bn_* tools are far below the cap (bn_decompile: 150 lines or 12,000 characters).
#   * bn_* answers go through _emit(): small fields first (ok, verb, error*, _binary, truncated, next_offset,
#     warnings, limits, then the other small fields, `result` last; inside `result` the big text / list fields
#     (pack_text, text, items, ...) come last, smallest first; order only, no key or value changes). An answer above
#     the cap is never sent: _refuse_size() answers error_code REFUSED_SIZE (bridge_refused true, server_ok = the
#     server's ok) with the _binary echo, the result fields that fit (each intact, in result_partial) and the withheld
#     fields by name and size; a bn_batch first withholds its largest item answers (each replaced by a REFUSED_SIZE
#     item) and is refused only when that cannot fit.
#   * the upstream (text) tools go through _cap_result(): a longer answer is cut at a line boundary and ends with a
#     [TRUNCATED by the bridge: ...] line that says how to page the rest.
# Lengths are counted in UTF-16 code units (JavaScript's String.length).
_DEFAULT_OUTPUT_CAP_CHARS = 48000
_MIN_OUTPUT_CAP_CHARS = 8000
_MAX_OUTPUT_CAP_CHARS = 500000


def _output_cap_from_env() -> int:
    raw = (_os.environ.get("BN_MCP_MAX_OUTPUT_CHARS") or "").strip()
    if not raw:
        return _DEFAULT_OUTPUT_CAP_CHARS
    try:
        v = int(raw, 10)
    except ValueError:
        v = -1
    if not (_MIN_OUTPUT_CAP_CHARS <= v <= _MAX_OUTPUT_CAP_CHARS):
        print(f"binja-agent-mcp bridge: ignoring BN_MCP_MAX_OUTPUT_CHARS={raw!r} (use an integer from "
              f"{_MIN_OUTPUT_CAP_CHARS} to {_MAX_OUTPUT_CAP_CHARS}); using {_DEFAULT_OUTPUT_CAP_CHARS}", file=_sys.stderr)
        return _DEFAULT_OUTPUT_CAP_CHARS
    return v


MCP_OUTPUT_CAP_CHARS = _output_cap_from_env()
_BIG_FIELD_CHARS = 2000          # a field whose JSON is longer than this is emitted after the small ones
_BULK_KEYS = frozenset(("pack_text", "text", "lines", "diff", "diffs", "items"))   # always after the small fields
_ENVELOPE_HEAD = ("ok", "verb", "error_code", "error", "http_status", "bridge_refused", "size_chars", "cap_chars",
                  "server_ok", "server_error_code", "server_error", "_binary", "binary_defaulted", "truncated",
                  "next_offset", "warnings", "limits", "candidates", "available", "withheld_fields", "advice")
_SIZE_ADVICE = ("re-call with a smaller request: lower max_chars / max_lines or page with line_offset (bn_decompile, "
                "bn_handler_slice), lower limit and page with offset (bn_il_search, bn_sinks, bn_xrefs), "
                "lower depth / max_nodes / max_depth (bn_callers, bn_callees, bn_backward_slice), lower max_blocks "
                "(bn_cfg) or max_paths (bn_call_paths), or send fewer / smaller items (bn_batch)")
# Routes whose request has an effect on the server even when its answer is withheld.
_EFFECTFUL_ROUTES = frozenset(("x/closeBinary",))


def _clen(s: str) -> int:
    """Length in UTF-16 code units (JavaScript's String.length, which the MCP client's limits count)."""
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _jlen(obj) -> int:
    return _clen(_dump(obj))


def _clip_str(v, n: int) -> str:
    s = "" if v is None else str(v)
    return s if len(s) <= n else s[:n] + "...[clipped]"


def _small_first(d: dict, head=(), last=()) -> dict:
    """The same mapping re-ordered: the `head` keys (in that order), the other keys whose JSON is at most
    _BIG_FIELD_CHARS characters (original order), the bigger ones and the _BULK_KEYS (smallest first, ties in
    original order), then the `last` keys. Order only: no key or value changes."""
    out = {k: d[k] for k in head if k in d}
    small, big = [], []
    for i, (k, v) in enumerate(d.items()):
        if k in out or k in last:
            continue
        n = _jlen(v)
        (small if n <= _BIG_FIELD_CHARS and k not in _BULK_KEYS else big).append((n, i, k))
    for _n, _i, k in small:
        out[k] = d[k]
    for _n, _i, k in sorted(big):
        out[k] = d[k]
    for k in last:
        if k in d:
            out[k] = d[k]
    return out


def _order_env(env):
    """Small-first order of one bn_* envelope: the head keys, the other small keys, `result` last; a dict result is
    itself small-first, and so is every item envelope of a bn_batch result."""
    if not isinstance(env, dict):
        return env
    out = _small_first(env, _ENVELOPE_HEAD, ("result",))
    res = out.get("result")
    if isinstance(res, dict):
        items = res.get("items")
        if env.get("verb") == "batch" and isinstance(items, list):
            res = dict(res, items=[_order_env(it) for it in items])
        out["result"] = _small_first(res)
    return out


def _batch_withheld_item(it, i: int, size: int) -> dict:
    """The REFUSED_SIZE item that replaces one withheld bn_batch item answer (the server's own REFUSED_SIZE item shape)."""
    verb = it.get("verb") if isinstance(it, dict) else None
    idx = it.get("index") if isinstance(it, dict) else None
    if not isinstance(idx, int) or isinstance(idx, bool):
        idx = i
    return {"ok": False, "verb": _clip_str(verb or "?", 100), "index": idx, "error_code": "REFUSED_SIZE",
            "bridge_refused": True, "size_chars": size,
            "error": f"REFUSED_SIZE (bridge): this item's answer ({size} characters) was withheld to keep the bn_batch "
                     f"reply under the MCP output cap of {MCP_OUTPUT_CAP_CHARS} characters (nothing was cut); run it "
                     f"alone or with a smaller max_chars / max_lines / limit"}


def _fit_batch(env: dict):
    """An oversized successful bn_batch answer: replace item answers by REFUSED_SIZE items, largest first (ties: the
    later item), until the envelope fits; ok_count / not_run_or_refused are recounted like the server counts them and
    truncated is set. Returns the ordered envelope, or None when it cannot fit."""
    res = env.get("result")
    if env.get("ok") is not True or not isinstance(res, dict) or not isinstance(res.get("items"), list):
        return None
    items = list(res["items"])
    sizes = [_jlen(it) for it in items]
    withheld = []

    def shaped():
        if not withheld:
            return _order_env(env)
        r = dict(res, items=items)
        if "ok_count" in res:
            r["ok_count"] = sum(1 for x in items if isinstance(x, dict) and x.get("ok"))
        if "not_run_or_refused" in res:
            r["not_run_or_refused"] = sum(1 for x in items if isinstance(x, dict) and not x.get("ok")
                                          and x.get("error_code") in ("BUSY", "REFUSED_SIZE"))
        r["bridge_withheld_items"] = sorted(withheld)
        w = env.get("warnings")
        warns = list(w) if isinstance(w, list) else ([] if w is None else [w])
        warns.append(f"bridge: withheld {len(withheld)} bn_batch item answer(s) (result.bridge_withheld_items) as "
                     f"REFUSED_SIZE to keep the reply under {MCP_OUTPUT_CAP_CHARS} characters; run them alone or smaller")
        return _order_env(dict(env, result=r, truncated=True, warnings=warns))

    cur = shaped()
    for i in sorted(range(len(items)), key=lambda j: (-sizes[j], -j)):
        if _jlen(cur) <= MCP_OUTPUT_CAP_CHARS:
            break
        repl = _batch_withheld_item(items[i], i, sizes[i])
        if _jlen(repl) >= sizes[i]:
            break                       # the rest are smaller than their replacement: withholding cannot help
        items[i] = repl
        withheld.append(repl["index"])
        cur = shaped()
    return cur if _jlen(cur) <= MCP_OUTPUT_CAP_CHARS else None


def _refuse_size(env: dict, endpoint: str, size: int) -> str:
    """The explicit REFUSED_SIZE answer for an envelope whose JSON is above MCP_OUTPUT_CAP_CHARS: the server's
    metadata (the _binary echo included), every result field that fits (each intact, in result_partial, original
    order) and the rest by name and size in withheld_fields. Never a cut value; its own JSON always fits."""
    cap = MCP_OUTPUT_CAP_CHARS
    ep = str(endpoint).strip("/")
    verb = _clip_str(env.get("verb") or ep, 100)
    server_ok = env.get("ok")
    head = {"ok": False, "verb": verb, "error_code": "REFUSED_SIZE", "error": "", "bridge_refused": True,
            "size_chars": size, "cap_chars": cap, "server_ok": server_ok}
    if server_ok is not True:
        code = env.get("error_code")
        head["server_error_code"] = code if code is None else _clip_str(code, 100)
        head["server_error"] = _clip_str(env.get("error"), 2000)
        if "http_status" in env:
            st = env.get("http_status")
            head["http_status"] = st if isinstance(st, int) else _clip_str(st, 100)
    carried = {k: env[k] for k in ("_binary", "binary_defaulted", "truncated", "next_offset", "warnings", "limits",
                                   "candidates", "available") if k in env}
    consumed = set(("ok", "verb", "error_code", "error", "http_status", "result")) | set(carried)
    pool = []     # (size, order, where, key): the fields that may still fit, smallest first
    for i, (k, v) in enumerate(env.items()):
        if k not in consumed:
            pool.append((_jlen(v), i, "top", k))
    res = env.get("result")
    if isinstance(res, dict):
        for i, (k, v) in enumerate(res.items()):
            pool.append((_jlen(v), len(env) + i, "result", k))
    elif "result" in env:
        pool.append((_jlen(res), len(env), "whole", "result"))
    pool.sort()
    kept = set()

    def build(fields_ok=True):
        out = dict(head)
        out.update(carried)
        out["withheld_fields"] = [{"field": ("result." + k if w == "result" else k), "chars": n}
                                  for (n, _i, w, k) in pool if (w, k) not in kept]
        out["advice"] = _SIZE_ADVICE
        if fields_ok:
            for (_n, _i, w, k) in sorted((p for p in pool if p[2] == "top" and ("top", p[3]) in kept),
                                         key=lambda p: p[1]):
                out[k] = env[k]
            if ("whole", "result") in kept:
                out["result_partial"] = res
            elif isinstance(res, dict):
                out["result_partial"] = {k: res[k] for k in res if ("result", k) in kept}
        shown = ", ".join(x["field"] for x in out["withheld_fields"][:12])
        if len(out["withheld_fields"]) > 12:
            shown += ", ..."
        if server_ok is True:
            done = "The server completed the request"
            if ep in _EFFECTFUL_ROUTES:
                done += " and its effect HAS happened (this verb is not read-only)"
            done += "; only its answer is withheld. "
        else:
            done = "The server itself answered an error (server_error_code / server_error). "
        out["error"] = (f"REFUSED_SIZE (bridge): the {verb} answer is {size} characters of JSON, above the bridge's "
                        f"output cap of {cap} characters (BN_MCP_MAX_OUTPUT_CHARS). Nothing was cut: result_partial "
                        f"holds the result fields that fit, each intact; withheld: {shown or 'none'}. {done}"
                        f"Advice: {_SIZE_ADVICE}")
        return _order_env(out)

    budget = cap - 2000   # a margin under the cap (each build() is measured with its final error text)
    for (_n, _i, w, k) in pool:
        kept.add((w, k))
        if _jlen(build()) > budget:
            kept.discard((w, k))
    out = build()
    if _jlen(out) <= cap:
        return _dump(out)
    # Degrade (the carried metadata itself is too big): no fields, clipped warnings, then only the identity echo.
    kept.clear()
    w = carried.get("warnings")
    if isinstance(w, list):
        carried["warnings"] = [_clip_str(x, 300) for x in w[:10]] + (["... (warnings clipped)"] if len(w) > 10 else [])
    elif w is not None:
        carried["warnings"] = _clip_str(w, 2000)
    for k in ("candidates", "available", "limits"):
        carried.pop(k, None)
    out = build()
    if _jlen(out) <= cap:
        return _dump(out)
    echo = carried.get("_binary")
    minimal = dict(head, error=_clip_str(build(False)["error"], 4000), advice=_SIZE_ADVICE)
    if isinstance(echo, dict):
        minimal["_binary"] = {k: _clip_str(echo[k], 512) if isinstance(echo[k], str) else echo[k]
                              for k in ("view_id", "binary_id", "sha256", "sha256_source", "filename", "basename",
                                        "resolved_by", "analysis_state") if k in echo
                              and (echo[k] is None or isinstance(echo[k], (str, int, float, bool)))}
    return _dump(_order_env(minimal))


def _emit(env: dict, endpoint: str) -> str:
    """One bn_* envelope as compact JSON for the MCP client: small fields first, never above MCP_OUTPUT_CAP_CHARS."""
    try:
        s = _dump(_order_env(env))
        n = _clen(s)
        if n <= MCP_OUTPUT_CAP_CHARS:
            return s
        if str(endpoint).strip("/") == "x/batch":
            fit = _fit_batch(env)
            if fit is not None:
                return _dump(fit)
        return _refuse_size(env, endpoint, n)
    except Exception as e:  # pragma: no cover - a shaping bug must never lose or oversize the answer
        s = _dump(env)
        if _clen(s) <= MCP_OUTPUT_CAP_CHARS:
            return s
        out = {"ok": False, "verb": _clip_str(env.get("verb") or str(endpoint).strip("/"), 100),
               "error_code": "INTERNAL", "server_ok": env.get("ok"),
               "error": _clip_str(f"bridge: the {_clen(s)}-character answer could not be fitted under the MCP output "
                                  f"cap of {MCP_OUTPUT_CAP_CHARS} ({e!r}); re-call with a smaller request: "
                                  f"{_SIZE_ADVICE}", 3000)}
        echo = env.get("_binary")
        if isinstance(echo, dict) and _clen(_dump(echo)) <= 8000:
            out["_binary"] = echo
        return _dump(out)


def _x(method: str, endpoint: str, params: dict = None, body: dict = None, binary: str = "",
       timeout: float = X_TIMEOUT) -> str:
    q = _xparams(params)
    if str(endpoint).strip("/") in _X_BUDGETED and "time_budget_s" not in q:
        q["time_budget_s"] = X_SCAN_BUDGET_S
    try:
        response = _req(method, endpoint, params=q, json_body=body, timeout=timeout, binary=binary)
    except _CallDeadline as e:
        return _dump({"ok": False, "error": f"TIMEOUT: {e}", "error_code": "TIMEOUT"})
    except requests.exceptions.Timeout as e:
        return _dump({"ok": False, "error_code": "TIMEOUT",
                      "error": f"TIMEOUT: no answer within the bridge's per-call limit ({e}); Binary Ninja may still be "
                               f"working on it (holding its view lock): retry later with a narrower request"})
    except Exception as e:
        return _dump({"ok": False, "error": f"Request failed: {e}", "error_code": "UNREACHABLE"})
    try:
        data = response.json()
        parsed = True
    except Exception:
        data, parsed = None, False
    if isinstance(data, dict):
        if not response.ok:
            data.setdefault("ok", False)
            data.setdefault("http_status", response.status_code)
        return _emit(data, endpoint)
    if parsed and response.ok:
        return _emit({"ok": True, "result": data}, endpoint)
    text = (response.text or "").strip()
    return _dump({"ok": False, "error": f"Error {response.status_code}: {text[:2000]}",
                  "http_status": response.status_code})


def _need_binary(verb: str, binary: str):
    if str(binary or "").strip():
        return None
    return _dump({"ok": False, "verb": verb, "error_code": "BAD_ARGUMENT",
                  "error": f"{verb} requires binary=<view:<id> | sha256 | ABSOLUTE path | unique basename>"})


@_tool
def bn_server_info() -> str:
    """Server identity: version, contract, verb list, limits, sink presets and address syntax.
    Needs no binary."""
    return _x("GET", "x/serverInfo")


@_tool
def bn_binary_info(binary: Binary = "") -> str:
    """Identity and analysis state of one binary: sha256, file name, image base, architecture,
    platform and analysis_state.
    See also: get_binary_status (the server's /status)."""
    return _x("GET", "x/binaryInfo", {}, binary=binary)


@_tool
def bn_function_status(function: str, binary: Binary = "") -> str:
    """Analysis status of one function: skip reason, available IL levels, too_large, unresolved
    indirect branches. function: name or 0x start. A missing IL does not mean there is no code."""
    return _x("GET", "x/functionStatus", {"function": function}, binary=binary)


@_tool
def bn_decompile(function: str, il: str = "hlil", ssa: bool = False, render: str = "ast", line_offset: int = 0,
                 max_lines: int = 150, max_chars: int = 12000, binary: Binary = "") -> str:
    """Code of one function: il = hlil | mlil | llil | asm, ssa for the SSA form, render=ast for
    brace-structured HLIL. Paged by line_offset / max_lines / max_chars; truncated and next_offset say
    how to continue.
    See also: decompile_function, get_il, fetch_disassembly (text forms of the same)."""
    return _x("GET", "x/decompile", {"function": function, "il": il, "ssa": ssa, "render": render,
                                     "line_offset": line_offset, "max_lines": max_lines, "max_chars": max_chars},
              binary=binary)


@_tool
def bn_il_search(function: str = "", il: str = "mlil", operation: str = "", callee: str = "", constant: str = "",
                 text_regex: str = "", offset: int = 0, limit: int = 100, binary: Binary = "") -> str:
    """Search IL instructions of one function, or of the whole binary in address order, by operation,
    callee, constant or a regex over the instruction text. Paged by offset / limit; a whole-binary scan
    stops after 30 s and names the function to continue from."""
    return _x("GET", "x/ilSearch", {"function": function, "il": il, "operation": operation, "callee": callee,
                                    "constant": constant, "text_regex": text_regex, "offset": offset, "limit": limit},
              binary=binary, timeout=X_LONG_TIMEOUT)


@_tool
def bn_ssa_def(function: str, var: str, version: int = -1, at_va: str = "", binary: Binary = "") -> str:
    """MLIL SSA definition of a variable version (version=-1: the version live at at_va, or all)."""
    return _x("GET", "x/ssaDef", {"function": function, "var": var, "version": version, "at_va": at_va},
              binary=binary)


@_tool
def bn_ssa_uses(function: str, var: str, version: int = -1, at_va: str = "", binary: Binary = "") -> str:
    """MLIL SSA uses of a variable version (version=-1: the version live at at_va, or all)."""
    return _x("GET", "x/ssaUses", {"function": function, "var": var, "version": version, "at_va": at_va},
              binary=binary)


@_tool
def bn_backward_slice(call_site: str, arg_index: int, function: str = "", max_depth: int = 24,
                      max_nodes: int = 200, binary: Binary = "") -> str:
    """Where argument arg_index of the call at call_site comes from: a backward slice over MLIL SSA
    (phi nodes, one memory hop) with sources classed as param, const, global, call_return, memory
    or uninitialized, plus its blind spots."""
    return _x("GET", "x/backwardSlice", {"call_site": call_site, "arg_index": arg_index, "function": function,
                                         "max_depth": max_depth, "max_nodes": max_nodes},
              binary=binary, timeout=X_LONG_TIMEOUT)


@_tool
def bn_possible_values(va: str, function: str = "", operand: str = "", var: str = "", when: str = "before",
                       options: str = "", binary: Binary = "") -> str:
    """Value-set analysis (PossibleValueSet) of an operand or variable at an address, including
    UndeterminedValue. options: DataFlowQueryOption names. Over-complex functions are refused
    (REFUSED_COMPLEXITY)."""
    return _x("GET", "x/possibleValues", {"va": va, "function": function, "operand": operand, "var": var,
                                          "when": when, "options": options},
              binary=binary, timeout=X_LONG_TIMEOUT)


@_tool
def bn_branch_dependence(va: str, function: str = "", binary: Binary = "") -> str:
    """The conditional branches an instruction depends on (taken or not taken), with caveats."""
    return _x("GET", "x/branchDependence", {"va": va, "function": function}, binary=binary)


@_tool
def bn_cfg(function: str, level: str = "disasm", max_blocks: int = 200, binary: Binary = "") -> str:
    """Basic blocks and edges (type, back edge) of one function at level disasm | llil | mlil | hlil."""
    return _x("GET", "x/cfg", {"function": function, "level": level, "max_blocks": max_blocks}, binary=binary)


@_tool
def bn_dominators(function: str, block_va: str, kind: str = "dominators", level: str = "disasm",
                  binary: Binary = "") -> str:
    """Dominance facts for the block that contains block_va: dominators, post-dominators, strict and
    immediate forms, dominance frontiers or dominator-tree children (kind)."""
    return _x("GET", "x/dominators", {"function": function, "block_va": block_va, "kind": kind, "level": level},
              binary=binary)


@_tool
def bn_reachable(function: str, from_va: str, to_va: str, removed_edges: str = "", removed_out_of: str = "",
                 level: str = "disasm", binary: Binary = "") -> str:
    """Whether to_va is reachable from from_va inside one function, optionally with edges
    (removed_edges) or all out-edges of blocks (removed_out_of) removed."""
    return _x("GET", "x/reachable", {"function": function, "from_va": from_va, "to_va": to_va,
                                     "removed_edges": removed_edges, "removed_out_of": removed_out_of,
                                     "level": level}, binary=binary)


@_tool
def bn_callers(function: str, depth: int = 1, max_nodes: int = 100, binary: Binary = "") -> str:
    """Callers of a function up to depth 4, with how each edge was found."""
    return _x("GET", "x/callers", {"function": function, "depth": depth, "max_nodes": max_nodes}, binary=binary)


@_tool
def bn_callees(function: str, depth: int = 1, max_nodes: int = 100, include_imports: bool = True,
               binary: Binary = "") -> str:
    """Callees of a function up to depth 4; each edge is direct, tailcall, import or unresolved-indirect."""
    return _x("GET", "x/callees", {"function": function, "depth": depth, "max_nodes": max_nodes,
                                   "include_imports": include_imports}, binary=binary)


@_tool
def bn_call_paths(src: str, dst: str, max_hops: int = 6, max_paths: int = 20, binary: Binary = "") -> str:
    """Call paths from function src to a function or import dst, bounded by max_hops and max_paths. A
    search stopped by its 30 s budget says the list may be incomplete."""
    return _x("GET", "x/callPaths", {"src": src, "dst": dst, "max_hops": max_hops, "max_paths": max_paths},
              binary=binary)


@_tool
def bn_return_check(call_site: str, function: str = "", binary: Binary = "") -> str:
    """How the return value of the call at call_site is checked: compared-to-const,
    compared-to-nonconst, passed-through, used-unchecked or none, with the checks found."""
    return _x("GET", "x/returnCheck", {"call_site": call_site, "function": function}, binary=binary)


@_tool
def bn_sinks(preset: str = "", names: str = "", include_builtins: bool = True, offset: int = 0, limit: int = 100,
             binary: Binary = "") -> str:
    """Call sites of selected APIs: a preset (file, registry, security, process, load, object, service,
    memory, alloc, free, impersonation, identity) and/or comma-separated names, plus __builtin_* memory
    intrinsics. Paged by offset / limit."""
    return _x("GET", "x/sinks", {"preset": preset, "names": names, "include_builtins": include_builtins,
                                 "offset": offset, "limit": limit}, binary=binary, timeout=X_LONG_TIMEOUT)


@_tool
def bn_undominated_sinks(function: str, gate: str = "", preset: str = "", binary: Binary = "") -> str:
    """Calls to selected APIs in one function that are not dominated by a check call (default
    checks: impersonation and access-check APIs; gate replaces them). Candidates for review."""
    return _x("GET", "x/undominatedSinks", {"function": function, "gate": gate, "preset": preset}, binary=binary)


@_tool
def bn_stack_frame(function: str, binary: Binary = "") -> str:
    """Stack frame layout of one function: variables and parameters with offsets, sizes and types."""
    return _x("GET", "x/stackFrame", {"function": function}, binary=binary)


@_tool
def bn_handler_slice(function: str, depth: int = 3, max_callees: int = 40, max_chars: int = 16000,
                     include: str = "hlil,callers,types,strings,imports", disasm: bool = False,
                     binary: Binary = "") -> str:
    """One text pack for reviewing a function: its HLIL, callees to `depth`, callers, types, strings,
    imports and optional disassembly, with pack_sha256 and complete / sections_missing. max_chars
    bounds the pack text."""
    return _x("GET", "x/handlerSlice", {"function": function, "depth": depth, "max_callees": max_callees,
                                        "max_chars": max_chars, "include": include, "disasm": disasm},
              binary=binary, timeout=X_LONG_TIMEOUT)


@_tool
def bn_resolve_entity(ref: str, binary: Binary = "") -> str:
    """Resolve 0x<address>, symbol, symbol+0x<offset> or <module>!symbol to the exact address, its
    containing function and section.
    See also: function_at (the function name only)."""
    return _x("GET", "x/resolveEntity", {"ref": ref}, binary=binary)


@_tool
def bn_resolve_dispatch(function: str, call_site: str = "", max_targets: int = 64, options: str = "",
                        binary: Binary = "") -> str:
    """Possible targets of indirect calls (those bn_callees lists as unresolved-indirect), from
    value-set analysis of the call destination. call_site: one site, or empty for all such
    sites of the function."""
    return _x("GET", "x/resolveDispatch", {"function": function, "call_site": call_site,
                                           "max_targets": max_targets, "options": options},
              binary=binary, timeout=X_LONG_TIMEOUT)


@_tool
def bn_ndr_decode(va: str, count: int = 0, format: str = "oif", param_offset: int = 0, max_params: int = 32,
                  header: bool = False, length: int = 0, binary: Binary = "") -> str:
    """Decode a MIDL/NDR procedure format string at va (format oif or oi): direction, base type or type
    offset and attributes of each parameter. count gives the exact parameter count; without it up to
    max_params are read and flagged as unverified."""
    return _x("GET", "x/ndrDecode", {"va": va, "count": count, "format": format, "param_offset": param_offset,
                                     "max_params": max_params, "header": header, "length": length}, binary=binary)


@_tool
def bn_interproc_slice(call_site: str, arg_index: int, function: str = "", max_hops: int = 2, max_frames: int = 24,
                       gate: str = "", binary: Binary = "") -> str:
    """bn_backward_slice continued into callers across parameters, up to max_hops levels, with the
    check calls (gate) that dominate each caller's call."""
    return _x("GET", "x/interprocSlice", {"call_site": call_site, "arg_index": arg_index, "function": function,
                                          "max_hops": max_hops, "max_frames": max_frames, "gate": gate},
              binary=binary, timeout=X_LONG_TIMEOUT)


@_tool
def bn_bytes_at(va: str, length: int = 16, binary: Binary = "") -> str:
    """Raw bytes at an address (at most 256) and whether they differ from the file.
    See also: hexdump_address (longer dumps)."""
    return _x("GET", "x/bytesAt", {"va": va, "length": length}, binary=binary)


@_tool
def bn_xrefs(va: str, kind: str = "code", offset: int = 0, limit: int = 100, binary: Binary = "") -> str:
    """Code or data references to an address (kind code | data), paged by offset / limit.
    See also: get_xrefs_to (not paged), get_xrefs_to_type and get_xrefs_to_field (types, fields)."""
    return _x("GET", "x/xrefs", {"va": va, "kind": kind, "offset": offset, "limit": limit}, binary=binary)


@_tool
def bn_debug_info_status(binary: Binary = "") -> str:
    """Debug information present: parsers applied, the CodeView RSDS GUID and age of the PDB the
    image names, and the share of named functions."""
    return _x("GET", "x/debugInfoStatus", {}, binary=binary)


@_tool
def bn_uninit_reads(function: str, binary: Binary = "") -> str:
    """Reads of local variables that may be uninitialized in one function (candidates to verify)."""
    return _x("GET", "x/uninitReads", {"function": function}, binary=binary)


@_tool
def bn_compute(expr: str) -> str:
    """Exact integer arithmetic: 0x / 0o / 0b / decimal / 0n literals with + - * // % ** << >> & | ^ ~
    and parentheses. Needs no binary."""
    return _x("GET", "x/compute", {"expr": expr})


@_tool
def bn_batch(items_json: str, binary: Binary = "") -> str:
    """Run up to 25 read-only bn_* verbs against one binary in one request. items_json: a JSON list of
    {"verb": "decompile", "params": {...}}. Items not started within the 30 s batch budget answer
    'not run'; item answers too large for the output cap are withheld (REFUSED_SIZE)."""
    return _x("POST", "x/batch", body={"items": items_json}, binary=binary, timeout=X_LONG_TIMEOUT)


@_tool
def bn_close_binary(binary: Binary) -> str:
    """Close a binary that this server opened (bn_load_binary). Binaries opened in the Binary Ninja
    UI are refused."""
    err = _need_binary("close_binary", binary)
    if err:
        return err
    return _x("POST", "x/closeBinary", body={}, binary=binary)


# =====================================================================================================================
# bn_load_binary: ONE POST to /x/loadBinary (an idempotent verb). The body carries request_id (uuid4) and deadline_ms
# (this call's remaining budget minus 3000 ms); the POST is never retried and never falls back to GET.
# =====================================================================================================================
def _post_once(endpoint: str, params: dict = None) -> str:
    """ONE POST request; the body carries request_id and deadline_ms."""
    import uuid as _uuid
    body = dict(_xparams(params))
    body["request_id"] = _uuid.uuid4().hex
    d = _call_deadline()
    left_ms = (d - _time.monotonic()) * 1000.0 if d is not None else CALL_DEADLINE_S * 1000.0
    body["deadline_ms"] = int(max(1, left_ms - 3000))
    try:
        response = _req("POST", endpoint, json_body=body, timeout=X_TIMEOUT)
    except _CallDeadline as e:
        return _dump({"ok": False, "error": f"TIMEOUT: {e}", "error_code": "TIMEOUT"})
    except requests.exceptions.Timeout as e:
        return _dump({"ok": False, "error_code": "TIMEOUT",
                      "error": f"TIMEOUT: no answer within the bridge's per-call limit ({e}); Binary Ninja may still "
                               f"be working: check list_binaries (never re-send a POST blindly)"})
    except Exception as e:
        return _dump({"ok": False, "error": f"Request failed: {e}", "error_code": "UNREACHABLE"})
    try:
        data = response.json()
    except Exception:
        data = None
    if isinstance(data, dict):
        if not response.ok:
            data.setdefault("ok", False)
            data.setdefault("http_status", response.status_code)
        return _emit(data, endpoint)
    text = (response.text or "").strip()
    return _dump({"ok": False, "error": f"Error {response.status_code}: {text[:2000]}",
                  "http_status": response.status_code})


@_tool
def bn_load_binary(filepath: str) -> str:
    """Open a file through the Binary Ninja core API (no UI tab) and start its analysis. Returns at once
    with view_id, binary_id and analysis_state; poll bn_binary_info until analysis_state is
    IdleState. The same unchanged file returns the same view. filepath: absolute path, preferably
    of a copy."""
    return _post_once("x/loadBinary", {"filepath": filepath, "wait": False})


# =====================================================================================================================
# Output cap of the upstream (text) tools
# =====================================================================================================================
def _paging_advice(fn) -> str:
    try:
        params = _inspect.signature(fn).parameters
    except (TypeError, ValueError):
        params = {}
    if "line_offset" in params:
        return "Page with line_offset and max_lines, or use bn_decompile, which pages by default."
    if "offset" in params:
        size = "count" if "count" in params else "limit"
        return f"Page with offset and a smaller {size}."
    return "Narrow the request (a smaller length or a more specific name)."


def _cut_to(text: str, units: int) -> str:
    """The longest prefix of `text` that is at most `units` UTF-16 code units and ends at a line boundary
    (at a character boundary when the first line alone is too long)."""
    if units <= 0:
        return ""
    head = text[:units]
    while head and _clen(head) > units:
        head = head[:-max(1, (_clen(head) - units) // 2)]
    nl = head.rfind("\n")
    return head[:nl] if nl > 0 else head


def _cap_result(result, fn=None):
    """One tool result as the MCP client receives it, never above MCP_OUTPUT_CAP_CHARS characters.

    A list (the upstream line-list tools) becomes ONE text block, one item per line (the same text the client
    showed for the separate blocks, without the per-block overhead). A longer text is cut at a line boundary and
    ends with a [TRUNCATED by the bridge: ...] line that names the paging parameters of the tool. The bn_* tools
    are already inside the cap (_emit), so they pass unchanged."""
    if isinstance(result, (list, tuple)):
        text = "\n".join("" if x is None else str(x) for x in result)
    elif isinstance(result, str):
        text = result
    else:
        return result
    total = _clen(text)
    if total <= MCP_OUTPUT_CAP_CHARS:
        return text
    advice = _paging_advice(fn) if fn is not None else "Narrow the request."

    def marker(shown):
        return (f"\n[TRUNCATED by the bridge: the answer has {total} characters, above the output cap of "
                f"{MCP_OUTPUT_CAP_CHARS} (BN_MCP_MAX_OUTPUT_CHARS); shown: the first {shown}, cut at a line "
                f"boundary. {advice}]")
    room = MCP_OUTPUT_CAP_CHARS - _clen(marker(total))
    head = _cut_to(text, room)
    return head + marker(_clen(head))


def _capped(fn):
    """`fn` with its result passed through _cap_result (signature and docstring kept for the MCP schema)."""
    @functools.wraps(fn)
    def _w(*args, **kw):
        return _cap_result(fn(*args, **kw), fn)
    return _w


# =====================================================================================================================
# Tool sets: which tools the MCP client sees
# =====================================================================================================================
# core: the everyday reverse-engineering loop (open, find, read, follow, annotate) with ONE tool per job; where an
#   upstream tool and a bn_* tool overlap, core keeps the one whose output is paged or bounded by default.
# analysis: core plus the bn_* data-flow, control-flow and call-graph tools.
# upstream: exactly the 53 tool names of fosdickio/binary_ninja_mcp v1.1.0, for prompts written for upstream.
# full: every tool (upstream + bn_*), including the overlapping pairs.
CORE_TOOLS = (
    "list_binaries", "bn_load_binary", "bn_close_binary", "bn_binary_info",
    "search_functions_by_name", "list_methods", "get_entry_points", "list_imports", "list_exports",
    "list_strings_filter",
    "bn_decompile", "bn_xrefs", "bn_callers", "bn_callees", "bn_resolve_entity",
    "get_data_decl", "get_type_info", "declare_c_type",
    "rename_function", "rename_single_variable", "retype_variable", "rename_data",
    "set_comment", "set_function_comment", "set_function_prototype",
)
ANALYSIS_TOOLS = CORE_TOOLS + (
    "bn_function_status", "bn_il_search", "bn_ssa_def", "bn_ssa_uses", "bn_backward_slice", "bn_interproc_slice",
    "bn_possible_values", "bn_branch_dependence", "bn_cfg", "bn_dominators", "bn_reachable", "bn_call_paths",
    "bn_return_check", "bn_sinks", "bn_undominated_sinks", "bn_uninit_reads", "bn_stack_frame", "bn_handler_slice",
    "bn_resolve_dispatch", "bn_ndr_decode", "bn_debug_info_status", "bn_bytes_at", "bn_compute", "bn_batch",
    "bn_server_info",
)
UPSTREAM_TOOLS = (
    "list_methods", "get_entry_points", "retype_variable", "rename_single_variable", "rename_multi_variables",
    "define_types", "list_classes", "hexdump_address", "hexdump_data", "get_data_decl", "decompile_function",
    "get_il", "fetch_disassembly", "rename_function", "rename_data", "set_comment", "set_function_comment",
    "get_comment", "get_function_comment", "list_segments", "list_sections", "list_imports", "list_strings",
    "list_strings_filter", "list_local_types", "search_types", "list_all_strings", "list_exports",
    "list_namespaces", "list_data_items", "search_functions_by_name", "get_binary_status", "list_binaries",
    "select_binary", "delete_comment", "delete_function_comment", "function_at", "get_user_defined_type",
    "get_xrefs_to", "get_xrefs_to_field", "get_xrefs_to_struct", "get_xrefs_to_type", "get_xrefs_to_enum",
    "get_xrefs_to_union", "format_value", "convert_number", "get_type_info", "set_function_prototype",
    "make_function_at", "list_platforms", "declare_c_type", "set_local_variable_type", "patch_bytes",
)
TOOLSETS = {"core": CORE_TOOLS, "analysis": ANALYSIS_TOOLS, "upstream": UPSTREAM_TOOLS, "full": None}
DEFAULT_TOOLSET = "core"


def _toolset_names(key, all_names):
    members = TOOLSETS[key]
    return list(all_names) if members is None else [n for n in members if n in all_names]


def select_tools(env=None, all_names=None):
    """The tools to register -> (label, [names in definition order]).

    BN_MCP_TOOLSET = core (default) | analysis | upstream | full selects a tool set. BN_MCP_TOOLS is an explicit,
    comma-separated list instead: tool names and tool-set names (their tools are added), and `-name` to remove a
    tool, applied left to right (for example "core,bn_cfg" or "full,-patch_bytes"). Setting both, an unknown name or
    a list that selects nothing raises ValueError: the bridge then refuses to start rather than guess."""
    env = _os.environ if env is None else env
    all_names = list(ALL_TOOLS) if all_names is None else list(all_names)
    ts = (env.get("BN_MCP_TOOLSET") or "").strip().lower()
    tl = (env.get("BN_MCP_TOOLS") or "").strip()
    if ts and tl:
        raise ValueError("set BN_MCP_TOOLSET or BN_MCP_TOOLS, not both")
    if tl:
        wanted = set()
        for raw in tl.split(","):
            item = raw.strip()
            if not item:
                continue
            drop = item.startswith("-")
            name = item[1:].strip() if drop else item
            if not drop and name.lower() in TOOLSETS:
                wanted.update(_toolset_names(name.lower(), all_names))
            elif name in all_names:
                (wanted.discard if drop else wanted.add)(name)
            else:
                raise ValueError(f"BN_MCP_TOOLS: {item!r} is not a tool name or a tool set "
                                 f"({', '.join(TOOLSETS)})")
        if not wanted:
            raise ValueError("BN_MCP_TOOLS selects no tool")
        label = "custom"
    else:
        label = ts or DEFAULT_TOOLSET
        if label not in TOOLSETS:
            raise ValueError(f"BN_MCP_TOOLSET={ts!r}: use one of {', '.join(TOOLSETS)}")
        wanted = set(_toolset_names(label, all_names))
    return label, [n for n in all_names if n in wanted]


def _strip_schema_titles(schema):
    """Remove the pydantic-generated "title" annotations from a JSON schema (they repeat the parameter names and
    only cost context). Keys inside "properties" are parameter names and are kept, whatever they are called."""
    if isinstance(schema, dict):
        out = {}
        for k, v in schema.items():
            if k == "title" and isinstance(v, str):
                continue
            if k == "properties" and isinstance(v, dict):
                out[k] = {pk: _strip_schema_titles(pv) for pk, pv in v.items()}
            else:
                out[k] = _strip_schema_titles(v)
        return out
    if isinstance(schema, list):
        return [_strip_schema_titles(x) for x in schema]
    return schema


_SEE_ALSO = "See also:"
_NAME_TOKEN = _re.compile(r"\b[a-z][a-z0-9_]*\b")


def tool_description(name, registered):
    """The description sent for tool `name`: its docstring, minus every "See also:" line that names a tool which
    is not registered (so no description points at a tool the client does not have)."""
    doc = _inspect.cleandoc(ALL_TOOLS[name].__doc__ or "")
    keep = []
    for line in doc.split("\n"):
        if line.startswith(_SEE_ALSO):
            refs = [t for t in _NAME_TOKEN.findall(line) if t in ALL_TOOLS]
            if any(r not in registered for r in refs):
                continue
        keep.append(line)
    return "\n".join(keep)


# Claude Code saves a text result longer than 50,000 characters to a file unless the tool's tools/list entry
# declares _meta["anthropic/maxResultSizeChars"] (honoured up to 500,000; https://code.claude.com/docs/en/mcp, "Raise
# the limit for a specific tool", read 2026-11-18). With an output cap above that threshold, every tool declares the
# cap, so an answer the bridge lets through also stays in the conversation.
_CLIENT_FILE_THRESHOLD_CHARS = 50000
_RESULT_SIZE_META = "anthropic/maxResultSizeChars"


def _tool_meta():
    if MCP_OUTPUT_CAP_CHARS > _CLIENT_FILE_THRESHOLD_CHARS:
        return {_RESULT_SIZE_META: MCP_OUTPUT_CAP_CHARS}
    return None


def register_tools(names):
    """Register the named tools with the MCP server: unstructured output only (no outputSchema, and the answer
    is sent once, as text), descriptions without "See also" lines to unregistered tools, input schemas
    without generated titles, and _meta only when the output cap needs it (_tool_meta)."""
    registered = set(names)
    meta = _tool_meta()
    for name in names:
        fn = ALL_TOOLS[name]
        wrapped = _capped(fn)
        if anyio is not None:
            wrapped = _threaded(wrapped)
        mcp.tool(description=tool_description(name, registered), structured_output=False, meta=meta)(wrapped)
        try:
            t = mcp._tool_manager.get_tool(name)
            if t is not None:
                t.parameters = _strip_schema_titles(t.parameters)
        except Exception:  # pragma: no cover - a different mcp layout keeps the generated titles
            pass


def tool_definitions():
    """The tools/list result of this bridge as the MCP server serializes it (a list of JSON objects)."""
    import asyncio
    import mcp.types as _types
    tools = asyncio.run(mcp.list_tools())
    res = _types.ListToolsResult(tools=tools)
    return res.model_dump(by_alias=True, mode="json", exclude_none=True)["tools"]


def _list_tools_cli(as_json: bool) -> int:
    defs = tool_definitions()
    rows = [(d["name"], len(_dump(d))) for d in defs]
    total = len(_dump({"tools": defs}))
    if as_json:
        print(_dump({"toolset": ACTIVE_TOOLSET, "tools": len(rows), "tools_list_chars": total,
                     "per_tool_chars": dict(rows)}))
    else:
        for name, n in rows:
            print(f"{n:6d}  {name}")
        print(f"tool set {ACTIVE_TOOLSET}: {len(rows)} tools, tools/list result {total} characters "
              f"(about {round(total / 4)} tokens at 4 characters per token)")
    return 0


try:
    ACTIVE_TOOLSET, ACTIVE_TOOLS = select_tools()
    TOOLSET_ERROR = ""
except ValueError as _e:
    ACTIVE_TOOLSET, ACTIVE_TOOLS, TOOLSET_ERROR = "invalid", [], str(_e)
register_tools(ACTIVE_TOOLS)


# ---------- parent watchdog ----------
# Windows does not reliably deliver stdin EOF to a child whose MCP client was killed (another process may still hold
# the write end of the pipe), so FastMCP's stdio loop can block forever and orphaned bridges accumulate each time the
# client restarts. The watchdog exits the bridge when the client is gone.
# A Windows venv's Scripts\python.exe is a launcher that starts the base interpreter as a CHILD and waits for it: the
# bridge's parent is then the launcher, which outlives the client. When the parent's image is sys.executable while
# this process runs sys._base_executable (the launcher case), the parent's parent (the client) is watched as well.
_WATCH_INTERVAL_S = 5.0


def _watch_targets(ppid, parent_image, self_exe, base_exe, parent_of):
    """The process ids to watch: the parent, plus its own parent when the parent is the venv launcher of this
    interpreter (its image is sys.executable while this process runs another, base, executable). Pure function."""
    out = [ppid] if ppid else []

    def _norm(p):
        return _os.path.normcase(_os.path.abspath(p)) if p else ""
    if (ppid and parent_image and self_exe and base_exe and _norm(self_exe) != _norm(base_exe)
            and _norm(parent_image) == _norm(self_exe)):
        gp = parent_of(ppid)
        if gp and gp not in out and gp != _os.getpid():
            out.append(gp)
    return out


@functools.lru_cache(maxsize=1)
def _win32_process_api():
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    k32.GetExitCodeProcess.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = (wintypes.HANDLE,)
    k32.CloseHandle.restype = wintypes.BOOL
    k32.QueryFullProcessImageNameW.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                               ctypes.POINTER(wintypes.DWORD))
    k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    k32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_wchar * 260)]
    k32.Process32FirstW.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
    k32.Process32FirstW.restype = wintypes.BOOL
    k32.Process32NextW.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
    k32.Process32NextW.restype = wintypes.BOOL
    return ctypes, wintypes, k32, PROCESSENTRY32W


def _win32_parent_of(pid):
    """The parent process id of `pid` (Toolhelp32 snapshot), or None."""
    try:
        ctypes, wintypes, k32, entry_t = _win32_process_api()
        snap = k32.CreateToolhelp32Snapshot(0x2, 0)            # TH32CS_SNAPPROCESS
        if not snap or snap == wintypes.HANDLE(-1).value:
            return None
        try:
            e = entry_t()
            e.dwSize = ctypes.sizeof(e)
            ok = k32.Process32FirstW(snap, ctypes.byref(e))
            while ok:
                if int(e.th32ProcessID) == int(pid):
                    return int(e.th32ParentProcessID) or None
                ok = k32.Process32NextW(snap, ctypes.byref(e))
        finally:
            k32.CloseHandle(snap)
    except Exception:
        return None
    return None


def _win32_open(pid):
    """A handle to process `pid` with PROCESS_QUERY_LIMITED_INFORMATION, or None. Holding the handle keeps the
    process id from being reused for another process while it is watched."""
    try:
        _c, _w, k32, _e = _win32_process_api()
        return k32.OpenProcess(0x1000, False, int(pid)) or None
    except Exception:
        return None


def _win32_image(handle):
    try:
        ctypes, wintypes, k32, _e = _win32_process_api()
        buf = ctypes.create_unicode_buffer(32768)
        n = wintypes.DWORD(len(buf))
        if k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(n)):
            return buf.value
    except Exception:
        pass
    return ""


def _win32_alive(handle):
    try:
        ctypes, wintypes, k32, _e = _win32_process_api()
        code = wintypes.DWORD()
        return bool(k32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259   # STILL_ACTIVE
    except Exception:
        return False


def _install_parent_watchdog():
    """Exit the bridge (os._exit(0)) within _WATCH_INTERVAL_S of its MCP client process ending (see above)."""
    ppid = _os.getppid()
    if _sys.platform == "win32":
        handles = {}
        h = _win32_open(ppid)
        if h is None:
            return                                   # cannot watch: rely on stdin EOF alone
        handles[ppid] = h
        targets = _watch_targets(ppid, _win32_image(h), _sys.executable, getattr(_sys, "_base_executable", ""),
                                 _win32_parent_of)
        for pid in targets[1:]:
            gh = _win32_open(pid)
            if gh is not None:
                handles[pid] = gh

        def _gone():
            return [pid for pid, hh in handles.items() if not _win32_alive(hh)]
    else:
        def _gone():
            # POSIX: an orphaned child is reparented, so getppid() changes (to 1 or a subreaper)
            return [ppid] if _os.getppid() != ppid else []

    def _watch():
        while True:
            _time.sleep(_WATCH_INTERVAL_S)
            gone = _gone()
            if gone:
                print("binja-agent-mcp bridge: the MCP client process is gone (pid %s); exiting"
                      % ", ".join(str(p) for p in gone), file=_sys.stderr)
                _os._exit(0)

    _threading.Thread(target=_watch, daemon=True, name="parent-watchdog").start()


if __name__ == "__main__":
    # Important: write any logs to stderr to avoid corrupting MCP stdio JSON-RPC
    if "--list-tools" in _sys.argv[1:]:
        if TOOLSET_ERROR:
            print(f"binja-agent-mcp bridge: {TOOLSET_ERROR}", file=_sys.stderr)
            _sys.exit(2)
        _sys.exit(_list_tools_cli("--json" in _sys.argv[1:]))
    if TOOLSET_ERROR or URL_ERROR:
        print(f"binja-agent-mcp bridge: not starting: {TOOLSET_ERROR or URL_ERROR}", file=_sys.stderr)
        _sys.exit(2)
    print(f"binja-agent-mcp bridge {BRIDGE_VERSION}: tool set {ACTIVE_TOOLSET} ({len(ACTIVE_TOOLS)} tools), "
          f"output cap {MCP_OUTPUT_CAP_CHARS} characters, server {binja_server_url}", file=_sys.stderr)
    _install_parent_watchdog()
    try:
        mcp.run()
    except Exception as _e:
        # Print the traceback to stderr (the MCP client's log of this server)
        _bridge_excepthook(type(_e), _e, _e.__traceback__)
        raise
