# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""Per-request (thread-local) context for the Binary Ninja MCP HTTP server.

Added by binja-agent-mcp (not in upstream). Stdlib only, Python 3.10 grammar.

Why this exists
---------------
Upstream holds ONE global "current view"; every verb reads it. With a threaded
server and several concurrent clients, a sibling's select_binary would silently
swap the binary under a request. The server therefore resolves the binary for
each request (the optional ``binary`` parameter) and enters ``scope(view, ...)``
for the duration of that request. ``BinaryOperations._current_view`` consults
``override_view()`` first, so all existing code paths become request-scoped
without per-site edits; outside a scope the global selection is used as before.

The context also carries per-request notes:
  * ambiguity - the last AmbiguousError raised while resolving a name, so the
    HTTP layer can turn a legacy error response into a 409 with candidates;
  * warnings  - short, de-duplicated strings (cap 20) surfaced in JSON replies.

Error classes carry a machine-readable ``code`` and an HTTP status:
  BAD_ARGUMENT 400, POLICY 403, NOT_FOUND 404, AMBIGUOUS 409, GONE 410,
  REFUSED_SIZE 413, NO_IL / REFUSED_COMPLEXITY 422,
  INTERNAL 500, UNSUPPORTED_API 501, BUSY 503.
"""

import threading
from contextlib import contextmanager


class _Unset:
    """Sentinel: no request scope is active (use the global selection)."""

    __slots__ = ()

    def __repr__(self):
        return "UNSET"

    def __bool__(self):
        return False


UNSET = _Unset()

_WARN_CAP = 20
_CAND_CAP = 50
_MSG_CAND_CAP = 10

_state = threading.local()


def _get(name, default):
    return getattr(_state, name, default)


def _jsonable(v):
    """Best-effort conversion of a candidate/extra value into JSON-safe data."""
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, dict):
        return {str(k): _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set, frozenset)):
        return [_jsonable(x) for x in v]
    return str(v)


def _norm_candidate(c):
    if isinstance(c, dict):
        out = {}
        for k, v in c.items():
            if k == "start" and isinstance(v, int) and not isinstance(v, bool):
                out["start"] = hex(v)
            else:
                out[str(k)] = _jsonable(v)
        return out
    return _jsonable(c)


def _cand_label(c):
    if isinstance(c, dict):
        name = c.get("name")
        if name is None:
            name = c.get("filename") or c.get("view_id") or "?"
        start = c.get("start")
        if start is None or start == "":
            return str(name)
        if isinstance(start, int) and not isinstance(start, bool):
            start = hex(start)
        return "%s@%s" % (name, start)
    return str(c)


class ApiError(Exception):
    """An error with a machine-readable code and an HTTP status."""

    def __init__(self, code, message, http_status=400, extra=None):
        super().__init__(str(message))
        self.code = str(code)
        self.message = str(message)
        try:
            self.http_status = int(http_status)
        except (TypeError, ValueError):
            self.http_status = 500
        self.extra = dict(extra) if isinstance(extra, dict) else {}

    def __str__(self):
        return self.message

    def payload(self):
        """JSON body for this error: {error, error_code, **extra}."""
        out = {"error": self.message, "error_code": self.code}
        for k, v in self.extra.items():
            if k not in out:
                out[k] = _jsonable(v)
        return out


class AmbiguousError(ApiError):
    """More than one entity matches an identifier; never guess (409)."""

    def __init__(self, what, ident, candidates):
        cands = [_norm_candidate(c) for c in list(candidates or [])]
        n = len(cands)
        shown = "; ".join(_cand_label(c) for c in cands[:_MSG_CAND_CAP])
        more = "; ... (%d more)" % (n - _MSG_CAND_CAP) if n > _MSG_CAND_CAP else ""
        msg = "AMBIGUOUS: %d %s match %s: %s%s" % (n, what, ident, shown, more)
        super().__init__("AMBIGUOUS", msg, 409, {"candidates": cands[:_CAND_CAP]})
        self.what = str(what)
        self.ident = ident
        self.candidates = cands


class NotFoundError(ApiError):
    """Nothing matches an identifier (404); ``available`` lists what exists."""

    def __init__(self, what, ident, available=None):
        extra = {}
        if available is not None:
            extra["available"] = available
        super().__init__("NOT_FOUND", "NOT_FOUND: no %s matches %s" % (what, ident), 404, extra)
        self.what = str(what)
        self.ident = ident


class GoneError(ApiError):
    """The target is closing or was closed while the request waited (410)."""

    def __init__(self, what, ident):
        super().__init__("GONE", "GONE: %s %s is closing or was closed" % (what, ident), 410)
        self.what = str(what)
        self.ident = ident


@contextmanager
def scope(view, info, defaulted=False):
    """Run the body with ``view`` as the request's binary.

    Saves the previous (view, info, defaulted, ambiguity, warnings), CLEARS the
    ambiguity and warnings on entry, and restores everything on exit (nesting
    is safe). ``view`` may be None (a legacy request with nothing selected).
    """
    prev = (
        _get("view", UNSET),
        _get("info", None),
        _get("defaulted", False),
        _get("ambiguity", None),
        _get("warnings", None),
    )
    _state.view = view
    _state.info = info
    _state.defaulted = bool(defaulted)
    _state.ambiguity = None
    _state.warnings = []
    try:
        yield
    finally:
        _state.view, _state.info, _state.defaulted, _state.ambiguity, _state.warnings = prev


def override_view():
    """The request-scoped view, or UNSET outside a scope."""
    return _get("view", UNSET)


def info():
    """The request's binary description (the `_binary` echo), or None."""
    return _get("info", None)


def defaulted():
    """True when the request fell back to the global selection with >1 view open."""
    return bool(_get("defaulted", False))


def note_ambiguity(err):
    _state.ambiguity = err


def ambiguity():
    return _get("ambiguity", None)


def warn(msg):
    lst = _get("warnings", None)
    if lst is None:
        lst = []
        _state.warnings = lst
    s = str(msg)[:500]
    if s in lst or len(lst) >= _WARN_CAP:
        return
    lst.append(s)


def warnings():
    lst = _get("warnings", None)
    return list(lst) if lst else []


def reset_notes():
    """Clear ambiguity and warnings (e.g. between the items of a batch)."""
    _state.ambiguity = None
    _state.warnings = []
