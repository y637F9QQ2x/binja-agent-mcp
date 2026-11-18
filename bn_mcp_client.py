#!/usr/bin/env python3
# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""bn_mcp_client.py - a command-line client of the binja-agent-mcp plugin's HTTP API (standard library only).

PURPOSE
  Two jobs for scripts and CI, without an MCP client:
    caps  Is a binja-agent-mcp server reachable, and which version, contract and capabilities does it report?
    pack  Write one function's context pack ("# BN-PACK v1", GET /x/handlerSlice) to a file, ONLY after checking it:
          the envelope is ok, sha256(pack_text) == pack_sha256, the _binary echo names the requested binary
          (resolved_by explicit), analysis_state is IdleState, the slice is complete, no byte in the slice is
          modified, and the view's sha256 was computed from the unchanged file. Any other answer writes nothing.
  caps and pack never start Binary Ninja and never change a view (/status and /x/handlerSlice are read-only).

CLI (python bn_mcp_client.py <sub> ...)
  caps [--strict] [--url U]
  pack --binary SEL --function FN --out PATH [--overwrite] [--depth 3] [--max-callees 40] [--max-chars 120000]
       [--include hlil,callers,types,strings,imports] [--disasm 0|1] [--timeout 600] [--busy-retries 30]
       [--busy-sleep 10] [--url U]
  Base URL: --url, else the BN_MCP_URL environment variable, else http://127.0.0.1:9009; only
  http://127.0.0.1:<port> and http://localhost:<port> are accepted (usage error otherwise). Connect timeout 5 s; read
  timeout 30 s for caps and --timeout for pack. Every request carries the server's per-run token (X-BN-MCP-Token),
  read from BN_MCP_TOKEN_FILE or the default per-user token file (see README.md).
  A SEL that contains a path separator is made ABSOLUTE against the current directory before it is sent and before
  the echo is compared. --out is resolved the same way; its directory is created when missing. An existing --out
  is replaced only with --overwrite; a directory, a link or a reparse point at --out is refused (exit 4) before any
  request is made. A 503 BUSY answer is retried up to --busy-retries times, --busy-sleep seconds apart.

ECHO RULE (echo_ok)
  _binary.resolved_by == 'explicit' AND
    SEL is a path        -> the normalized absolute SEL equals the normalized _binary.filename or original_filename
                            (on Windows case-, slash- and \\\\?\\-insensitive; elsewhere case-sensitive);
    SEL has an extension -> the basename of filename or original_filename equals SEL's basename (without case on
                            Windows);
    otherwise            -> the stem of filename or original_filename equals SEL (without case on Windows).

OUTPUT
  One line of compact ASCII JSON on stdout.
  caps: {ok, subcommand:'caps', reachable, contract, capabilities[], version, bn_core_version, lock_mode,
         import_errors{}, http_status, url}. Not reachable -> reachable:false, contract ''. A /status without a
         `server` object (the upstream plugin) -> contract ''. Exit 0 in both cases; with --strict, exit 5 when the
         server is unreachable and 3 unless it answered HTTP 200 with contract binja-agent-mcp/1 (ok:false then).
  pack: {ok:true, subcommand:'pack', written, out, pack_sha256, truncated, analysis_state, binary_echo_ok,
         refused_reason, binary_echo:{view_id, filename, binary_id, resolved_by}, function:{name, start}, error_code,
         error, candidates[<=20 {name, start}], http_status, busy_retries_used}
  Exit codes: 0 whenever the HTTP exchange completed (a refusal and BUSY exhaustion included) | 1 an unexpected
  internal error | 2 usage | 3 caps --strict: not served as binja-agent-mcp/1 | 4 a bad --out | 5 Binary Ninja
  unreachable or the request timed out (error_code UNREACHABLE / TIMEOUT, written false). A non-zero exit still prints
  {ok:false, subcommand, error, exit_code, ...}.

VERIFICATION: offline, against stub HTTP servers and the plugin's real HTTP server on the fake binaryninja
(tests/test_bn_mcp_client.py).
"""

import argparse
import hashlib
import http.client
import json
import ntpath
import os
import posixpath
import re
import socket
import stat
import sys
import tempfile
import time
import urllib.parse

TOOL = "bn_mcp_client"
CONTRACT = "binja-agent-mcp/1"
EXIT_OK, EXIT_INTERNAL, EXIT_USAGE, EXIT_NOT_SERVED, EXIT_INVALID, EXIT_UNREACHABLE = 0, 1, 2, 3, 4, 5
DEFAULT_URL = "http://127.0.0.1:9009"
CONNECT_TIMEOUT_S = 5.0
CAPS_READ_TIMEOUT_S = 30.0
MAX_CANDIDATES = 20
TOKEN_HEADER = "X-BN-MCP-Token"
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,200}$")


class UsageError(Exception):
    pass


class InvalidInput(Exception):
    pass


class Unreachable(Exception):
    def __init__(self, code, msg):
        Exception.__init__(self, msg)
        self.code = code


# =====================================================================================================================
# output (_ascii / _clean / emit)
# =====================================================================================================================
def _ascii(s, maxlen=None):
    """Printable ASCII only; backslash -> '/', double quote -> single quote, control -> space, non-ASCII -> '?'."""
    if s is None:
        return ""
    s = str(s)
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("/")
        elif ch == '"':
            out.append("'")
        elif 32 <= o < 127:
            out.append(ch)
        elif o < 32:
            out.append(" ")
        else:
            out.append("?")
    r = "".join(out)
    if maxlen is not None and len(r) > maxlen:
        r = r[:maxlen]
    return r


def _clean(obj):
    if isinstance(obj, dict):
        return {_ascii(k): _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(v) for v in obj]
    if isinstance(obj, bool) or obj is None:
        return obj
    if isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        return int(obj) if obj == int(obj) else round(obj, 4)
    return _ascii(obj)


def emit(obj):
    line = json.dumps(_clean(obj), separators=(",", ":"), ensure_ascii=True)
    sys.stdout.buffer.write((line + "\n").encode("ascii"))
    sys.stdout.flush()


# =====================================================================================================================
# HTTP
# =====================================================================================================================
def token_file_path():
    """BN_MCP_TOKEN_FILE, else the per-user default location of the token file (the same rule as the plugin's
    plugin/core/local_auth.py and the bridge; a test keeps the three equal)."""
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


def read_token():
    try:
        with open(token_file_path(), "r", encoding="utf-8") as f:
            t = f.read().strip()
    except (OSError, UnicodeDecodeError):
        return ""
    return t if _TOKEN_RE.match(t) else ""


def base_url(arg):
    """(host, port, url) of --url, else BN_MCP_URL, else DEFAULT_URL. Only http://127.0.0.1:<port> and
    http://localhost:<port> are accepted: the plugin listens on the loopback address only, and every request carries
    the token, which must not travel to another host."""
    u = (arg or os.environ.get("BN_MCP_URL") or DEFAULT_URL).strip()
    p = urllib.parse.urlsplit(u)
    try:
        port = p.port
    except ValueError:
        raise UsageError("bad port in %s" % _ascii(u, 120))
    host = (p.hostname or "").lower()
    if (p.scheme != "http" or host not in ("127.0.0.1", "localhost") or not port or p.username or p.password
            or p.path not in ("", "/") or p.query or p.fragment):
        raise UsageError("the server URL must be http://127.0.0.1:<port> or http://localhost:<port> (got %s)"
                         % _ascii(u, 120))
    return host, port, "http://%s:%d" % (host, port)


def http_get(url, path, params, read_timeout):
    """-> (status, parsed JSON or None, raw body). Raises Unreachable on a connect failure / timeout."""
    host, port, _u = base_url(url)
    q = urllib.parse.urlencode([(k, str(v)) for k, v in params]) if params else ""
    headers = {"Accept": "application/json", "Connection": "close"}
    tok = read_token()
    if tok:
        headers[TOKEN_HEADER] = tok
    conn = http.client.HTTPConnection(host, port, timeout=CONNECT_TIMEOUT_S)
    try:
        try:
            conn.connect()
        except (OSError, socket.timeout) as e:
            raise Unreachable("UNREACHABLE", "server not reachable at %s:%d (%s)" % (host, port, _ascii(e, 120)))
        conn.sock.settimeout(read_timeout)
        try:
            conn.request("GET", path + ("?" + q if q else ""), headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
        except socket.timeout:
            raise Unreachable("TIMEOUT", "the request to %s timed out after %d s" % (path, int(read_timeout)))
        except (OSError, http.client.HTTPException) as e:
            raise Unreachable("UNREACHABLE", "the connection to %s:%d failed: %s" % (host, port, _ascii(e, 120)))
    finally:
        conn.close()
    body = None
    try:
        body = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        body = None
    return resp.status, body, raw


# =====================================================================================================================
# caps
# =====================================================================================================================
def cmd_caps(args):
    _h, _p, url = base_url(args.url)
    out = {"ok": True, "subcommand": "caps", "reachable": False, "contract": "", "capabilities": [], "version": "",
           "bn_core_version": "", "lock_mode": "", "import_errors": {}, "http_status": 0, "url": url}
    try:
        status, body, _raw = http_get(args.url, "/status", [], CAPS_READ_TIMEOUT_S)
    except Unreachable as e:
        out["error"] = str(e)
        if getattr(args, "strict", False):
            out["ok"] = False
            out["exit_code"] = EXIT_UNREACHABLE
            return out, EXIT_UNREACHABLE
        return out, EXIT_OK
    out["reachable"] = True
    out["http_status"] = status
    srv = body.get("server") if (status == 200 and isinstance(body, dict)) else None
    if isinstance(srv, dict):
        c = srv.get("contract")
        out["contract"] = c if isinstance(c, str) else ""
        caps = srv.get("capabilities")
        out["capabilities"] = [x for x in caps if isinstance(x, str)][:32] if isinstance(caps, list) else []
        for k in ("version", "bn_core_version", "lock_mode"):
            v = srv.get(k)
            out[k] = v if isinstance(v, str) else ("" if v is None else str(v))
        ie = srv.get("import_errors")
        out["import_errors"] = {str(k): _ascii(v, 200) for k, v in ie.items()} if isinstance(ie, dict) else {}
    elif status != 200:
        code = body.get("error_code") if isinstance(body, dict) else None
        out["error"] = "GET /status answered HTTP %d%s" % (status, (" " + _ascii(code, 40)) if code else "")
    elif not isinstance(body, dict):
        out["error"] = "GET /status did not answer a JSON object"
    else:
        out["error"] = "GET /status carries no `server` object (the upstream plugin, not binja-agent-mcp)"
    if getattr(args, "strict", False) and not (out["reachable"] and status == 200 and out["contract"] == CONTRACT):
        out["ok"] = False
        out["exit_code"] = EXIT_NOT_SERVED
        return out, EXIT_NOT_SERVED
    return out, EXIT_OK


# =====================================================================================================================
# pack
# =====================================================================================================================
def _is_link(p):
    try:
        st = os.lstat(p)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0) or 0
    return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _abs(p):
    return os.path.normpath(os.path.abspath(str(p).strip()))


_WIN = sys.platform == "win32"


def _norm_path_key(p, win=None):
    """A path as the plugin compares it: on Windows case-, slash- and \\\\?\\-insensitive; elsewhere only normalized
    (case kept, a backslash is an ordinary character)."""
    win = _WIN if win is None else win
    s = str(p or "").strip()
    if not win:
        return posixpath.normpath(s) if s else s
    s = s.replace("/", "\\")
    for pre in ("\\\\?\\UNC\\", "\\\\?\\", "\\??\\", "\\\\.\\"):
        if s.startswith(pre):
            s = ("\\\\" + s[len(pre):]) if pre == "\\\\?\\UNC\\" else s[len(pre):]
            break
    s = ntpath.normpath(s) if s else s
    return s.casefold()


def _basename(p, win=None):
    win = _WIN if win is None else win
    s = str(p or "")
    if win:
        s = s.replace("\\", "/")
    return s.rstrip("/").rsplit("/", 1)[-1]


def _name_key(name, win=None):
    win = _WIN if win is None else win
    return str(name or "").casefold() if win else str(name or "")


def check_out(out_arg, overwrite):
    """-> absolute out path; raises InvalidInput (exit 4)."""
    out = _abs(out_arg)
    if os.path.lexists(out):
        if _is_link(out) or os.path.isdir(out):
            raise InvalidInput("--out %s is a link, a reparse point or a directory" % _ascii(out_arg, 160))
        if not overwrite:
            raise InvalidInput("--out %s exists; pass --overwrite to replace it" % _ascii(out_arg, 160))
    parent = os.path.dirname(out)
    if os.path.lexists(parent) and (_is_link(parent) or not os.path.isdir(parent)):
        raise InvalidInput("the directory of --out is a link, a reparse point or not a directory")
    return out


def _candidates(body):
    out = []
    c = body.get("candidates") if isinstance(body, dict) else None
    if not isinstance(c, list):
        return out
    for x in c[:MAX_CANDIDATES]:
        name, start = "", ""
        if isinstance(x, dict):
            name = x.get("name") or x.get("function") or x.get("filename") or x.get("binary_id") or ""
            start = x.get("start", x.get("address", x.get("va", "")))
        elif isinstance(x, str):
            m = re.match(r"^(.*)@(0x[0-9a-fA-F]+)$", x.strip())
            name, start = (m.group(1), m.group(2)) if m else (x, "")
        if isinstance(start, int) and not isinstance(start, bool):
            start = "0x%x" % start
        out.append({"name": _ascii(name, 160), "start": _ascii(start, 40).lower()})
    return out


def echo_ok(sel, sel_is_path, b):
    if not isinstance(b, dict) or b.get("resolved_by") != "explicit":
        return False
    names = [x for x in (b.get("filename"), b.get("original_filename")) if isinstance(x, str) and x]
    if not names:
        return False
    if sel_is_path:
        want = _norm_path_key(sel)
        return any(_norm_path_key(n) == want for n in names)
    sb = _basename(sel)
    if os.path.splitext(sb)[1]:
        return any(_name_key(_basename(n)) == _name_key(sb) for n in names)
    return any(_name_key(os.path.splitext(_basename(n))[0]) == _name_key(sel) for n in names)


def _write_atomic(path, text):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".bnpack-", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(text.encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def cmd_pack(args):
    sel = (args.binary or "").strip()
    fn = (args.function or "").strip()
    if not sel or not fn:
        raise UsageError("--binary and --function must be non-empty")
    if args.disasm not in ("0", "1"):
        raise UsageError("--disasm must be 0 or 1")
    for name, v, lo, hi in (("--depth", args.depth, 0, 4), ("--max-callees", args.max_callees, 0, 1000),
                            ("--max-chars", args.max_chars, 1000, 4000000), ("--timeout", args.timeout, 5, 3600),
                            ("--busy-retries", args.busy_retries, 0, 1000), ("--busy-sleep", args.busy_sleep, 0, 600)):
        if not (lo <= v <= hi):
            raise UsageError("%s must be in %d..%d" % (name, lo, hi))
    base_url(args.url)
    out_path = check_out(args.out, args.overwrite)
    sel_is_path = ("/" in sel) or ("\\" in sel)
    sel_send = _abs(sel) if sel_is_path else sel
    params = [("binary", sel_send), ("function", fn), ("depth", args.depth), ("max_callees", args.max_callees),
              ("max_chars", args.max_chars), ("include", args.include), ("disasm", args.disasm)]
    res = {"ok": True, "subcommand": "pack", "written": False, "out": out_path, "pack_sha256": "", "truncated": False,
           "analysis_state": "", "binary_echo_ok": False, "refused_reason": "",
           "binary_echo": {"view_id": "", "filename": "", "binary_id": "", "resolved_by": ""},
           "function": {"name": "", "start": ""}, "error_code": "", "error": "", "candidates": [], "http_status": 0,
           "busy_retries_used": 0}
    used = 0
    while True:
        try:
            status, body, _raw = http_get(args.url, "/x/handlerSlice", params, float(args.timeout))
        except Unreachable as e:
            res.update({"ok": False, "error": str(e), "error_code": e.code, "exit_code": EXIT_UNREACHABLE,
                        "refused_reason": "Binary Ninja did not answer"})
            return res, EXIT_UNREACHABLE
        code = (body.get("error_code") if isinstance(body, dict) else "") or ""
        if status == 503 and (code == "BUSY" or not code) and used < args.busy_retries:
            used += 1
            time.sleep(args.busy_sleep)
            continue
        break
    res["http_status"] = status
    res["busy_retries_used"] = used
    b = body.get("_binary") if isinstance(body, dict) else None
    if isinstance(b, dict):
        res["binary_echo"] = {"view_id": _ascii(b.get("view_id"), 40), "filename": _ascii(b.get("filename"), 260),
                              "binary_id": _ascii(b.get("binary_id"), 120), "resolved_by": _ascii(b.get("resolved_by"), 20)}
        res["analysis_state"] = _ascii(b.get("analysis_state"), 40)
    res["binary_echo_ok"] = echo_ok(sel_send, sel_is_path, b)
    if not isinstance(body, dict):
        res.update({"error_code": "HTTP_%d" % status, "error": "the answer is not a JSON object",
                    "refused_reason": "non-JSON answer (HTTP %d)" % status})
        return res, EXIT_OK
    if status != 200 or body.get("ok") is not True:
        res.update({"error_code": _ascii(code or ("HTTP_%d" % status), 40), "error": _ascii(body.get("error"), 400),
                    "candidates": _candidates(body),
                    "refused_reason": "the server answered %s (HTTP %d)" % (_ascii(code or "an error", 40), status)})
        return res, EXIT_OK
    r = body.get("result")
    if not isinstance(r, dict):
        res.update({"error_code": "BAD_ENVELOPE", "refused_reason": "the envelope has no result object"})
        return res, EXIT_OK
    f = r.get("function") if isinstance(r.get("function"), dict) else {}
    st = f.get("start")
    res["function"] = {"name": _ascii(f.get("name"), 160),
                       "start": ("0x%x" % st) if isinstance(st, int) and not isinstance(st, bool) else _ascii(st, 40).lower()}
    res["truncated"] = bool(r.get("truncated") or body.get("truncated"))
    text = r.get("pack_text")
    psha = r.get("pack_sha256")
    res["pack_sha256"] = _ascii(psha, 64)
    mod = r.get("modified_bytes_in_slice")
    why = ""
    if not isinstance(text, str) or not text:
        why = "the envelope carries no pack_text"
    elif not isinstance(psha, str) or hashlib.sha256(text.encode("utf-8")).hexdigest() != psha.lower():
        why = "sha256(pack_text) does not equal pack_sha256 (transport or server defect)"
    elif not res["binary_echo_ok"]:
        why = "the _binary echo does not name the requested binary (resolved_by explicit + name match)"
    elif not isinstance(b, dict) or b.get("analysis_state") != "IdleState":
        why = "analysis_state is %s, not IdleState" % (_ascii((b or {}).get("analysis_state"), 40) or "missing")
    elif r.get("complete") is not True:
        why = "the slice is incomplete (sections_missing: %s)" % _ascii(",".join(str(x) for x in (r.get("sections_missing") or [])), 120)
    elif not (isinstance(mod, int) and not isinstance(mod, bool) and mod == 0):
        why = "modified_bytes_in_slice is %s, not 0 (patched bytes or unknown)" % _ascii(mod, 20)
    elif b.get("sha256_source") != "file":
        why = "sha256_source is %s, not file" % (_ascii(b.get("sha256_source"), 40) or "missing")
    if why:
        res["refused_reason"] = why
        return res, EXIT_OK
    _write_atomic(out_path, text)
    res["written"] = True
    return res, EXIT_OK


# =====================================================================================================================
# CLI
# =====================================================================================================================
class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise UsageError(message)

    def exit(self, status=0, message=None):
        if status:
            raise UsageError(message or "usage error")
        raise SystemExit(status)


SUBCOMMANDS = ("caps", "pack")


def build_parser():
    p = _Parser(prog="bn_mcp_client.py", description="Command-line client of the binja-agent-mcp HTTP API "
                                                     "(contract %s)." % CONTRACT)
    sub = p.add_subparsers(dest="sub", parser_class=_Parser)
    s = sub.add_parser("caps", help="probe GET /status: version, contract and capabilities (read-only)")
    s.add_argument("--url", default=None)
    s.add_argument("--strict", action="store_true",
                   help="exit 5 when the server is unreachable and 3 unless it answered as %s with the token "
                        "accepted" % CONTRACT)
    s = sub.add_parser("pack", help="write one function's verified context pack (GET /x/handlerSlice)")
    s.add_argument("--binary", required=True)
    s.add_argument("--function", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--overwrite", action="store_true", help="replace an existing --out file")
    s.add_argument("--depth", type=int, default=3)
    s.add_argument("--max-callees", type=int, default=40)
    s.add_argument("--max-chars", type=int, default=120000)
    s.add_argument("--include", default="hlil,callers,types,strings,imports")
    s.add_argument("--disasm", default="0")
    s.add_argument("--timeout", type=int, default=600)
    s.add_argument("--busy-retries", type=int, default=30)
    s.add_argument("--busy-sleep", type=int, default=10)
    s.add_argument("--url", default=None)
    return p


def _guess_sub(argv):
    for x in argv:
        if x in SUBCOMMANDS:
            return x
    return ""


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    sub = _guess_sub(argv)
    try:
        if any(x in ("-h", "--help") for x in argv):
            build_parser().parse_args(argv)
            return EXIT_OK
        args = build_parser().parse_args(argv)
        if not args.sub:
            raise UsageError("a subcommand is required: " + " | ".join(SUBCOMMANDS))
        sub = args.sub
        out, code = {"caps": cmd_caps, "pack": cmd_pack}[sub](args)
        emit(out)
        return code
    except SystemExit as e:
        return int(e.code or 0)
    except UsageError as e:
        code, msg = EXIT_USAGE, str(e)
    except InvalidInput as e:
        code, msg = EXIT_INVALID, str(e)
    except Unreachable as e:
        code, msg = EXIT_UNREACHABLE, "%s: %s" % (e.code, e)
    except Exception as e:                   # unexpected: still print one JSON line
        code, msg = EXIT_INTERNAL, "internal error: %s: %s" % (type(e).__name__, e)
    o = {"ok": False, "subcommand": sub, "error": _ascii(msg, 400), "exit_code": code}
    if sub == "pack":
        o["written"] = False
    emit(o)
    return code


if __name__ == "__main__":
    sys.exit(main())
