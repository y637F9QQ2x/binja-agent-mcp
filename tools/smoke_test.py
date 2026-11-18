#!/usr/bin/env python3
# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""Smoke test of a running binja-agent-mcp server inside Binary Ninja, through its HTTP API (standard library only).

USAGE
  python tools/smoke_test.py --binary PATH [--url http://127.0.0.1:9009] [--analysis-timeout 300]

  PATH: an absolute path to a COPY of a binary you may analyze (the test loads it, renames its entry function in
  memory and closes it again; nothing is saved). Start Binary Ninja with this plugin and start the server first.
  The token is read like bn_mcp_client.py reads it (BN_MCP_TOKEN_FILE or the default per-user file).

STEPS (each prints one JSON line; the last line is the summary; exit 0 only when every step passed)
  status       GET /status answers with contract binja-agent-mcp/1
  binaries     GET /binaries answers
  load         POST /x/loadBinary opens PATH (a new view, or the view the server already holds)
  analysis     GET /x/binaryInfo until analysis_state is IdleState (at most --analysis-timeout seconds)
  decompile    GET /x/decompile of the entry function returns code, and _binary names the loaded view
  xrefs        GET /x/xrefs of the entry address answers
  rename       POST /renameFunction renames the entry function; GET /x/resolveEntity finds the new name there
  close        POST /x/closeBinary closes the view; GET /binaries no longer lists it

The steps that need the Binary Ninja UI are done by hand (README.md, Tests): the menu and the status-bar button,
two UI tabs in list_binaries, a closed tab leaving the list, and stopping the server.
"""

import argparse
import http.client
import json
import os
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bn_mcp_client as client  # noqa: E402  (the repository's client: token file and URL rules)

SMOKE_NAME = "binja_agent_mcp_smoke_entry"


class Step(Exception):
    pass


def request(url, method, path, params=None, body=None, form=None, timeout=60.0):
    host, port, _u = client.base_url(url)
    q = urllib.parse.urlencode(params or {})
    headers = {"Connection": "close"}
    tok = client.read_token()
    if tok:
        headers[client.TOKEN_HEADER] = tok
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(method, path + ("?" + q if q else ""), body=data, headers=headers)
        r = conn.getresponse()
        raw = r.read()
    finally:
        conn.close()
    try:
        js = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        js = None
    return r.status, js


def run(args):
    report = []

    def step(name, fn):
        t0 = time.monotonic()
        try:
            detail = fn()
            ok = True
        except Step as e:
            detail, ok = str(e), False
        except Exception as e:                              # a transport error ends the run as a failed step
            detail, ok = "%s: %s" % (type(e).__name__, e), False
        row = {"step": name, "ok": ok, "seconds": round(time.monotonic() - t0, 2), "detail": detail}
        print(json.dumps(row, separators=(",", ":")))
        report.append(row)
        return ok

    url = args.url
    state = {}

    def status():
        st, js = request(url, "GET", "/status")
        contract = ((js or {}).get("server") or {}).get("contract")
        if st != 200 or contract != client.CONTRACT:
            raise Step("HTTP %d, contract %r (is the server started, and is the token file readable?)" % (st, contract))
        return {"version": js["server"].get("version"), "bn_core_version": js["server"].get("bn_core_version")}

    def binaries():
        st, js = request(url, "GET", "/binaries")
        if st != 200 or not isinstance((js or {}).get("binaries"), list):
            raise Step("HTTP %d" % st)
        state["before"] = len(js["binaries"])
        return {"open": state["before"]}

    def load():
        st, js = request(url, "POST", "/x/loadBinary", body={"filepath": args.binary, "wait": False})
        res = (js or {}).get("result") or {}
        if st != 200 or not res.get("view_id"):
            raise Step("HTTP %d: %s" % (st, (js or {}).get("error")))
        state["sel"] = "view:" + str(res["view_id"])
        return {"view_id": res["view_id"], "reused": res.get("reused")}

    def analysis():
        deadline = time.monotonic() + args.analysis_timeout
        while True:
            st, js = request(url, "GET", "/x/binaryInfo", {"binary": state["sel"]})
            res = (js or {}).get("result") or {}
            if st != 200:
                raise Step("HTTP %d: %s" % (st, (js or {}).get("error")))
            if res.get("analysis_state") == "IdleState":
                state["entry"] = res.get("entry_point")
                return {"entry_point": state["entry"], "functions": res.get("function_count")}
            if time.monotonic() > deadline:
                raise Step("analysis_state is still %r after %d s" % (res.get("analysis_state"), args.analysis_timeout))
            time.sleep(2.0)

    def decompile():
        st, js = request(url, "GET", "/x/decompile", {"binary": state["sel"], "function": state["entry"],
                                                      "max_lines": 40})
        res = (js or {}).get("result") or {}
        echo = (js or {}).get("_binary") or {}
        if st != 200 or not res.get("text"):
            raise Step("HTTP %d: %s" % (st, (js or {}).get("error")))
        if "view:" + str(echo.get("view_id")) != state["sel"]:
            raise Step("_binary names view %r, not %s" % (echo.get("view_id"), state["sel"]))
        return {"lines": len(str(res["text"]).splitlines())}

    def xrefs():
        st, js = request(url, "GET", "/x/xrefs", {"binary": state["sel"], "va": state["entry"], "limit": 20})
        if st != 200 or not (js or {}).get("ok"):
            raise Step("HTTP %d: %s" % (st, (js or {}).get("error")))
        return {"returned": len(((js or {}).get("result") or {}).get("xrefs") or [])}

    def rename():
        st, js = request(url, "POST", "/renameFunction", {"binary": state["sel"]},
                         form={"oldName": state["entry"], "newName": SMOKE_NAME})
        if st != 200:
            raise Step("rename: HTTP %d: %s" % (st, (js or {}).get("error")))
        st, js = request(url, "GET", "/x/resolveEntity", {"binary": state["sel"], "ref": SMOKE_NAME})
        res = (js or {}).get("result") or {}
        if st != 200 or str(res.get("va", "")).lower() != str(state["entry"]).lower():
            raise Step("resolveEntity(%s): HTTP %d, %r" % (SMOKE_NAME, st, res.get("va")))
        return {"va": res.get("va")}

    def close():
        st, js = request(url, "POST", "/x/closeBinary", {"binary": state["sel"]}, body={})
        if st != 200:
            raise Step("HTTP %d: %s" % (st, (js or {}).get("error")))
        st, js = request(url, "GET", "/binaries")
        ids = ["view:" + str(b.get("view_id")) for b in (js or {}).get("binaries") or []]
        if state["sel"] in ids:
            raise Step("%s is still listed after the close" % state["sel"])
        return {"open": len(ids)}

    for name, fn in (("status", status), ("binaries", binaries), ("load", load), ("analysis", analysis),
                     ("decompile", decompile), ("xrefs", xrefs), ("rename", rename), ("close", close)):
        if not step(name, fn):
            if "sel" in state and name != "close":
                step("close", close)                     # leave nothing open behind a failed step
            break
    passed = all(r["ok"] for r in report) and len(report) == 8
    print(json.dumps({"summary": "passed" if passed else "failed", "steps": len(report),
                      "failed": [r["step"] for r in report if not r["ok"]]}, separators=(",", ":")))
    return 0 if passed else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="Smoke test of a running binja-agent-mcp server (HTTP API).")
    ap.add_argument("--binary", required=True, help="absolute path to a copy of a binary you may analyze")
    ap.add_argument("--url", default=None, help="default: BN_MCP_URL, else http://127.0.0.1:9009")
    ap.add_argument("--analysis-timeout", type=int, default=300)
    args = ap.parse_args(argv)
    if not os.path.isabs(args.binary):
        ap.error("--binary must be an absolute path")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
