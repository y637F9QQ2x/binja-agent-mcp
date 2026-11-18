#!/usr/bin/env python3
# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""Measure the tool definitions an MCP bridge sends to its client (the MCP tools/list result).

USAGE
  python tools/measure_tool_definitions.py BRIDGE.py [--toolset NAME] [--json]

  BRIDGE.py  a bridge file: binja_agent_mcp's bridge/binja_mcp_bridge.py, or the bridge of upstream
             fosdickio/binary_ninja_mcp v1.1.0 (bridge/binja_mcp_bridge.py of that checkout), or any other bridge
             that keeps its FastMCP instance in the module attribute `mcp`.
  --toolset  sets BN_MCP_TOOLSET for this import (binja_agent_mcp's bridge reads it; other bridges ignore it).

WHAT IT DOES
  Imports BRIDGE.py under a private module name, so its `if __name__ == "__main__"` block does not run: no server
  starts and no connection is made. Then it serializes mcp.list_tools() as the MCP server sends it: a
  ListToolsResult dumped with field aliases and without None fields, as compact JSON (separators "," and ":",
  non-ASCII characters kept). It prints the number of tools, the characters of the whole {"tools": [...]} object
  and the characters of each definition. Characters are Python str lengths (code points).

  README.md ("Tool count and context cost") was measured with this script and with mcp 1.27.2. The bridge's own
  `--list-tools` flag prints the same numbers for its selected tool set.
"""

import argparse
import asyncio
import importlib.util
import json
import os
import sys


def measure(bridge_path, toolset=None):
    """-> {'tools': n, 'chars': total, 'per_tool': {name: chars}} for the bridge file at `bridge_path`."""
    import mcp.types as types
    saved = os.environ.get("BN_MCP_TOOLSET")
    if toolset:
        os.environ["BN_MCP_TOOLSET"] = toolset
    hook = sys.excepthook
    try:
        spec = importlib.util.spec_from_file_location("_measured_bridge", bridge_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        sys.excepthook = hook            # a bridge may install its own excepthook at import time
        if toolset:
            if saved is None:
                os.environ.pop("BN_MCP_TOOLSET", None)
            else:
                os.environ["BN_MCP_TOOLSET"] = saved
    server = getattr(mod, "mcp", None)
    if server is None or not hasattr(server, "list_tools"):
        raise SystemExit("%s has no FastMCP instance named `mcp`" % bridge_path)
    tools = asyncio.run(server.list_tools())
    defs = types.ListToolsResult(tools=tools).model_dump(by_alias=True, mode="json", exclude_none=True)["tools"]

    def dump(obj):
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return {"tools": len(defs), "chars": len(dump({"tools": defs})),
            "per_tool": {d["name"]: len(dump(d)) for d in defs}}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Measure the tools/list result of an MCP bridge file.")
    ap.add_argument("bridge")
    ap.add_argument("--toolset", default=None)
    ap.add_argument("--json", action="store_true", help="print one JSON line")
    args = ap.parse_args(argv)
    m = measure(os.path.abspath(args.bridge), args.toolset)
    if args.json:
        print(json.dumps(m, separators=(",", ":")))
    else:
        for name, n in m["per_tool"].items():
            print("%6d  %s" % (n, name))
        print("%d tools, tools/list result %d characters (about %d tokens at 4 characters per token, a rough "
              "estimate)" % (m["tools"], m["chars"], round(m["chars"] / 4.0, -2)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
