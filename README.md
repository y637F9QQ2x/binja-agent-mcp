# binja-agent-mcp

An MCP (Model Context Protocol) server for Binary Ninja, built for LLM agents.

binja-agent-mcp lets an MCP client (Claude Code, Claude Desktop, Cursor and others) work with the binaries open in
a Binary Ninja that runs on the same computer: find functions, read decompiled code, follow cross-references and
calls, query data flow, and add names, types and comments.

**Status: preview.** This release has been tested with the offline test suite only (against a fake `binaryninja`
module), not inside Binary Ninja. See [Tests](#tests) for the live checks that are still to be done, and
[Limitations](#limitations).

It is a modified version of [Binary Ninja MCP](https://github.com/fosdickio/binary_ninja_mcp) by fosdickio and
CX330Blake, based on upstream release v1.1.0, and is licensed under GPL-3.0-or-later. It is an independent
repository, not a GitHub fork, and it is not affiliated with or endorsed by Vector 35 Inc. or by the upstream
authors.

It has two parts:

- a Binary Ninja plugin (`binja_agent_mcp/plugin/`) that serves an HTTP API on `127.0.0.1:9009` from inside your
  running Binary Ninja;
- an MCP bridge (`binja_agent_mcp/bridge/binja_mcp_bridge.py`) that your MCP client starts over stdio and that calls
  this HTTP API.

## Contents

- [What it changes compared with upstream](#what-it-changes-compared-with-upstream)
- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [Configuration](#configuration)
- [Tool count and context cost](#tool-count-and-context-cost)
- [Security and trust model](#security-and-trust-model)
- [Limitations](#limitations)
- [Tests](#tests)
- [Repository layout](#repository-layout)
- [Related projects](#related-projects)
- [Credits and license](#credits-and-license)

## What it changes compared with upstream

- **Tool sets.** The bridge registers only the tools of one tool set: `core` (25 tools, the default), `analysis`
  (50), `upstream` (the 53 upstream tool names) or `full` (86), or an explicit list. See
  [Tool count and context cost](#tool-count-and-context-cost).
- **Bounded answers.** No tool answer is longer than 48,000 characters, and the `bn_*` tools use small default
  pages. Long answers are paged, cut with an explicit marker, or refused with a structured `REFUSED_SIZE` answer.
- **Authenticated localhost requests.** The plugin checks the `Host` header, refuses requests from web pages and
  requires a per-run token. Upstream sent `Access-Control-Allow-Origin: *` with every answer and had none of these
  checks. See [Security and trust model](#security-and-trust-model).
- **33 additional `bn_*` tools**: paged code at every IL level and as assembly, IL search, paged cross-references,
  SSA definitions and uses, backward and interprocedural slices, value sets, branch dependence, CFG, dominators and
  reachability, callers, callees and call paths, return-value checks, call sites of selected APIs and whether a
  check call dominates them, uninitialized reads, stack frames, a context pack for one function
  (`bn_handler_slice`), MIDL/NDR format-string decoding, indirect-call targets, bytes with patch information, entity
  resolution, server, binary, function and debug-info status, exact integer arithmetic, a batch tool, and loading
  and closing binaries.
- **Per-call binary selection.** Tools that work on a binary take an optional `binary` selector (`view:<id>`, a
  sha256, an absolute path or a unique file name; `list_binaries` shows the selectors of each open binary), so
  several binaries can be queried without switching the global selection. Every scoped answer says which binary
  answered (`_binary`).
- **Structured errors**: 400 `BAD_ARGUMENT`, 401 `UNAUTHORIZED`, 403 `POLICY`, 404 `NOT_FOUND` (with `available`),
  409 `AMBIGUOUS` (with `candidates`), 410 `GONE`, 413 `REFUSED_SIZE`, 422 `NO_IL` / `REFUSED_COMPLEXITY`, 501, 503
  `BUSY`.
- **A concurrent HTTP server** (one thread per connection). By default one global lock serializes the Binary Ninja
  work of every request that reads or changes a binary, and of the two load routes.
- **Changed defaults.** The server does not start by itself, the plugin shows no message boxes, MCP client
  configuration files are written only when you ask for it, and `patch_bytes` never writes to disk unless Binary
  Ninja runs with `BN_MCP_ALLOW_SAVE=1`.
- **Refusals for text that a hostile binary can plant.** Loads refuse network and device paths, and C declarations
  may not name a file with `#include` (see [Security and trust model](#security-and-trust-model)).

[CHANGES-FROM-UPSTREAM.md](CHANGES-FROM-UPSTREAM.md) lists every change, file by file.

## Requirements

- Binary Ninja with a license for an edition that runs plugins. The free edition has "No API / plugin access"
  (https://binary.ninja/free/). Your Binary Ninja license governs how you may use it
  (https://docs.binary.ninja/about/license.html).
- This release was written against the Binary Ninja 6.0 Python API. `plugin.json` keeps upstream's
  `minimumbinaryninjaversion` (build 4000), but builds earlier than 6.0 are untested.
- Python 3.10 or later for the bridge, with the packages in `binja_agent_mcp/bridge/requirements.txt`
  (`mcp==1.27.2`, the version the bridge was tested with, and `requests>=2.32.3`). `bn_mcp_client.py` and
  `tools/smoke_test.py` need only the standard library; `tools/measure_tool_definitions.py` also needs `mcp`.

## Install

1. Get the code:

   ```
   git clone https://github.com/y637F9QQ2x/binja-agent-mcp
   ```

2. Make the folder `binja_agent_mcp` a Binary Ninja user plugin. The user plugin folders are those listed in the
   Binary Ninja documentation (https://docs.binary.ninja/guide/plugins.html). A link keeps the plugin in step with
   the repository; a copy works too.

   ```
   rem Windows (cmd.exe)
   mklink /J "%APPDATA%\Binary Ninja\plugins\binja_agent_mcp" "<repo>\binja_agent_mcp"

   # macOS
   ln -s "<repo>/binja_agent_mcp" "$HOME/Library/Application Support/Binary Ninja/plugins/binja_agent_mcp"

   # Linux
   ln -s "<repo>/binja_agent_mcp" "$HOME/.binaryninja/plugins/binja_agent_mcp"
   ```

   Do not install the upstream "Binary Ninja MCP" from the Plugin Manager at the same time: both register the same
   "MCP Server" menu and port 9009.

3. Create the bridge's Python environment:

   ```
   python -m venv <repo>/binja_agent_mcp/.venv
   # Windows
   <repo>\binja_agent_mcp\.venv\Scripts\python -m pip install -r <repo>\binja_agent_mcp\bridge\requirements.txt
   # macOS, Linux
   <repo>/binja_agent_mcp/.venv/bin/python -m pip install -r <repo>/binja_agent_mcp/bridge/requirements.txt
   ```

4. Add the bridge to your MCP client. In the commands below, `<python>` is the interpreter of step 3 and `<bridge>`
   is `<repo>/binja_agent_mcp/bridge/binja_mcp_bridge.py`.

   - Claude Code (`claude mcp add` syntax from https://code.claude.com/docs/en/mcp):

     ```
     claude mcp add --env BN_MCP_TOOLSET=core --scope user --transport stdio binja_agent_mcp -- <python> <bridge>
     ```

   - Any client that reads a JSON configuration with an `mcpServers` object:

     ```json
     {
       "mcpServers": {
         "binja_agent_mcp": {
           "command": "<python>",
           "args": ["<bridge>"],
           "env": {"BN_MCP_TOOLSET": "core"}
         }
       }
     }
     ```

   - Or let the installer write such an entry into the configuration of each supported client whose configuration
     folder exists (Cline, Roo Code, Claude Desktop, Cursor, Windsurf, LM Studio; Claude Desktop not on Linux). For
     Claude Code it prints the `claude mcp add` command instead of editing `~/.claude.json`, a file Claude Code
     rewrites while it runs.

     ```
     python <repo>/binja_agent_mcp/scripts/mcp_client_installer.py --install     # add the entries
     python <repo>/binja_agent_mcp/scripts/mcp_client_installer.py --uninstall   # remove them again
     python <repo>/binja_agent_mcp/scripts/mcp_client_installer.py --config      # print an entry (read-only)
     python <repo>/binja_agent_mcp/scripts/mcp_client_installer.py --list        # the clients and their files
     ```

     A tool timeout is written only where a client documents one, in its own unit: `"timeout": 60` (seconds) for
     Cline and Roo Code. The other clients get no `timeout` key. When `binja_agent_mcp/.venv` does not exist yet,
     `--install` creates it and runs `pip install -r requirements.txt`, which downloads the packages from PyPI and
     shows pip's output; `--python <interpreter>` uses an interpreter of your choice instead. No configuration file
     is written unless the interpreter can import `mcp`, `requests` and `anyio`. `PYTHONPATH`, `PYTHONHOME` and the
     other `PYTHON*` variables of your shell are copied into the entries only with `--copy-python-env`. Without a
     flag the installer prints its usage and changes nothing.

   Use the bridge from this repository: the upstream bridge does not send the token and is refused (401).

5. Restart Binary Ninja, then start the server: menu **Plugins > MCP Server > Start MCP Server**, or the "MCP:
   Stopped" button in the status bar. The menu item is a global command, so it needs no open binary (on builds
   without `PluginCommand.register_global` it is enabled only while a binary is open). To start the server every
   time the plugin loads, set `BN_MCP_AUTOSTART=1` in the environment Binary Ninja starts from. On macOS, a Binary
   Ninja started from the Finder or the Dock does not see the variables of your shell: start it from a terminal, or
   set the variable with `launchctl setenv BN_MCP_AUTOSTART 1`.

6. Restart the MCP client. To check the server without an MCP client:

   ```
   python <repo>/bn_mcp_client.py caps --strict
   ```

   It prints one JSON line and exits 0 only when the server answered with `"contract":"binja-agent-mcp/1"` and
   accepted the token (5: unreachable, 3: another answer).

To uninstall: run the installer with `--uninstall` (or remove the `binja_agent_mcp` entry from your client; for
Claude Code, `claude mcp remove --scope user binja_agent_mcp`), then delete the plugin link or copy. The token file
is deleted each time the server stops; if Binary Ninja exits without stopping it, the next start replaces the stale
token.

## Usage

- Open a binary in Binary Ninja, or from the MCP client with `bn_load_binary(filepath=<absolute path>)`. It answers
  at once; poll `bn_binary_info(binary=...)` until `analysis_state` is `IdleState`. Close what the agent opened with
  `bn_close_binary` (both are in `core`); the server holds at most 8 binaries it loaded (`BN_MCP_MAX_OWNED`).
- `list_binaries` lists the binaries open in Binary Ninja's UI tabs and those the server loaded. A binary that
  another script opened with `binaryninja.load` and that is not in a tab is not listed.
- Without `binary`, a tool uses the globally selected binary, as upstream does (after a start, the active tab). With
  several binaries open, pass `binary` (a selector from `list_binaries`) so that each call names the binary it
  means. `view:<id>` stays valid while the binary stays open. The listing's ordinal `#<n>` is still accepted, but it
  is not advertised: it names another binary after one is opened or closed.
- Work on copies of the files you analyze. Annotation tools (rename, retype, comments, `patch_bytes`) change the
  analysis in Binary Ninja's memory; saving a database is your decision in Binary Ninja.
- `bn_mcp_client.py pack --binary <path> --function <name> --out <file>` writes one function's context pack to a
  file only after it checked the pack (its sha256, the binary that answered, finished analysis, a complete slice
  and no modified bytes). See the docstring at the top of `bn_mcp_client.py`.
- The HTTP API can be called directly. Every request needs the token (see
  [Security and trust model](#security-and-trust-model)):

  ```
  # Windows PowerShell
  $t = Get-Content "$env:LOCALAPPDATA\binja-agent-mcp\token"
  curl.exe -H "X-BN-MCP-Token: $t" http://127.0.0.1:9009/status

  # macOS
  curl -H "X-BN-MCP-Token: $(cat "$HOME/Library/Application Support/binja-agent-mcp/token")" http://127.0.0.1:9009/status

  # Linux
  curl -H "X-BN-MCP-Token: $(cat "${XDG_STATE_HOME:-$HOME/.local/state}/binja-agent-mcp/token")" http://127.0.0.1:9009/status
  ```

## Configuration

Environment variables. The plugin reads its variables when Binary Ninja loads it; the bridge reads its variables
when the MCP client starts it (set them in the client's server entry, as in [Install](#install)).

| Variable | Read by | Meaning |
|---|---|---|
| `BN_MCP_TOOLSET` | bridge | `core` (default), `analysis`, `upstream` or `full` |
| `BN_MCP_TOOLS` | bridge | An explicit tool list instead of `BN_MCP_TOOLSET` (see [Tool count and context cost](#tool-count-and-context-cost)) |
| `BN_MCP_MAX_OUTPUT_CHARS` | bridge | 8000 to 500000 (default 48000): the output cap; above 50000 it is declared per tool (see [Tool count and context cost](#tool-count-and-context-cost)) |
| `BN_MCP_URL` | bridge, client | Base URL of the plugin's server (default `http://127.0.0.1:9009`); only `http://127.0.0.1:<port>` and `http://localhost:<port>` are accepted. The plugin always listens on port 9009, so another port is useful for tests only |
| `BN_MCP_TOKEN_FILE` | plugin, bridge, client | Path of the token file (default: see [Security and trust model](#security-and-trust-model)) |
| `BN_MCP_REQUIRE_TOKEN` | plugin | `1` (default) or `0`: with `0`, requests without the token may read; every request that changes the analysis, the selection or the open binaries still needs it |
| `BN_MCP_AUTOSTART` | plugin | `1` = start the server when Binary Ninja loads the plugin |
| `BN_MCP_AUTO_SETUP` | plugin | `1` = when the plugin loads, add the server entry to the supported MCP clients, as `--install` does (upstream always did this on first start) |
| `BN_MCP_ALLOW_SAVE` | plugin | `1` = allow `patch_bytes` with `save_to_file` to write the patched file to disk (see below) |
| `BN_MCP_ALLOW_NETWORK_PATHS` | plugin | `1` = let loads open UNC paths and files on network drives (refused by default, see below) |
| `BN_MCP_MAX_OWNED` | plugin | 1 to 64 (default 8): binaries the server loaded that may be open at once |
| `BN_MCP_LOCK_MODE` | plugin | `global` (default: one lock around the Binary Ninja work of requests) or `per-view` (experimental) |
| `BN_MCP_LOCK_WAIT_S` | plugin | 1 to 300 (default 20): how long a request that names a `binary`, or a `bn_load_binary`, waits for the lock before 503 `BUSY` |
| `BN_MCP_THREADED` | plugin | `1` (default) or `0`: one thread per connection |
| `BN_MCP_MAX_INFLIGHT` | plugin | 1 to 64 (default 8): concurrent Binary Ninja requests, `per-view` mode only |
| `BN_MCP_EXCLUSIVE_BIND` | plugin | Windows only: `1` = bind with `SO_EXCLUSIVEADDRUSE` |
| `BN_MCP_REUSEADDR` | plugin | Windows only: `1` = bind with `SO_REUSEADDR` (a second server can then share the port). On macOS and Linux the server always sets `SO_REUSEADDR`: there it only lets a restarted server bind while connections of the previous one are closing, and a second server still cannot listen on the port |
| `BN_MCP_TEST_BASELINE` | tests | A checkout of upstream v1.1.0 for the backward-compatibility tests |

An invalid plugin value is ignored with a warning in the Binary Ninja log, and the default stays. An invalid tool
selection (see [Tool count and context cost](#tool-count-and-context-cost)) or `BN_MCP_URL` stops the bridge. The
server always binds `127.0.0.1:9009`; no variable changes the address or the port.

## Tool count and context cost

Every MCP tool has a definition (name, description and input schema) that the client sends to the model. How much
of the context window those definitions use depends on the tool set and on the client.

**Measured definition size per tool set.** Characters of the `tools/list` result as the bridge serializes it
(compact JSON), measured on 2026-11-18 with `tools/measure_tool_definitions.py` and mcp 1.27.2 (the bridge's own
`--list-tools` flag prints the same numbers). The token column is characters divided by 4, rounded to the nearest
hundred: a rough estimate, because the real count depends on the model's tokenizer and on how the client wraps tool
definitions. A test (`test_toolsets.py`) fails when this table no longer matches the code.

| Tool set | Tools | Characters | About tokens | For |
|---|---|---|---|---|
| `core` (default) | 25 | 9,230 | 2,300 | everyday work: open, close, find, read, follow, annotate; one tool per job |
| `analysis` | 50 | 21,199 | 5,300 | `core` plus the data-flow, control-flow and call-graph tools |
| `upstream` | 53 | 19,334 | 4,800 | exactly the tool names of upstream v1.1.0, for prompts written for upstream |
| `full` | 86 | 35,348 | 8,800 | every tool, including the overlapping pairs below |

For comparison, measured with the same script: the bridge of upstream v1.1.0 registers 53 tools in 22,122
characters, and the bridge of the earlier release of this code (`binja-mcp-advanced`) registered 92 tools in
64,143 characters. The bridge also sends a 432-character server instruction once per session (in the MCP
`initialize` result).

Three changes keep the definitions small: no `outputSchema` (the bridge registers every tool with unstructured
output, so each answer is also sent only once, as text), no generated `title` fields in the input schemas, and one
short description for the `binary` parameter ("selector from list_binaries"), with the selector syntax explained
once, in the `list_binaries` description and in the server instruction. As a result the `upstream` set is about 13
percent smaller than upstream's own definitions, although it adds a `binary` parameter to 49 of the 53 tools.

**Clients that load tool definitions on demand.** Claude Code uses tool search by default: "Only tool names and
server instructions load at session start", and a tool's full definition is loaded when Claude needs it
(https://code.claude.com/docs/en/mcp, "Scale with MCP tool search"; `ENABLE_TOOL_SEARCH=false` turns this off). On
the Anthropic API, tools marked `defer_loading: true` are found with the tool search tool and loaded only when
needed (https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool). With such a client, even
`full` costs little context until a tool is used.

**Clients that load every definition upfront** pay for all registered tools on every request. Use `core`, or list
exactly the tools you need. The tool search documentation above also states that tool selection accuracy degrades
once more than 30 to 50 tools are available. `analysis` (50 tools) is at the upper end of that range; for a smaller
set, start from `core` and add the tools you use (`BN_MCP_TOOLS=core,bn_cfg,bn_sinks`).

**Why `core` is the default.** A client that loads all definitions upfront pays for every tool, so the default is
the smallest set that covers the common reverse-engineering loop. Prompts and scripts written for upstream tool
names keep working with `BN_MCP_TOOLSET=upstream` or `full`: the 53 names keep their upstream parameters, with an
optional `binary` where it applies, optional paging parameters on `decompile_function`, `get_il` and
`fetch_disassembly`, and `save_to_file` defaulting to false in `patch_bytes` (upstream defaulted to true).

**Choosing tools.** `BN_MCP_TOOLSET` picks a set. `BN_MCP_TOOLS` is an explicit comma-separated list instead: tool
names and set names, and `-name` removes a tool, applied left to right, for example `core,bn_cfg,bn_sinks` or
`full,-patch_bytes`. An unknown name, a list that selects nothing, or both variables set at once stops the bridge
with an error message instead of guessing. `--list-tools` (add `--json` for one JSON line) prints the selected tools
and their sizes without starting the server.

**Overlapping tools.** Some upstream tools and `bn_*` tools do the same job. `core` keeps one of each pair: the one
whose output is paged or bounded by default. In `upstream` and `full` both are present, and each description has a
`See also:` line that names its twin and says how it differs (lines that name a tool outside the selected set are
removed from the description).

| Upstream tool | Overlaps with | In `core` |
|---|---|---|
| `decompile_function`, `get_il`, `fetch_disassembly` | `bn_decompile` (all IL levels and assembly, paged by default) | `bn_decompile` |
| `get_xrefs_to` (not paged) | `bn_xrefs` (paged) | `bn_xrefs` |
| `function_at` | `bn_resolve_entity` (also symbols; returns the section) | `bn_resolve_entity` |
| `hexdump_address` | `bn_bytes_at` (up to 256 bytes, with patch information) | neither |
| `get_binary_status` | `bn_binary_info` (one binary in detail) | `bn_binary_info` |
| `set_local_variable_type` | `retype_variable` (same effect) | `retype_variable` |
| `define_types` | `declare_c_type` (same effect) | `declare_c_type` |
| `get_user_defined_type` | `get_type_info` (more detail) | `get_type_info` |
| `rename_multi_variables` | `rename_single_variable` | `rename_single_variable` |
| `list_all_strings`, `list_strings` | `list_strings_filter` | `list_strings_filter` |

**Answers cost more context than definitions.** Claude Code documents these limits for one MCP tool result
(https://code.claude.com/docs/en/mcp, "MCP output limits and warnings", read 2026-11-18): its transcript viewer
warns above 10,000 tokens; a text result longer than 50,000 characters, or above `MAX_MCP_OUTPUT_TOKENS` (default
25,000 tokens), is saved to a file and replaced by a reference to it. So:

- The `bn_*` tools page by default, with small pages: `bn_decompile` 150 lines or 12,000 characters, `bn_xrefs`,
  `bn_il_search` and `bn_sinks` 100 entries, `bn_callers` and `bn_callees` 100 nodes, `bn_cfg` 200 blocks,
  `bn_handler_slice` 16,000 characters of pack text. Answers report `truncated` and `next_offset`.
- No answer is longer than 48,000 characters (`BN_MCP_MAX_OUTPUT_CHARS`, counted in UTF-16 code units as
  JavaScript counts them), so it stays under the 50,000-character limit. A `bn_*` answer that would exceed the cap
  is not cut: the bridge answers `REFUSED_SIZE` with the fields that fit, the names and sizes of the withheld fields,
  and advice on how to ask for less. `bn_batch` withholds its largest item answers first. Text that is dense in
  tokens (non-Latin strings, hex) can still pass 25,000 tokens below the character cap.
- Upstream tools keep upstream's page sizes; above the cap they are cut at a line boundary and end with
  `[TRUNCATED by the bridge: ...]`, which names the paging parameters of that tool (`line_offset` / `max_lines`, or
  `offset` / `limit`). `list_all_strings` stops reading pages at the cap and ends with `[INCOMPLETE: ...]`, which
  names the exact `list_strings` call that continues.
- A cap above 50,000 characters is declared to the client: each tool's definition then carries
  `_meta["anthropic/maxResultSizeChars"]` (Claude Code honours it up to 500,000), so such an answer also stays in
  the conversation.
- The scanning `bn_*` tools stop after a 30-second server budget and say so (`warnings`, `complete: false`). A
  call normally ends within 55 seconds, inside the 60-second tool timeout the installer writes for Cline and Roo
  Code; the HTTP timeouts bound each socket operation, so a server that sent its answer slowly could extend a call.

## Security and trust model

**Where it listens.** The plugin's HTTP server binds `127.0.0.1:9009` only, so it cannot be reached from the
network. Do not forward, proxy or tunnel the port. The bridge sends its requests only to that loopback address and
never through an HTTP proxy: it ignores `HTTP_PROXY` and the other proxy variables, which would otherwise route the
token and every answer through the proxy.

**Who may call it.** Every request passes three checks before any Binary Ninja work
(`binja_agent_mcp/plugin/core/local_auth.py`):

1. **Host allowlist.** The `Host` header must be `127.0.0.1:9009` or `localhost:9009`. A web page that uses DNS
   rebinding reaches `127.0.0.1` under its own host name, so its requests are refused (403 `FORBIDDEN_HOST`).
2. **No requests from web pages.** A request with an `Origin` or `Referer` header, or with a `Sec-Fetch-Site`
   header other than `none` (a URL the user typed), is refused (403 `BROWSER_REQUEST`). The server never sends CORS
   headers, so a browser neither shows an answer to a page nor sends a cross-origin request with a custom header.
3. **Per-run token.** When the server starts, it writes a random token (32 random bytes, URL-safe base64) to the
   token file and accepts only requests whose `X-BN-MCP-Token` header equals it (401 `UNAUTHORIZED` otherwise). The
   bridge and `bn_mcp_client.py` read the same file. The file is written only after the port is bound, so a second
   Binary Ninja that fails to bind never replaces the token of the first, and it is deleted when the server stops.

With `BN_MCP_REQUIRE_TOKEN=0`, check 3 applies only to requests that change something: the GET routes that rename,
retype, patch, create functions, define types, write comments or change the selection, and every POST and DELETE
except the read-only `bn_*` routes. A browser can send a GET without a preflight (an `<img>` tag, for example), and
an older browser may send it without the headers of check 2, so a token-less GET may only read.

The default token file is `%LOCALAPPDATA%\binja-agent-mcp\token` on Windows,
`~/Library/Application Support/binja-agent-mcp/token` on macOS and `$XDG_STATE_HOME/binja-agent-mcp/token`
(default `~/.local/state/binja-agent-mcp/token`) on Linux; `BN_MCP_TOKEN_FILE` changes it for all three
components. On macOS and Linux the file is created with mode 0600. On Windows the file inherits the access list of
its folder; by default the user profile, which holds `%LOCALAPPDATA%`, gives access to your account, SYSTEM and
Administrators. If other accounts were granted access to that folder (check with `icacls "%LOCALAPPDATA%"`), or if
you point `BN_MCP_TOKEN_FILE` elsewhere, choose a folder that only you can read.

**What the checks protect against.** Web pages you visit (cross-site requests and DNS rebinding), and other OS
users on the same computer, who cannot read your token file: they can neither read the analysis nor change it.
Upstream had no such checks and sent `Access-Control-Allow-Origin: *`, so any web page that the browser let reach
`127.0.0.1` could read its answers and trigger its GET routes that change the analysis (for example `/patch`,
`/renameVariable` and `/retypeVariable`).

**What they do not protect against.**

- Software that runs as your own OS user: it can read the token file, and it could control Binary Ninja directly
  anyway. Treat the bridge like any other tool that you let an agent run.
- Availability. Any local process can open connections to the port. The server closes a connection that sends
  nothing for 15 seconds and serves at most 256 connections at once (the rest are closed at once, and the refusal
  is logged at most once a minute), so such a process can delay the server, but it cannot make it run Binary Ninja
  work.
- A server that is not this plugin. The token proves the client to the server, but nothing proves the server to the
  bridge: a process of another user that binds `127.0.0.1:9009` before Binary Ninja does receives the bridge's
  requests and can send forged answers to the agent. It gets no valid token, because only a server that holds the
  port writes one. Binary Ninja logs an error when the plugin cannot bind the port; that is the sign to look for.

**What a caller with the token can do.** Read everything Binary Ninja has loaded; make Binary Ninja open files your
OS user can read (`bn_load_binary`, `/load`; at most 8 at a time); change the analysis in memory (rename, retype,
comments, function creation, `patch_bytes`). The file on disk is written only by `patch_bytes(save_to_file=true)`,
and only when Binary Ninja runs with `BN_MCP_ALLOW_SAVE=1`; it is refused for a view opened from a `.bndb`
database, because saving would write the raw patched image over the database. On macOS, a saved file is also
re-signed with an ad-hoc signature (`codesign --remove-signature`, then `codesign -f -s -`), as upstream did.

**Untrusted input reaches the model.** Strings, symbol names and comments in an analyzed binary become part of tool
answers, so a hostile binary can contain text written to steer an agent. Review what an agent proposes before you
act on it, and keep write tools out of the tool set (`BN_MCP_TOOLS`) when you analyze files you do not trust. Two
refusals close paths that such text could use to reach the network:

- **Network and device paths.** On Windows, even testing whether `\\host\share\file` exists makes the computer
  connect to that host and authenticate with your Windows credentials. Loads therefore check the path as text first
  and refuse UNC paths, device paths (`\\.\`, `\\?\`, `\??\`) and files on network drives (403 `POLICY`), before any
  file-system call; the real path of a junction or link is checked again. `BN_MCP_ALLOW_NETWORK_PATHS=1` allows
  UNC paths and network drives, never device paths.
- **Files named in C text.** Binary Ninja's type parser preprocesses the C text of `declare_c_type`, `define_types`,
  `set_function_prototype` and the retype tools, and reads every file an `#include` names. Text with `#include`,
  `#include_next`, `#import`, `#embed` or `__has_include` is refused (403 `POLICY`); declare the types themselves.

**Other effects on your system.** The plugin writes MCP client configuration files only when you run the installer
or set `BN_MCP_AUTO_SETUP=1`. The bridge connects only to `BN_MCP_URL`. Nothing in this repository sends data
anywhere else; the only downloads are the `pip install` runs (step 3 of [Install](#install), the installer, or
`BN_MCP_AUTO_SETUP=1` when the plugin's `.venv` is missing). Nothing here needs administrator rights, and nothing
installs a service or a scheduled task. Request bodies and query strings are not written to the Binary Ninja log:
one debug-level line per request names the method, the path and the status. An error line can still name what a
failed request referred to, for example `Could not find function: <name>`.

**Reporting a vulnerability.** See [SECURITY.md](SECURITY.md).

## Limitations

- Preview: the plugin has not been run inside Binary Ninja yet (see [Tests](#tests)). The fake `binaryninja` module
  models only the API the plugin uses; it is not Binary Ninja, so a difference between the fake and a real Binary
  Ninja can hide a defect.
- The suite was run on Windows only; the CI workflow is its first run on macOS and Linux.
- The analysis tools report what Binary Ninja's static analysis shows. Dominance, slices, value sets and "unchecked"
  results are hints that can miss behaviour; each such tool lists its blind spots in its answer.
- `per-view` lock mode lets requests for different binaries run at the same time. Binary Ninja documents no
  thread-safety guarantee for this, so it is experimental. In the default `global` mode one lock serializes the
  Binary Ninja work of every request that reads or changes a binary, and of `/load` and `/x/loadBinary`; `/status`,
  `/binaries`, `/selectBinary`, `/platforms`, `/convertNumber`, `/x/compute` and `/x/serverInfo` run without it (they
  read file names, the platform list or the core version, or no Binary Ninja state).
- The bridge reads the tool set once, at start. Restart the MCP client after you change it.
- Answers above the output cap are cut (upstream tools) or refused (`bn_*` tools); ask for smaller pages.

## Tests

```
python -I tests/run_tests.py
```

The offline suite needs no Binary Ninja: it runs the plugin's real code against a fake `binaryninja` module
(`tests/fake_bn/`) and uses only `127.0.0.1` with ports chosen by the operating system. Every server it starts
writes its token file into a temporary directory, `BN_MCP_URL` points at a closed port, and a guard makes any
connection of the test process to port 9009 fail, so it never touches a Binary Ninja that may be running. The
bridge tests need `mcp`, `requests` and `anyio`. The backward-compatibility tests compare the plugin with upstream
when `BN_MCP_TEST_BASELINE` points at a checkout of upstream v1.1.0 (outside this repository):

```
git clone --depth 1 --branch v1.1.0 https://github.com/fosdickio/binary_ninja_mcp <dir>
```

The workflow `.github/workflows/tests.yml` runs pyflakes and the suite on Windows, macOS and Linux with Python
3.10 to 3.14 for every push and pull request, with such a checkout as the baseline (the workflow stops if the tag
no longer names commit `d8a2709df69ff475d6be6366c2eec733663b008b`); its results are on the repository's Actions
page. The local result (Windows only) is in [tests/README.md](tests/README.md#result), which also describes each
test module.

**Live checks (to do before this release leaves preview).** The suite cannot show how the plugin behaves inside
Binary Ninja. With a public sample binary, on a real Binary Ninja build:

1. Start the server from the menu with no binary open, and from the status-bar button.
2. Open two binaries in two UI tabs; `list_binaries` shows both. Close one tab; it leaves the list within 2 seconds.
3. Run `python tools/smoke_test.py --binary <absolute path to a copy of the sample>`: it loads the copy, waits for
   the analysis, decompiles the entry function, lists its cross-references, renames it, checks the new name and
   closes the binary, and prints one JSON line per step.
4. Stop the server from the menu.

## Repository layout

| Path | What it is |
|---|---|
| `binja_agent_mcp/` | The Binary Ninja plugin and the MCP bridge. This is the folder you install. |
| `bn_mcp_client.py` | A standard-library command-line client of the HTTP API: `caps` and `pack` |
| `tests/` | The offline test suite and its fake `binaryninja` module |
| `tools/` | `smoke_test.py` (the live check above) and `measure_tool_definitions.py` (the table above) |
| `.github/workflows/tests.yml` | The CI workflow |
| [NOTICE.md](NOTICE.md) | Attribution, and which files are modified, added, unchanged or not included |
| [CHANGES-FROM-UPSTREAM.md](CHANGES-FROM-UPSTREAM.md) | The dated list of changes required by GPL-3.0 section 5 |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability |
| [LICENSE](LICENSE) | The GNU General Public License v3.0 (identical to `binja_agent_mcp/LICENSE`) |

## Related projects

Other repositories by the same author:

- [windbg-hyperv-mcp](https://github.com/y637F9QQ2x/windbg-hyperv-mcp): an MCP server for Windows kernel and
  user-mode debugging of one Hyper-V guest.
- [hyperv-lpe-lab](https://github.com/y637F9QQ2x/hyperv-lpe-lab): PowerShell scripts for a headless Hyper-V lab,
  with VM control that needs no elevation and guest commands over SSH as an administrator or as a standard user.
- [win-agent-probes](https://github.com/y637F9QQ2x/win-agent-probes): PowerShell probes for Windows security
  research; each prints one JSON document.
- [winremote-session-ext](https://github.com/y637F9QQ2x/winremote-session-ext): an extension for winremote-mcp that
  reports the Windows logon session the server runs in and restricts how its HTTP endpoint can be exposed.

The author's blog: [y637f9qq2x.com](https://y637f9qq2x.com).

## Credits and license

binja-agent-mcp is a modified version of **Binary Ninja MCP** by **fosdickio** and **CX330Blake**, including the
contributions of the binary_ninja_mcp contributors (https://github.com/fosdickio/binary_ninja_mcp). It is based on
upstream release v1.1.0 (git tag `v1.1.0`, commit `d8a2709df69ff475d6be6366c2eec733663b008b`, 2025-12-16). The
modifications are by Kazuma Matsumoto ([y637F9QQ2x](https://github.com/y637F9QQ2x)).

- Original work: Copyright (C) 2025 fosdickio, CX330Blake
- Modifications: Copyright (C) 2026 Kazuma Matsumoto (2026-10-14 to 2026-11-18)

License: GPL-3.0-or-later. Upstream's `plugin.json` grants the GPL "either version 3 of the License, or (at your
option) any later version", and this project keeps that grant. See [LICENSE](LICENSE).

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
details. You should have received a copy of the GNU General Public License along with this program (see
[LICENSE](LICENSE)). If not, see <https://www.gnu.org/licenses/>.

"Binary Ninja" is a trademark of Vector 35 Inc. Please report problems with binja-agent-mcp in this repository, not
to the upstream authors or to Vector 35.
