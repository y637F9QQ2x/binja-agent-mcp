# Changes from upstream (GPL-3.0 section 5 notice)

binja-agent-mcp 1.0.0 is a MODIFIED version of fosdickio/binary_ninja_mcp v1.1.0 (commit
d8a2709df69ff475d6be6366c2eec733663b008b, 2025-12-16). Modified by Kazuma Matsumoto between 2026-10-14 and
2026-11-18; date of this release: 2026-11-18. Server and bridge contract: `binja-agent-mcp/1`.

The upstream repository root corresponds to `binja_agent_mcp/` here. To see every change, check out upstream tag
v1.1.0 and compare its files with `binja_agent_mcp/` (with line endings normalized to LF).

## Upstream files changed

- `bridge/binja_mcp_bridge.py`
  - Tool sets: only the tools selected by `BN_MCP_TOOLSET` (`core` by default, `analysis`, `upstream`, `full`) or
    `BN_MCP_TOOLS` are registered; an invalid selection stops the bridge. `--list-tools` prints the selected tools
    and the size of their definitions. `core` includes `bn_load_binary` and `bn_close_binary`.
  - Tool definitions: unstructured output only (no `outputSchema`), input schemas without generated `title` fields,
    one short schema description for every `binary` parameter, rewritten short descriptions, and `See also:` lines
    between overlapping tools that are removed when the named tool is not registered. A server instruction for
    clients with tool search.
  - Output cap: every answer is at most 48,000 characters (`BN_MCP_MAX_OUTPUT_CHARS`; a cap above 50,000 is
    declared per tool with `_meta["anthropic/maxResultSizeChars"]`); upstream (text) tools are cut at a line
    boundary with a `[TRUNCATED by the bridge: ...]` line, `bn_*` answers above the cap are refused with
    `REFUSED_SIZE`, `list_all_strings` stops at the cap with an `[INCOMPLETE: ...]` line, and list answers are sent
    as one text block.
  - Every request carries the plugin's per-run token (`X-BN-MCP-Token`) read from the token file, goes only to the
    loopback server of `BN_MCP_URL` (another host stops the bridge) and never through an HTTP proxy (`requests`
    sessions with `trust_env` off).
  - Every tool that works on a binary takes an optional `binary` selector; correct URL encoding; tools run in worker
    threads with per-call deadlines (the `/status` probe included) and a per-server concurrency gate; a
    respond-once guard for client-cancelled calls (it says so on stderr when it cannot be installed); a
    parent-process watchdog that also watches the MCP client behind a Windows venv launcher.
  - 33 new `bn_*` tools (see README.md), with small default pages. Paging parameters on `decompile_function`,
    `get_il` and `fetch_disassembly`. `patch_bytes(save_to_file)` defaults to false (upstream: true).
- `bridge/requirements.txt`: `mcp[cli]>=1.6.0` became `mcp==1.27.2` (without the `cli` extra; the version the
  bridge was tested with, because the respond-once guard patches an mcp internal); `anthropic>=0.49.0` removed (the
  bridge does not use it); `requests>=2.32.3` unchanged.
- `plugin/__init__.py`: the menu commands are global commands (`PluginCommand.register_global`, with zero-argument
  callbacks; `register` on builds without it), so the server starts without an open binary; it starts by itself only
  with `BN_MCP_AUTOSTART=1` (a value other than 0 or 1 of this switch or of `BN_MCP_AUTO_SETUP` is logged as a
  warning); the views open in UI tabs are registered from `UIContext.getAvailableBinaryViews` on the UI
  notifications and every 2 seconds, and released when their file is closed (`OnAfterCloseFile` with its
  `FileContext`; `OnBeforeCloseFile` returns True); the binary-view event hooks and the 1-second UI monitor were
  removed; message boxes became log lines; MCP client configuration files are written at load only with
  `BN_MCP_AUTO_SETUP=1` (upstream wrote them on the first start); the status-bar text has no emoji.
- `plugin/server/http_server.py`: Host allowlist, refusal of browser requests and the per-run token on every request
  (`plugin/core/local_auth.py`); with `BN_MCP_REQUIRE_TOKEN=0` a request without the token may only read; no
  `Access-Control-Allow-Origin` header (upstream sent `*`); the token file is written after the bind and removed on
  stop; a thread-per-connection server with a global (default) or per-view lock and bounded waits, a 15-second idle
  timeout per connection and at most 256 connections at once; the load routes hold the global lock in global mode;
  refusals are logged at most once a minute per reason; structured JSON errors; the `_binary` echo and the
  `X-BN-Binary` header; a `server` block in `/status`; the `/x/*` routes; paging for `/decompile`, `/il` and
  `/assembly`; C text that names a file (`#include` and the like) is refused; on Windows no `SO_REUSEADDR` unless
  `BN_MCP_REUSEADDR=1` (macOS and Linux keep it, as upstream did, and `SO_REUSEPORT` is never set); a `DELETE`
  handler; one hexdump formatter instead of three copies. The request line (with its query string) and request
  bodies are no longer written to the Binary Ninja log: one debug-level line per request gives the method, the path
  and the status, and the per-request info lines are debug lines (an error line can still name the function or
  variable a failed request referred to).
- `plugin/api/endpoints.py`: per-request binary resolution; dispatch of the `bn_*` verbs; a verb without a binary in
  scope answers 404 `NOT_FOUND` with `available`; the `/binaries` listing compares paths and names with the
  resolver's own rules and no longer advertises the positional `#<n>` selector; the unused method `get_status`
  was removed.
- `plugin/core/binary_operations.py`: a view registry and selector resolution (view id, ordinal, sha256, path,
  basename), with paths and names compared without case on Windows only; views open in the UI are held while their
  tab is open; per-view locks; server-owned views, at most `BN_MCP_MAX_OWNED` (default 8); loading through the core
  API; load paths are checked before any file-system call (no UNC, device or network-drive path unless
  `BN_MCP_ALLOW_NETWORK_PATHS=1`); `patch_bytes(save_to_file=True)` is refused unless `BN_MCP_ALLOW_SAVE=1`, and for
  a view opened from a `.bndb`; a record of `patch_bytes` writes per view; leftover debug log lines, unused imports
  and variables, and the method `unregister_by_filename` (no longer called) removed.
- `plugin/core/config.py`: identity and contract; validated `BN_MCP_*` settings, including `BN_MCP_REQUIRE_TOKEN`,
  `BN_MCP_TOKEN_FILE`, `BN_MCP_ALLOW_NETWORK_PATHS` and `BN_MCP_MAX_OWNED`; the unused fields `debug`,
  `api_version` and `log_level` were removed.
- `plugin/utils/auto_setup.py`: runs only with `BN_MCP_AUTO_SETUP=1` and uses `plugin/utils/mcp_clients.py` (see
  the installer below); it writes nothing unless the bridge's interpreter can import its packages; the copy of
  upstream's legacy key `binary_ninja_mcp_max` was removed.
- `plugin/utils/python_detection.py`: no console windows for child processes; every return code is checked; pip's
  output is shown (or kept for the error message), with a 900-second limit; an environment whose packages are
  missing is repaired by the next run; `get_python_executable` (no longer called) removed.
- `scripts/mcp_client_installer.py`: the key `binja_agent_mcp`; a tool timeout only where a client documents one,
  in its unit (`"timeout": 60` seconds for Cline and Roo Code; upstream wrote `"timeout": 1800` into every client,
  which is 30 minutes where the unit is seconds and 1.8 seconds where it is milliseconds, the unit Claude Code
  documents for its per-server timeout); for Claude Code the `claude mcp add` command is printed instead of editing
  `~/.claude.json`; atomic writes; no configuration
  is written unless the interpreter can import `mcp`, `requests` and `anyio`; `--config` and `--list` are read-only;
  `--python` and `--copy-python-env`; no change without a flag (upstream installed by default).
- `plugin.json` and `README.md`: the identity and notices of this project; `type` is `helper` only (upstream also
  listed `core`, `binaryview` and `architecture`).

## Files added (not in upstream)

- `plugin/core/expert_ops.py` (the verbs behind the `bn_*` tools), `plugin/core/local_auth.py` (request
  authentication), `plugin/core/request_context.py` (per-request binary scope), `plugin/utils/mcp_clients.py` (the
  MCP client table shared by the installer and the auto-setup)
- `bn_mcp_client.py`, a standard-library command-line client
- `tests/`, the offline test suite
- `tools/smoke_test.py` (a smoke test of a running server) and `tools/measure_tool_definitions.py` (the measurement
  behind the README's tool table)
- `.github/workflows/tests.yml`, the CI workflow
- At the repository root: `README.md`, `NOTICE.md`, `CHANGES-FROM-UPSTREAM.md`, `SECURITY.md`, `.gitignore`,
  `.gitattributes` and `LICENSE` (an identical copy of `binja_agent_mcp/LICENSE`)

## Upstream content not included

`docs_for_llms/`, `scripts/setup_claude_desktop.py`, `images/`, `example/` and `.gitignore` (see NOTICE.md).

## Unchanged from upstream

`LICENSE`, `__init__.py`, `plugin/utils/number_utils.py`, `plugin/utils/string_utils.py` and the empty
`plugin/{api,core,server,utils}/__init__.py`.

## Behaviour changes users of upstream will notice

- The bridge registers 25 tools by default. `BN_MCP_TOOLSET=upstream` gives the 53 upstream tool names,
  `BN_MCP_TOOLSET=full` every tool.
- Every HTTP request needs the `X-BN-MCP-Token` header (the bridge and `bn_mcp_client.py` send it). The upstream
  bridge, `curl` without the header and web pages are refused. `BN_MCP_REQUIRE_TOKEN=0` lets requests without the
  token read, never change anything.
- Answers longer than 48,000 characters are cut or refused, with a marker that says how to page.
- Binary Ninja no longer starts the server by itself and no longer edits MCP client configuration files by itself.
- No message boxes are shown.
- `patch_bytes` no longer saves to disk by default; saving needs `save_to_file=true` and `BN_MCP_ALLOW_SAVE=1`.
- Loads refuse UNC paths, device paths and files on network drives; C text with `#include` is refused.
- On Windows, port 9009 is bound without `SO_REUSEADDR`: a second server fails instead of sharing the port. On
  macOS and Linux the port is bound with `SO_REUSEADDR`, as upstream did; there it does not let a second server
  listen on the port.
- The MCP server entry is named `binja_agent_mcp` (upstream: `binary_ninja_mcp`).

## Moving from the earlier release of this code

The modifications were first published on 2026-10-30 as `binja-mcp-advanced`. For a user of that release:

- the server and bridge contract is now `binja-agent-mcp/1`; the `/status` key `fork_version` is now `version`,
  and the `_binary` key `stock_modified` is now `modified`;
- the six `bn_vp_*` tools and their `/vp/*` routes are gone;
- the MCP client auto-setup is opt-in (`BN_MCP_AUTO_SETUP=1`), the bridge registers the `core` tool set unless told
  otherwise, and every request needs the per-run token;
- `bn_mcp_client.py pack` writes a pack to any path (`--overwrite` replaces an existing file) and prints one JSON
  line.

Every upstream route and every upstream MCP tool name is still available. The offline test suite compares the HTTP
routes and the tool names with upstream v1.1.0 when `BN_MCP_TEST_BASELINE` points at an upstream checkout.
