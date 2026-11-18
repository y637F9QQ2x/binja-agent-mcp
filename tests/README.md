# binja-agent-mcp: offline test suite

These tests cover the plugin's HTTP server and verbs, the Binary Ninja glue (`binja_agent_mcp/plugin/__init__.py`,
with a stand-in for `binaryninjaui`), the MCP bridge (`binja_agent_mcp/bridge/binja_mcp_bridge.py`), the MCP client
installer, the command-line client `bn_mcp_client.py` and the scripts in `tools/`. They need no Binary Ninja: the
plugin's real code runs against a fake `binaryninja` module. They use only the standard library (`unittest`); the
bridge tests also need the `mcp`, `requests` and `anyio` packages.

## Run it

```
python -I tests/run_tests.py [--plugin DIR] [--client PATH] [-k TEXT] [-v]
```

- `--plugin DIR`: the plugin tree to test (the directory that holds `plugin/`, `bridge/` and `plugin.json`; default
  `../binja_agent_mcp`).
- `--client PATH`: the `bn_mcp_client.py` to test (default `../bn_mcp_client.py`).
- `-k TEXT`: run only the tests whose id contains `TEXT` (repeatable); `-v`: verbose.

Exit codes: 0 = every test passed (skips allowed), 1 = a failure or an error, 2 = a usage error.

## Optional input

`BN_MCP_TEST_BASELINE`: a checkout of the upstream plugin at tag `v1.1.0` (commit
`d8a2709df69ff475d6be6366c2eec733663b008b`), outside this repository. With it, the backward-compatibility tests
compare every legacy HTTP route and every upstream tool name with upstream; without it, those tests are reported as
SKIPPED with the reason, never as passed.

```
git clone --depth 1 --branch v1.1.0 https://github.com/fosdickio/binary_ninja_mcp <dir>
```

The CI workflow (`.github/workflows/tests.yml`) makes this checkout in the runner's temporary directory, checks that
the tag still names that commit, and sets `BN_MCP_TEST_BASELINE` for the suite.

## Result

Run on 2026-11-18 on Windows 11 with Python 3.14.6, mcp 1.27.2, requests 2.34.2 and anyio 4.13.0:

| Configuration | Result |
|---|---|
| without `BN_MCP_TEST_BASELINE` | `Ran 212 tests ... OK (skipped=9)`: the six backward-compatibility tests and the upstream measurement are skipped as well |
| `BN_MCP_TEST_BASELINE` set | not run again after the last changes (the bind policy, the token file, the `claude mcp add` command, the plugin switches); the run before them gave `Ran 210 tests ... OK (skipped=2)`. The CI workflow runs this configuration. |

Two tests are skipped in every configuration here: `VenvRerun` re-runs the bridge tests under `<plugin>/.venv` and
runs only when the current Python cannot import `mcp`, and `test_two_real_files_that_differ_only_by_case` needs a
case-sensitive file system. macOS and Linux were not run locally; the CI workflow (`.github/workflows/tests.yml`)
runs them.

## How it works

- `fake_bn/binaryninja/` is an offline fake of the Binary Ninja Python API. It is not Binary Ninja and contains no
  Binary Ninja code. `run_tests.py` puts `fake_bn/` first on `sys.path`, so the plugin's `import binaryninja` binds to
  the fake, and refuses to run if a real `binaryninja` module is loaded.
  - `enums.py`: the enumerations, as `enum.IntEnum` (`AnalysisState.IdleState == 2`).
  - `binaryview.py`: the object model and a fixed test program (`main`, `helper`, `leaf`, `dispatch` with a diamond
    CFG, `slice_target` with a phi cycle, two functions named `dup`, `values_fn`, `getinput`, imports, strings, a data
    symbol and a struct type). Rendering derives from the current bytes, so a patch changes disassembly and HLIL.
    `ACTIVITY` counts concurrent simulated Binary Ninja work per view; `save()` only records the call.
  - The fake's views compare by identity. Binary Ninja's `BinaryView` compares and hashes by its core handle and
    creates a new Python wrapper per call; `test_plugin_glue` models that with a test-local wrapper class.
- The plugin's `core`, `server` and `api` modules are imported through a synthetic parent package (`bnmcp_live`), so
  `plugin/__init__.py` does not run there; `test_plugin_glue` executes it on its own, with a stand-in for
  `binaryninjaui` and the server port set to 0.
- Every server a test starts listens on `127.0.0.1` with a port chosen by the operating system (never 9009) and
  writes its token file into a temporary directory; `BN_MCP_TOKEN_FILE` points into the suite's temporary directory
  and `BN_MCP_URL` at a closed port for the whole run, and a tripwire makes any connect of the test process to
  `127.0.0.1:9009` fail. No test reads or writes the token file of a Binary Ninja that may be running, and none can
  reach it.
- `BN_MCP_*` variables are cleared before the run (the `BN_MCP_TEST_*` inputs are kept), `sys.dont_write_bytecode` is
  set, and every file a test creates lives in a temporary directory. The installer tests point `HOME`,
  `USERPROFILE` and `APPDATA` at a temporary directory and check every target path before the installer runs.
- No test opens a network path: the load-path tests guard `os.path.isfile`, `os.path.realpath`, `os.stat` and
  `os.path.exists` so that a UNC path fails the test instead of reaching the network.

## What is covered

| Module | Checks |
|---|---|
| `test_resolution_and_scoping` | Every `binary` selector form; duplicate names give 409 with candidates, unknown ones 404 with `available`, relative paths 400; paths and names compared without case on Windows only (the POSIX rules are also checked on Windows); per-thread request scopes; nested scopes restore their state. |
| `test_http_threading` | The real threaded server: global and per-view lock modes, lock order, bounded waits (503 `BUSY`), health paths while a view is locked, the bind policy (no second listener on a port; a restart binds at once; the socket options per platform), POST routes, non-ASCII headers, 410 `GONE` behind a close. |
| `test_backcompat_routes` | Every legacy route answers with the same status and a superset of the upstream JSON keys (with the baseline); `patch_bytes` save policy; the exact key set of the `/status` server block; the Python 3.10 grammar of every plugin file. |
| `test_expert_ops` | The verbs behind the `bn_*` tools on the fake program, including the context pack's fail-closed rules (patched bytes, unfinished analysis), the batch verb and the exact route tables. |
| `test_bridge` | Every registered tool through FastMCP: selector forwarding, routes, POST fallback, the HTTP concurrency gate, the retry policy, the worker-thread limiter and the respond-once guard; proxy variables are ignored; `BN_MCP_URL` accepts the loopback server only; the `/status` probe stays inside the call deadline; the watchdog's choice of processes; the `binary` schema description; `_meta` for an output cap above 50,000. |
| `test_toolsets` | Tool-set selection and its error cases, tool-set membership, no overlapping pair in `core`, the definitions sent per set (no `outputSchema`, no generated titles, valid `See also` lines, the 4,096-character description limit), the README measurement table, and the output cap. |
| `test_local_auth` | The Host allowlist, the refusal of browser requests, the token (missing, wrong, truncated), refused state-changing requests that have no effect, no CORS header, the token-file lifecycle (including a temporary file with a new name that leaves a planted file alone), the same token-file path in plugin, bridge and client, and the bridge end to end. |
| `test_bn_mcp_client` | `caps` and `pack` against stub servers and the real server: the token header, every refusal reason, BUSY retries, bad `--out` paths, `--overwrite`, atomic writes, the one-line output, `caps --strict` exit codes, the loopback-only URL. |
| `test_load_binary` | `/load` and `/x/loadBinary`: idempotent loads, no second view for an unchanged file. |
| `test_static_rules` | No dialog or focus API, no `execute_on_main_thread_and_wait`, no CORS header, child processes without a console window; `/status` never calls the main thread; an unknown route is a 404. |
| `test_plugin_glue` | `plugin/__init__.py`: global menu commands with no argument (and the fallback to `register`), a start with no binary open that selects the active tab, `OnBeforeCloseFile` never vetoes a close, `OnAfterCloseFile` releases only the closed file, an invalid `BN_MCP_AUTOSTART` or `BN_MCP_AUTO_SETUP` value is off and logged once; the registry keeps the views of open tabs after their wrappers are gone and drops closed ones. |
| `test_hardening` | Load paths: UNC, device and network-drive paths and links to a share are refused before any file-system call, `BN_MCP_ALLOW_NETWORK_PATHS`, the cap on binaries the server loaded; C text that names a file is refused; `patch_bytes` never saves over a `.bndb`; with `BN_MCP_REQUIRE_TOKEN=0` only reads are served without the token; idle connections are closed, connections above the limit are closed at once, many idle connections leave the server answering, refusals are logged once a minute; the load routes take the global lock; no request data in the log. |
| `test_mcp_clients` | The client table (a timeout only where a client documents one, in its unit; Claude Code gets a command, with its `--env` pairs before `--scope`), install and uninstall that keep other entries, invalid files left alone, pip and interpreter failures reported, and the installer CLI (`--list`, read-only `--config`, `--install --python`, no configuration without the packages, no flag). |
| `test_tools` | `tools/smoke_test.py` against the real server (every step passes, a refused token fails the first step) and `tools/measure_tool_definitions.py` (equal to the bridge's `--list-tools`; 53 tools for upstream's bridge with the baseline). |
