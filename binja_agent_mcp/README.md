# binja_agent_mcp

This folder is the Binary Ninja plugin of binja-agent-mcp. Install it as described in the
[repository README](../README.md#install).

| Path | What it is |
|---|---|
| `plugin/` | The plugin: the HTTP server (`server/`), the routes (`api/`), the analysis code (`core/`) and helpers (`utils/`) |
| `bridge/` | The MCP bridge that your MCP client starts (`binja_mcp_bridge.py`) and its Python requirements |
| `scripts/mcp_client_installer.py` | Adds or removes the MCP server entry in the configuration of supported MCP clients |
| `plugin.json` | Binary Ninja plugin metadata |
| `LICENSE` | GNU General Public License v3.0, the license of the upstream plugin and of this modified version |

This folder replaces the README of the upstream plugin, "Binary Ninja MCP" by fosdickio and CX330Blake
(https://github.com/fosdickio/binary_ninja_mcp). See [NOTICE.md](../NOTICE.md) for the attribution and the list of
changed files.
