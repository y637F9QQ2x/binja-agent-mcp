# NOTICE

binja-agent-mcp, version 1.0.0

Copyright (C) 2025 fosdickio, CX330Blake (original "Binary Ninja MCP" plugin)
Copyright (C) 2026 Kazuma Matsumoto (modifications and additional components)

The original plugin includes the contributions of the binary_ninja_mcp contributors
(https://github.com/fosdickio/binary_ninja_mcp).

binja-agent-mcp is a MODIFIED VERSION of the "Binary Ninja MCP" plugin by fosdickio and CX330Blake,
https://github.com/fosdickio/binary_ninja_mcp. It is based on upstream tag v1.1.0, commit
d8a2709df69ff475d6be6366c2eec733663b008b ("Update version to 1.1.0 in plugin.json", 2025-12-16). The modifications
were made between 2026-10-14 and 2026-11-18. It is not the upstream project, and it is not endorsed by the upstream
authors or by Vector 35 Inc.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with this program (see LICENSE). If not, see
<https://www.gnu.org/licenses/>.

Upstream's `plugin.json` grants the GPL "either version 3 of the License, or (at your option) any later version";
this project keeps that grant (GPL-3.0-or-later).

## Upstream files MODIFIED by Kazuma Matsumoto (2026-10-14 to 2026-11-18)

Paths are relative to `binja_agent_mcp/`, which corresponds to the root of the upstream repository.

- `bridge/binja_mcp_bridge.py`
- `bridge/requirements.txt`
- `plugin/__init__.py`
- `plugin/api/endpoints.py`
- `plugin/core/binary_operations.py`
- `plugin/core/config.py`
- `plugin/server/http_server.py`
- `plugin/utils/auto_setup.py`
- `plugin/utils/python_detection.py`
- `scripts/mcp_client_installer.py`
- `plugin.json` (name, version, author, type, descriptions, license text and URLs)
- `README.md` (replaced by a short description of the folder that points to the repository README)

Every modified upstream Python file carries a header that says it was modified, by whom and when.
[CHANGES-FROM-UPSTREAM.md](CHANGES-FROM-UPSTREAM.md) describes the changes.

## Files ADDED (Copyright (C) 2026 Kazuma Matsumoto, GPL-3.0-or-later)

- `binja_agent_mcp/plugin/core/expert_ops.py`, `local_auth.py`, `request_context.py`
- `binja_agent_mcp/plugin/utils/mcp_clients.py`
- `bn_mcp_client.py`
- `tests/` (the offline test suite and the `fake_bn` test double)
- `tools/smoke_test.py`, `tools/measure_tool_definitions.py`
- `.github/workflows/tests.yml`
- At the repository root: `README.md`, `NOTICE.md`, `CHANGES-FROM-UPSTREAM.md`, `SECURITY.md`, `.gitignore`,
  `.gitattributes`, and `LICENSE` (an identical copy of `binja_agent_mcp/LICENSE`)

## Upstream files distributed UNCHANGED

- `binja_agent_mcp/LICENSE`, `binja_agent_mcp/__init__.py`
- `binja_agent_mcp/plugin/utils/number_utils.py`, `binja_agent_mcp/plugin/utils/string_utils.py`
- the empty package files `binja_agent_mcp/plugin/api/__init__.py`, `core/__init__.py`, `server/__init__.py`,
  `utils/__init__.py`

## Upstream content NOT included

- `docs_for_llms/` (rendered snapshots of Vector 35's Binary Ninja documentation; the current documentation is at
  https://docs.binary.ninja/)
- `scripts/setup_claude_desktop.py` (a macOS-only Claude Desktop setup script; `scripts/mcp_client_installer.py`
  covers the same client)
- `images/`, `example/` and upstream's `.gitignore`

## Third-party notices

- Binary Ninja is proprietary software of Vector 35 Inc. No part of it (program files, libraries, license files or
  documentation) is included in this repository. "Binary Ninja" is a trademark of Vector 35 Inc., used here only to
  name the software this project works with.
- `tests/fake_bn/` is an independent test double written for this project. It contains no Binary Ninja code. Its
  module, class and enumeration names, and the enumeration values the plugin depends on, follow the public Binary
  Ninja Python API (https://github.com/Vector35/binaryninja-api, Copyright (c) 2015-2026 Vector 35 Inc, MIT
  License); the other enumeration values are numbered in sequence and do not match Binary Ninja's.
- The NDR format-character names and values in `binja_agent_mcp/plugin/core/expert_ops.py` follow Microsoft's
  documentation (MS Learn, "Format Strings" and "Parameter Descriptors") and the `ndrtypes.h` headers of Wine and
  MinGW-w64; only constant names and values are used, no code.
- The Python packages the bridge needs (`binja_agent_mcp/bridge/requirements.txt`: `mcp`, `requests` and their
  dependencies) are installed separately by the user, under their own licenses, and are not redistributed here.
