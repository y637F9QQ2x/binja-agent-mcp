# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | yes |

Fixes go into the next release; there are no backports.

## Reporting a vulnerability

Please report a vulnerability privately, through GitHub's private vulnerability reporting for this repository: the
"Security" tab, then "Report a vulnerability". Do not open a public issue for a security problem.

Include the binja-agent-mcp version, your operating system and Binary Ninja build, the steps that reproduce the
problem, and what an attacker gains (for example: who can send the request, and what it reads or changes).

This project is maintained by one person. Reports are answered as time allows; there is no guaranteed response
time.

## Scope

The trust model is in [README.md](README.md#security-and-trust-model): what the checks of the localhost server
protect against, and what they do not. A report that shows a way around one of those checks (the Host allowlist,
the refusal of browser requests, the per-run token, the refusal of network paths and of file-naming C text) is in
scope. Binary Ninja itself, the MCP clients and the Python packages the bridge uses are maintained by others;
please report problems in them to their maintainers.
