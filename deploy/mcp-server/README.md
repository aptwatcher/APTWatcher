# Deploy — Mode B (Custom MCP Server)

Mode B runs APTWatcher as a standalone MCP server over stdio. Any
MCP-capable client — Claude Desktop, Cursor, a custom Python runner,
another agent — can attach and call the registered tools.

Use this mode when:

- You want APTWatcher available to a host agent that already speaks MCP.
- You're running headless (CI, scheduled triage, batch replay).
- You want tier gating enforced by the server rather than the client prompt.

## Requirements

- Python 3.11+.
- `mcp>=1.2` (installed transitively via `uv sync`).
- `config.yaml` for anything past Tier 0. The Tier 0 default needs no config.

## Install

```bash
cd APTWatcher
uv sync
aptwatcher-mcp --help
```

## Run

Tier 0 only — no auth, no external calls:

```bash
aptwatcher-mcp                         # stdio transport
# or:
python -m mcp_server.server
```

With a full config (Tier 1+ adapters gated per-tier):

```bash
aptwatcher-mcp --config ./config.yaml --knowledge-root ./knowledge
```

Environment variables:

- `APTWATCHER_CONFIG` — default config path.
- `APTWATCHER_KB_ROOT` — default knowledge base root.

## Tools exposed (Tier 0)

| Tool                  | Purpose                                             |
|-----------------------|-----------------------------------------------------|
| `preflight`           | Probe SIFT tool inventory, hash evidence.           |
| `list_profiles`       | Return registered use-case profiles.                |
| `knowledge_search`    | Keyword search across `knowledge/`.                 |
| `knowledge_get`       | Fetch one KB entry by id.                           |
| `aptwatcher_version`  | Server version string.                              |

Tier 1–4 tools register conditionally based on `config.yaml`. They do
not appear in the client's tool list if the config disables them.

## Attaching from a client

**Claude Desktop** — add to `~/Library/Application
Support/Claude/claude_desktop_config.json` (macOS) or the equivalent
Windows path:

```json
{
  "mcpServers": {
    "aptwatcher": {
      "command": "aptwatcher-mcp",
      "args": ["--config", "/abs/path/to/config.yaml"],
      "env": { "APTWATCHER_KB_ROOT": "/abs/path/to/knowledge" }
    }
  }
}
```

**Custom Python client** — import `from mcp_server.server import build_server`
and run its `.run(transport="stdio")` from your harness.

## Troubleshooting

- No tools visible to the client: confirm the client picked up the
  config by watching stderr; `aptwatcher-mcp --help` must succeed
  standalone first.
- `preflight` returns `ok: false` repeatedly: a tool on the profile's
  required list is missing; the reported name is the exact binary name
  on `PATH`.

## References

- [MCP tool inventory](../../docs/reference/mcp-tools.md)
- [Tier model](../../docs/architecture/tier-model.md)
- [Integrations](../../docs/integrations/README.md)
