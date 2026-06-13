# Reference

> Fact tables. Tool inventories, JSON schemas, MITRE coverage matrix,
> knowledge-base index. Reference pages answer "what exists" and "what
> shape does it take" — the conceptual explanations live in
> [Architecture](../architecture/README.md).

## Contents

| Page                                              | Purpose                                              |
|---------------------------------------------------|------------------------------------------------------|
| [MCP tools](mcp-tools.md)                         | Full tool inventory by tier, with JSON schemas       |
| [SIFT tools](sift-tools.md)                       | Wrapped SIFT tools, versions, wrappers, spoliation   |
| [MITRE coverage](mitre-coverage.md)               | Techniques demonstrated by each scenario             |
| [Knowledge index](knowledge-index.md)             | `knowledge/` KB entries by topic and source type     |

## Versioning

These pages are generated manually for now. A reference-audit pass on
the eve of submission cross-checks every parameter name, enum value, and
version number against the upstream source. Tool APIs drift; documentation
must match reality on submission day.

Expect each reference page to be regenerated against the code once
`src/core/`, `src/mcp_server/`, and the SIFT wrappers are implemented
(Phase 3).

## Related

- [Architecture](../architecture/README.md) — the conceptual layer above
  these tables
- [Integrations](../integrations/README.md) — external services the tools
  call into
