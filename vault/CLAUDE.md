---
title: Vault Conventions
type: meta
created: 2026-03-07
tags: [meta, vault]
---

# Vault Conventions

## Note Types

| Type | Directory | Purpose |
|------|-----------|---------|
| Discovery | `discoveries/` | Platform quirks, API limitations, undocumented behavior |
| Pattern | `patterns/` | Reusable recipes synthesizing multiple discoveries |
| Feature | `features/` | Feature planning with status tracking |
| Architecture | `architecture/` | System-level docs, data models, execution chains |
| Debug | `debug-journal/` | Date-prefixed troubleshooting logs |

## Required Frontmatter

All notes MUST include:
```yaml
---
title: <descriptive title>
type: discovery | pattern | feature | architecture | debug
created: YYYY-MM-DD
tags: [relevant, tags]
---
```

Feature notes additionally require:
```yaml
status: planned | in-progress | done | blocked
```

## Naming

- Lowercase, hyphen-separated filenames
- Debug journal entries: `YYYY-MM-DD-<topic>.md`
- Features: `<feature-name>.md`

## Links

- Use `[[wikilinks]]` for internal vault references
- Keep `_index.md` updated as the table of contents
