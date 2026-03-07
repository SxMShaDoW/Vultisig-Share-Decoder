---
title: Full Codebase Restructure
type: feature
created: 2026-03-07
status: planned
tags: [restructure, cleanup]
---

# Full Codebase Restructure

## Goal
Consolidate community-tools improvements and clean up package structure.

## Tasks
- [ ] Rename `pkg/` to `internal/` (Go convention)
- [ ] Port GG20 JSON output (currently only DKLS has structured JSON)
- [ ] Add JSON output to WASM entry points for website
- [ ] Remove dead code (`ProcessFilesContent`, `ProcessFiles` in actions.go)
- [ ] Remove `dkls_native.go` heuristic processor (superseded by go-wrappers CGo)
- [ ] Standardize coin naming (e.g., `atomchain` → `cosmos`, `kujirachain` → `kujira`)
- [ ] Add CI/CD for cross-platform builds (darwin/linux)

## Notes
- Module is named `main` — all import paths change with rename
- WASM builds can't use CGo, so DKLS in browser stays via Rust WASM
- community-tools repo at `/Users/dorian/Development/community-tools/recovery-tools/vultisig-share-decoder`
