---
title: CLI as a Reusable Skill
type: feature
created: 2026-03-07
status: planned
tags: [cli, skill, distribution]
---

# CLI as a Reusable Skill

## Goal
Package the CLI so others can easily use it for vault recovery.

## Tasks
- [ ] Pre-built binaries for darwin-arm64, darwin-amd64, linux-amd64
- [ ] Simple README with usage examples
- [ ] GitHub releases with binary attachments
- [ ] Consider Claude Code skill definition for automated recovery workflows
- [ ] Handle edge cases: encrypted vaults prompting for password interactively

## Notes
- CGo dependency means cross-compilation needs `go-wrappers` native libs per platform
- go-wrappers has pre-built libs for darwin + linux already
