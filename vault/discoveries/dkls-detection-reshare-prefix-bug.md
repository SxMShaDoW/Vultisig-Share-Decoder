---
title: ResharePrefix is not a reliable DKLS indicator
type: discovery
created: 2026-03-07
tags: [dkls, gg20, detection, bug]
---

# ResharePrefix is Not a Reliable DKLS Indicator

## Context
The honeypot.bak (GG20 vault) was being misdetected as DKLS, causing "requires at least 2 keyshare files" errors on single-file recovery.

## Discovery
The original detection logic was:
```go
isDKLS := vault.ResharePrefix != "" || !isJSONString(vault.KeyShares[0].Keyshare)
```

`vault.ResharePrefix` is set for **any** vault that has gone through resharing — including GG20 vaults. The honeypot vault has `ResharePrefix: "2c5e9ced"` but is fully GG20 with JSON keyshares.

## Fix
The correct detection is based solely on keyshare format:
```go
isDKLS := len(vault.KeyShares) > 0 && !isJSONString(vault.KeyShares[0].Keyshare)
```

GG20 keyshares are JSON objects. DKLS keyshares are hex-encoded binary blobs.

## References
- `pkg/fileutils/file_utils.go:226` — detection logic
- `honeypot.bak` — GG20 test file with ResharePrefix
