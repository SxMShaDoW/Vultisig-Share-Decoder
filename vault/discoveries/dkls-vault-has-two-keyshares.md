---
title: DKLS vaults contain two separate keyshares (ECDSA + EdDSA)
type: discovery
created: 2026-03-07
tags: [dkls, keyshare, vault-format]
---

# DKLS Vaults Contain Two Separate Keyshares

## Context
Investigating why DKLS recovery only produced ECDSA addresses (Bitcoin, Ethereum, etc.) but not EdDSA addresses (Solana, Sui, TON).

## Discovery
Each DKLS vault file contains two entries in `vault.KeyShares[]`:
- `KeyShares[0]` — ECDSA/DKLS keyshare (~88KB), public key matches `vault.PublicKeyEcdsa`
- `KeyShares[1]` — EdDSA/Schnorr keyshare (~176 bytes), public key matches `vault.PublicKeyEddsa`

The ECDSA keyshare uses the DKLS protocol (`go-dkls` / `DklsKeyExportReceiver*`).
The EdDSA keyshare uses the Schnorr protocol (`go-schnorr` / `SchnorrKeyExportReceiver*`).

Both follow identical API patterns but use different CGo functions.

## Impact
This means full DKLS recovery requires two separate key export sessions — one per protocol. Prior to this discovery, no existing tool (including the Vultisig website) exported EdDSA private keys from DKLS vaults.

## References
- `pkg/dkls/dkls_export.go` — ECDSA export
- `pkg/dkls/schnorr_export.go` — EdDSA export
- `pkg/dkls/vault_parser.go` — extracts both keyshares
- `github.com/vultisig/go-wrappers` — CGo bindings
