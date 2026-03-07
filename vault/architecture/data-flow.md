---
title: Recovery Data Flow
type: architecture
created: 2026-03-07
tags: [architecture, data-flow]
---

# Recovery Data Flow

## Input
`.vult` / `.bak` files → base64-encoded protobuf `VaultContainer`

## Pipeline

```
VaultContainer (protobuf)
  ├── IsEncrypted? → AES-GCM decrypt (SHA-256 hashed password)
  └── Inner Vault (protobuf)
       ├── KeyShares[] — array of {PublicKey, Keyshare}
       ├── LocalPartyId
       ├── PublicKeyEcdsa / PublicKeyEddsa
       └── HexChainCode

Scheme Detection:
  KeyShares[0].Keyshare is JSON? → GG20
  KeyShares[0].Keyshare is hex/binary? → DKLS

GG20 Path:
  JSON keyshares → tss.LocalState → VSS Shamir reconstruction
  → root ECDSA key + root EdDSA key → HD derivation → addresses

DKLS Path:
  KeyShares[0] (ECDSA) → go-dkls CGo → ECDSA private key
  KeyShares[1] (EdDSA) → go-schnorr CGo → EdDSA private key
  → HD derivation (ECDSA) / direct use (EdDSA) → addresses
```

## Coin Derivation
- ECDSA: BIP44/BIP84 HD paths → 13 coins (BTC, ETH, DOGE, LTC, THOR, MAYA, ATOM, etc.)
- EdDSA: Direct Ed25519 → 3 coins (Solana, Sui, TON)

## Output Formats
- Text: human-readable key/address listing
- JSON: structured `RecoveryResult` with `ecdsaKeys[]` and `eddsaKeys[]`
