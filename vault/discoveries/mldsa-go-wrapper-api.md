---
title: ML-DSA Go-Wrapper API Has No Key Export
type: discovery
created: 2026-03-07
tags: [mldsa, post-quantum, go-wrappers, key-export]
---

# ML-DSA Go-Wrapper API Has No Key Export

## Context

Analyzing `vultisig/go-wrappers/mldsa` to determine feasibility of ML-DSA support in the share decoder. ML-DSA (NIST FIPS 204, standardized CRYSTALS-Dilithium) is a post-quantum digital signature scheme based on module lattices.

## Discovery

The ML-DSA wrapper in `vultisig/go-wrappers/mldsa` exposes three categories of functions:

### Keyshare operations (available)
- `MldsaKeyshareFromBytes([]byte) -> Handle` — parse a keyshare
- `MldsaKeysharePublicKey(Handle) -> []byte` — extract public key (1,312+ bytes for ML-DSA-44)
- `MldsaKeyshareKeyID(Handle) -> []byte` — extract key ID
- `MldsaKeyshareToBytes(Handle) -> []byte` — serialize keyshare
- `MldsaKeyshareFree(*Handle)` — free handle

### Keygen session (NOT needed for recovery)
- `MldsaKeygenSetupMsgNew()`, `MldsaKeygenSessionFromSetup()`, `MldsaKeygenSessionInputMessage()`, `MldsaKeygenSessionOutputMessage()`, `MldsaKeygenSessionFinish()`

### Sign session (NOT needed for recovery)
- `MldsaSignSetupMsgNew()`, `MldsaSignSessionFromSetup()`, etc.
- Sign setup includes `chain_path` parameter, suggesting BIP32-like derivation may be supported

### Key export (MISSING)
Unlike DKLS (`DklsKeyExportReceiverNew` / `DklsKeyExporter` / `DklsKeyExportReceiverInputMessage` / `DklsKeyExportReceiverFinish`) and Schnorr (same pattern), **ML-DSA has NO key export functions** in the C header (`vs-core.h`). This means we cannot reconstruct the full private key from threshold shares.

### Security levels
- `MlDsa44` (128-bit) — Vultisig uses this level
- `MlDsa65` (192-bit)
- `MlDsa87` (256-bit)

### Key sizes (ML-DSA-44)
- Public key: 1,312 bytes (vs 33 bytes ECDSA, 32 bytes EdDSA)
- Private key: 2,560 bytes
- Signature: 2,420 bytes

## Vultisig Windows Implementation

From `vultisig-windows` repo (`core/mpc/mldsa/mldsaKeygen.ts`):
- ML-DSA is stored as an additional keyshare alongside DKLS (ECDSA) and Schnorr (EdDSA)
- Uses the same `KeygenSession` + `Keyshare` WASM pattern as DKLS/Schnorr
- Hardcoded to security level 44
- The WASM API (`lib/mldsa/vs_wasm.js`) exports: `KeygenSession`, `Keyshare`, `SignSession`, `Message`
- No `KeyExportSession` class exists in the ML-DSA WASM (unlike DKLS WASM which has it)

## Current Blockchain Adoption

- **XRP Ledger AlphaNet** (Dec 2024) — first major chain with ML-DSA ("Quantum Accounts")
- No other mainnet chains support ML-DSA signatures yet
- Transition timeline: NIST recommends migration from ECC by 2030

## Impact

- **Cannot implement full recovery** until key export API is added to go-wrappers
- **Can extract public key** from ML-DSA keyshares — useful for vault inspection
- When key export is eventually added, integration should follow the exact same pattern as [[dkls-key-export-protocol]]
- Will need test vault files with ML-DSA keyshares to validate

## References

- Go wrapper: `github.com/vultisig/go-wrappers/mldsa`
- C header: `github.com/vultisig/go-wrappers/includes/vs-core.h`
- WASM bindings: `github.com/vultisig/vultisig-windows/lib/mldsa/vs_wasm.js`
- Keygen implementation: `github.com/vultisig/vultisig-windows/core/mpc/mldsa/mldsaKeygen.ts`
- NIST FIPS 204: ML-DSA standard
- Our DKLS integration: `internal/recovery/dkls.go`
