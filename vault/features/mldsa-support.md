---
title: ML-DSA Post-Quantum Key Recovery Support
type: feature
created: 2026-03-07
status: blocked
tags: [mldsa, post-quantum, feature]
---

# ML-DSA Post-Quantum Key Recovery Support

## Goal

Support recovery of ML-DSA (post-quantum) keys from Vultisig vault shares, alongside existing ECDSA (DKLS) and EdDSA (Schnorr) recovery.

## Blockers

- [ ] `vultisig/go-wrappers` must add ML-DSA key export API (`MldsaKeyExportReceiverNew`, etc.)
- [ ] Need test vault files containing ML-DSA keyshares
- [ ] No mainnet blockchains use ML-DSA yet (only XRP Ledger AlphaNet)

## Tasks (once unblocked)

- [ ] Add `internal/recovery/mldsa.go` with `exportMLDSAKey()` following DKLS session pattern
- [ ] Extend `RecoveryResult` with `MLDSAKeys` field
- [ ] Update scheme detection in `vault.DetectScheme()` for vaults with ML-DSA keyshares
- [ ] Add ML-DSA address derivation (no BIP32 — direct from public key, chain-specific)
- [ ] Add `mldsa_stub.go` for WASM builds (same `!wasm` pattern)
- [ ] Website: add Rust ML-DSA WASM for key export (mirrors DKLS/Schnorr WASM pattern)
- [ ] Write tests with ML-DSA test vault files
- [ ] Update CLAUDE.md with ML-DSA architecture details

## Notes

- ML-DSA is NOT a replacement for DKLS/Schnorr — it's a complementary third keyshare type
- Vultisig currently uses security level 44 (ML-DSA-44, 128-bit post-quantum strength)
- Key sizes are much larger: 2,560 byte private key, 1,312 byte public key, 2,420 byte signatures
- Sign setup has `chain_path` parameter, so derivation may work similarly to ECDSA
- See [[mldsa-go-wrapper-api]] for full API analysis
