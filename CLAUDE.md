# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vultisig Share Decoder (VSD) is a cryptographic recovery tool that extracts private keys from Vultisig TSS (Threshold Signature Scheme) vault shares. It supports two schemes: **GG20** (via `bnb-chain/tss-lib`) and **DKLS** (via `vultisig/go-wrappers` CGo bindings). Recovered keys are derived into addresses for 13 cryptocurrencies (BTC, ETH, DOGE, LTC, THORChain, Cosmos chains, Solana, Sui, TON, etc.).

Deployment targets: **CLI** (Go, both schemes via CGo), **Website** (static site on Cloudflare Pages with Go WASM for GG20 + Rust WASM for DKLS/Schnorr).

## Build & Development Commands

```bash
make cli         # Build CLI binary -> dist/cli (13MB stripped)
make wasm        # Build Go WASM -> static/main.wasm (GG20 + address derivation)
make pages       # Build WASM + gzip for Cloudflare Pages deployment
make test        # go test ./...
make check       # go fmt && go vet
make clean       # Remove build artifacts
```

### Running

```bash
# Auto-detect scheme
./dist/cli recover --files testdata/TestDKLS1of2.vult --files testdata/TestDKLS2of2.vult

# Force scheme
./dist/cli recover --files testdata/honeypot.bak --scheme gg20

# JSON output
./dist/cli recover --files testdata/TestDKLS1of2.vult --files testdata/TestDKLS2of2.vult --format json
```

## Architecture

### Module

`github.com/vultisig/vsd` — all internal packages under `internal/`.

### Build Tags

- `cli`: CLI binary (CGo for DKLS via go-wrappers)
- `wasm`: Go WASM for browser (GG20 recovery + address derivation, no CGo)
- `!wasm` on `dkls.go`: DKLS CGo code excluded from WASM builds; `dkls_stub.go` provides a stub

### Core Data Flow

1. **Input**: `.vult`/`.bak` files -> base64-encoded protobuf `VaultContainer`
2. **Decryption**: AES-GCM with SHA-256-hashed password (if encrypted)
3. **Scheme detection**: `vault.DetectScheme()` checks `!isJSONString(keyshare)` -> DKLS; otherwise GG20
4. **Key reconstruction**:
   - GG20: VSS Shamir reconstruction via `bnb-chain/tss-lib/v2/crypto/vss`
   - DKLS: True algebraic key export via `vultisig/go-wrappers` CGo (DKLS for ECDSA, Schnorr for EdDSA)
5. **Derivation**: HD key derivation (BIP44/BIP84) -> coin-specific addresses/WIF keys
6. **Formatting**: Structured `RecoveryResult` -> text or JSON output

### Key Packages

- **`internal/vault`**: File parsing, protobuf deserialization, AES-GCM decryption, scheme detection
- **`internal/recovery`**: Unified `Recover()` entry point, GG20 + DKLS reconstruction
- **`internal/derive`**: Coin address derivation with structured returns (no strings.Builder)
- **`internal/format`**: Text and JSON formatters for `RecoveryResult`
- **`internal/tss`**: Minimal — just the `LocalState` struct for GG20 keyshare deserialization

### Website Architecture (static/)

- **Go WASM** (`main.wasm.gz`, ~5.5MB): Exposes `RecoverGG20()`, `DeriveAddresses()`, `DeriveEdDSAAddresses()` to JS
- **Rust DKLS WASM** (`vs_wasm_bg.wasm`, 783KB): ECDSA key export via `Keyshare` + `KeyExportSession`
- **Rust Schnorr WASM** (`vs_schnorr_wasm_bg.wasm`, 700KB): EdDSA key export (same API pattern)
- **JS** (`app.js`): Vault parsing via `vault_pb.js`, AES-GCM decryption via `aes_gcm.js`, scheme detection, WASM orchestration, structured JSON result rendering

Flow: Parse vault in JS -> detect scheme -> DKLS: Rust WASM key export + Go WASM address derivation; GG20: Go WASM full recovery -> render structured card results.

### WASM JS Exports

- `RecoverGG20(fileContents: Uint8Array[], passwords: string[]) -> JSON string`
- `DeriveAddresses(privKeyHex: string, chainCodeHex: string) -> JSON string`
- `DeriveEdDSAAddresses(privKeyHex: string, pubKeyHex: string) -> JSON string`

## Test Files

Located in `testdata/`:
- `honeypot.bak` — JPThor's unencrypted honeypot vault (GG20, single file)
- `Test-part1of2.vult` / `Test-part2of2.vult` — GG20 test shares
- `TestDKLS1of2.vult` / `TestDKLS2of2.vult` — DKLS test shares

## Adding a New Cryptocurrency

### ECDSA coin:
1. Add a derive function in `internal/derive/ecdsa.go`: `func deriveNewCoin(privKey, pubKey []byte) (CoinKey, error)`
2. Add entry to `getECDSACoinDefs()` in `internal/derive/coins.go`

### EdDSA coin:
1. Add a derive function in `internal/derive/eddsa.go`
2. Add entry to `getEdDSACoinDefs()` in `internal/derive/coins.go`

The coin is automatically included in all recovery outputs.

## Golden Test Values (DKLS test vault)

- ECDSA pubkey: `0333e3d4df9cc071be24fd6c995421036074a1a88e5d3e0bc211b7ef4330078d9b`
- EdDSA pubkey: `20e368bf985efdc270500c6e9dc1159102323ff6eabab56f8fa9798e4ac0e2a9`
- BTC: `bc1q0pap5flkh45w8zz2ew9xpf884me55g65l7vqcu`
- ETH: `0x60790246e37D154e02beaF2b9Fb27F93a26A6B3f`
- SOL: `3DPAkfuk5bkh1c1Pg5GN57Gr6cSJsZHVBcJLTFMapmA8`
