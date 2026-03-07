# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vultisig Share Decoder (VSD) is a cryptographic recovery tool that extracts private keys from Vultisig TSS (Threshold Signature Scheme) vault shares. It supports two schemes: **GG20** (via `bnb-chain/tss-lib`) and **DKLS** (via `vultisig/go-wrappers` CGo bindings). Recovered keys are derived into addresses for 13+ cryptocurrencies (BTC, ETH, DOGE, LTC, THORChain, Cosmos chains, Solana, Sui, TON, etc.).

Deployment targets: **CLI** (Go, both schemes via CGo), **Website** (static site on Cloudflare Pages with Go WASM for GG20 + Rust WASM for DKLS/Schnorr + pure JS address derivation).

## Build & Development Commands

```bash
make cli         # Build CLI binary -> dist/cli (stripped)
make wasm        # Build Go WASM -> static/main.wasm (GG20 recovery only)
make derive      # Bundle JS address derivation -> static/derive.js (bun build)
make pages       # wasm + derive + gzip for Cloudflare Pages deployment
make test        # Go tests (excludes internal/recovery — no CGo) + JS derive tests
make test-cgo    # All Go tests including DKLS recovery (requires CGo + libgodkls)
make check       # go fmt + go vet (fmt modifies files in-place)
make clean       # Remove build artifacts
```

### Running a single test

```bash
# Single Go test
go test ./internal/derive -run TestDeriveECDSA

# JS derive tests
bun run src/derive.test.js
```

### Running the CLI

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

`github.com/SxMShaDoW/Vultisig-Share-Decoder` — all internal packages under `internal/`. Uses `replace` directives in go.mod (no `go install` support).

### Build Tags

- `cli`: CLI binary (CGo for DKLS via go-wrappers)
- `wasm`: Go WASM for browser (GG20 recovery only, no CGo)
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
- **`internal/derive`**: Coin address derivation with structured returns
- **`internal/format`**: Text and JSON formatters for `RecoveryResult`
- **`internal/tss`**: Minimal — just the `LocalState` struct for GG20 keyshare deserialization

### Website Architecture (static/)

Two-layer WASM strategy:

- **Go WASM** (`main.wasm.gz`, ~5.5MB): Only exposes `RecoverGG20()` to JS. Lazy-loaded — only fetched when GG20 scheme is detected. `wasm_exec.js` loaded dynamically.
- **Rust DKLS WASM** (`vs_wasm_bg.wasm`, 783KB): ECDSA key export via `Keyshare` + `KeyExportSession`. Loaded eagerly.
- **Rust Schnorr WASM** (`vs_schnorr_wasm_bg.wasm`, 700KB): EdDSA key export (same API pattern). Loaded eagerly.
- **JS derivation** (`src/derive.js` -> `static/derive.js` via `bun build`, ~27KB gz): Pure JS address derivation using `@noble/curves`, `@noble/hashes`, `@scure/bip32`, `@scure/base`. Handles all coin derivation for both schemes in the browser.
- **JS orchestration** (`app.js`): Vault parsing via `vault_pb.js`, AES-GCM decryption via `aes_gcm.js`, scheme detection, WASM orchestration

Flow: Parse vault in JS -> detect scheme -> DKLS: Rust WASM key export + JS address derivation; GG20: Go WASM full recovery -> render structured card results.

### WASM JS Exports

- `RecoverGG20(fileContents: Uint8Array[], passwords: string[]) -> JSON string` (Go WASM, lazy-loaded)

Address derivation is handled by `static/derive.js` (pure JS), not Go WASM.

## Critical: EdDSA Scalar Reduction

DKLS Schnorr export returns raw scalars that may exceed Ed25519 group order L. **MUST reduce mod L** before computing pubkey. Without reduction: wrong pubkey, wrong addresses for ALL EdDSA coins (SOL, SUI, TON).

- Go: `reduceEdDSAScalar()` in `internal/recovery/dkls.go`
- JS: `processEdDSAScalar()` in `src/derive.js`
- GG20 path does NOT need this — VSS reconstruction on Edwards curve already produces valid scalars

## Key Derivation Rules

- **ECDSA**: Non-hardened BIP32 derivation — `getDerivePathBytes()` strips `'`, does NOT add 0x80000000
- **EdDSA**: NO path derivation — root key used directly for all coins (SOL, SUI, TON)

## Test Files

Located in `testdata/`:
- `honeypot.bak` — JPThor's unencrypted honeypot vault (GG20, single file)
- `Test-part1of2.vult` / `Test-part2of2.vult` — GG20 test shares
- `TestDKLS1of2.vult` / `TestDKLS2of2.vult` — DKLS test shares

## Adding a New Cryptocurrency

### ECDSA coin:
1. Add a derive function in `internal/derive/ecdsa.go`: `func deriveNewCoin(privKey, pubKey []byte) (CoinKey, error)`
2. Add entry to `getECDSACoinDefs()` in `internal/derive/coins.go`
3. Add JS derivation in `src/derive.js` if needed for web

### EdDSA coin:
1. Add a derive function in `internal/derive/eddsa.go`
2. Add entry to `getEdDSACoinDefs()` in `internal/derive/coins.go`
3. Add JS derivation in `src/derive.js` if needed for web

The coin is automatically included in all recovery outputs.

## Golden Test Values (DKLS test vault)

- ECDSA pubkey: `0333e3d4df9cc071be24fd6c995421036074a1a88e5d3e0bc211b7ef4330078d9b`
- EdDSA pubkey: `20e368bf985efdc270500c6e9dc1159102323ff6eabab56f8fa9798e4ac0e2a9`
- BTC: `bc1q0pap5flkh45w8zz2ew9xpf884me55g65l7vqcu`
- ETH: `0x60790246e37D154e02beaF2b9Fb27F93a26A6B3f`
- SOL: `3DPAkfuk5bkh1c1Pg5GN57Gr6cSJsZHVBcJLTFMapmA8`
