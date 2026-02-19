# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vultisig Share Decoder is a multi-platform cryptographic recovery tool that extracts private keys from Vultisig TSS (Threshold Signature Scheme) vault shares. It supports two schemes: **GG20** (via `bnb-chain/tss-lib`) and **DKLS** (native Go + Rust WASM fallback). Recovered keys are derived into addresses for 12+ cryptocurrencies (BTC, ETH, DOGE, LTC, THORChain, Cosmos chains, etc.).

## Build & Development Commands

```bash
make cli         # Build CLI binary → dist/cli
make webserver   # Build web server → dist/webserver
make wasm        # Build Go WASM → static/main.wasm
make all         # Build all three targets
make test        # go test ./...
make check       # go fmt && go vet
make clean       # Remove build artifacts
```

### Running

```bash
# CLI recovery
./dist/cli recover --files "Test-part1of2.vult" --files "Test-part2of2.vult"
./dist/cli recover --files "honeypot.bak"
./dist/cli recover --files "v1.vult" --files "v2.vult" --scheme dkls

# Test address derivation from known key
./dist/cli test-address --private-key <hex> --chaincode <hex>

# Web server (serves static/ on :8080)
./dist/webserver
```

## Architecture

### Build Tags

Three deployment targets from one codebase via Go build tags: `cli`, `server`, `wasm`.

### Module Name

The Go module is named `main` (non-standard). Internal imports use `main/pkg/...` and `main/tss`.

### Core Data Flow

1. **Input**: `.vult`/`.bak` files → base64-encoded protobuf `VaultContainer` (from `vultisig/commondata`)
2. **Decryption**: AES-GCM with SHA-256-hashed password (if encrypted)
3. **Scheme detection** (`pkg/shared`): checks for `ResharePrefix` or non-JSON keyshare → DKLS; otherwise GG20
4. **Key reconstruction**:
   - GG20: VSS Shamir reconstruction via `bnb-chain/tss-lib/v2/crypto/vss`
   - DKLS: Heuristic native Go engine (`pkg/dkls/dkls_native.go`); true algebraic reconstruction only in browser via Rust `vs_wasm`
5. **Derivation**: HD key derivation (BIP44/BIP84) → coin-specific addresses/WIF keys (`pkg/keyhandlers`)

### Key Packages

- **`pkg/shared`**: Orchestration entry point (`ProcessFileContent()`) — called from all three deployment modes
- **`pkg/encryption`**: AES-GCM vault decryption
- **`pkg/fileutils`**: Vault file parsing, protobuf deserialization
- **`pkg/keyprocessing`**: GG20 (`key_processing.go`) and DKLS (`dkls_processing.go`) reconstruction
- **`pkg/dkls`**: Native DKLS processor — entropy-based heuristic key extraction (not true algebraic reconstruction)
- **`pkg/keyhandlers`**: Coin-specific handlers and `GetSupportedCoins()` config
- **`tss/`**: Local port of `vultisig/mobile-tss-lib` (ported to prevent upstream drift)

### WASM Entry Points (`cmd/wasm/main.go`)

Exposes JS globals: `ProcessFiles()`, `DeriveAndShowKeys()`, `DeriveSpecificKey()`, `GetSupportedCoins()`

### Frontend (`static/`)

Static HTML/JS/CSS with two WASM binaries: `main.wasm` (Go) and `vs_wasm_bg.wasm` (Rust DKLS). The Rust WASM handles true DKLS algebraic reconstruction in-browser.

## Test Files

- `honeypot.bak` — JPThor's unencrypted honeypot vault (GG20, single file)
- `Test-part1of2.vult` / `Test-part2of2.vult` — GG20 test shares
- `TestDKLS1of2.vult` / `TestDKLS2of2.vult` — DKLS test shares

## Adding a New Cryptocurrency

1. Add a `CoinConfig` entry in `pkg/keyhandlers/coin_config.go`
2. Implement the handler function in `pkg/keyhandlers/key_handlers.go`
3. The coin will automatically be included via `GetSupportedCoins()` → `ProcessRootKeyForCoins()`
