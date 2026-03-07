# Vultisig Share Decoder

A cryptographic recovery tool that extracts private keys from Vultisig TSS (Threshold Signature Scheme) vault shares. Supports both **GG20** and **DKLS** schemes and derives addresses for 13+ cryptocurrencies.

You can (and should) run this locally.

## Demo

[https://vultisig-share-decoder.pages.dev/](https://vultisig-share-decoder.pages.dev/)

## Supported Recovery Networks

**UTXO Chains:** Bitcoin, Bitcoin Cash, Dogecoin, Litecoin

**Cosmos/BFT Chains:** THORChain, MayaChain, Cosmos Hub, Kujira, dYdX, Terra Classic, Terra

**EVM Chains:** Ethereum, Tron

**EdDSA Chains:** Solana, Sui, TON

## Supported Schemes

| Scheme | CLI | Web |
|--------|-----|-----|
| GG20   | Yes | Yes |
| DKLS   | Yes (requires CGo) | Yes |

## Quick Start

### Prerequisites

- [Go 1.25+](https://go.dev/doc/install)
- [Bun](https://bun.sh/) (for JS derivation bundling)

### CLI

```bash
# Build
make cli

# Recover from vault shares (auto-detects scheme)
./dist/cli recover --files "share1.vult" --files "share2.vult"

# Force a specific scheme
./dist/cli recover --files "vault.bak" --scheme gg20

# JSON output
./dist/cli recover --files "share1.vult" --files "share2.vult" --format json
```

### Web (Cloudflare Pages)

```bash
make pages    # Build Go WASM + bundle JS derivation + gzip
```

## Build Commands

```bash
make cli      # Build CLI binary -> dist/cli
make wasm     # Build Go WASM -> static/main.wasm (GG20 recovery)
make derive   # Bundle JS address derivation -> static/derive.js
make pages    # Build WASM + derive + gzip for Cloudflare Pages
make test     # Run Go tests + JS derive tests
make check    # go fmt + go vet
make clean    # Remove build artifacts
```

## Test Files

Located in `testdata/`:

| File | Scheme | Notes |
|------|--------|-------|
| `honeypot.bak` | GG20 | [JPThor's unencrypted honeypot](https://github.com/jpthor/blockchain/blob/master/vultisig-JP%20Honeypot%20Vault-2024-09-2of3-e8e5-iPad-D3842FFB838E.bak) (single file) |
| `Test-part1of2.vult` / `Test-part2of2.vult` | GG20 | Two-share test vault |
| `TestDKLS1of2.vult` / `TestDKLS2of2.vult` | DKLS | Two-share test vault |

```bash
# GG20 single share
./dist/cli recover --files testdata/honeypot.bak

# GG20 two shares
./dist/cli recover --files testdata/Test-part1of2.vult --files testdata/Test-part2of2.vult

# DKLS two shares
./dist/cli recover --files testdata/TestDKLS1of2.vult --files testdata/TestDKLS2of2.vult
```

## Importing Results

**Ethereum** — Import the hex private key into [MetaMask](https://metamask.io/)

**Bitcoin** — Import the WIF key (e.g. `p2wpkh:L5P6V9e...`) into [Electrum](https://electrum.org/#download)

Verify correctness by checking that the derived address matches what you had in Vultisig.

## Architecture

### Data Flow

1. **Input**: `.vult`/`.bak` files (base64-encoded protobuf `VaultContainer`)
2. **Decryption**: AES-GCM with SHA-256-hashed password (if encrypted)
3. **Scheme detection**: `vault.DetectScheme()` — binary keyshare = DKLS, JSON = GG20
4. **Key reconstruction**:
   - GG20: VSS Shamir reconstruction via `bnb-chain/tss-lib`
   - DKLS: Algebraic key export via `vultisig/go-wrappers` CGo (ECDSA + EdDSA/Schnorr)
5. **Derivation**: BIP44/BIP84 HD key derivation into coin-specific addresses
6. **Output**: Structured `RecoveryResult` as text or JSON

### Project Structure

```
cmd/
  cli/          CLI entry point
  wasm/         Go WASM entry point (GG20 recovery)
internal/
  vault/        File parsing, protobuf, AES-GCM decryption, scheme detection
  recovery/     Unified Recover() entry point, GG20 + DKLS reconstruction
  derive/       Coin address derivation (BIP32/BIP44)
  format/       Text and JSON formatters
  tss/          LocalState struct for GG20 keyshare deserialization
src/
  derive.js     JS address derivation source (bundled for web)
static/         Web assets (HTML, CSS, JS, WASM binaries)
testdata/       Test vault files
```

### Build Tags

- **`cli`**: Native CLI binary (CGo enabled for DKLS)
- **`wasm`**: Go WASM for browser (GG20 only, no CGo)
- **`!wasm`**: DKLS CGo code excluded from WASM; stub provided

### Website

- **Go WASM** (~5.5MB gzipped): GG20 recovery, lazy-loaded only when needed
- **Rust DKLS WASM** (783KB): ECDSA key export
- **Rust Schnorr WASM** (700KB): EdDSA key export
- **JS derivation** (~27KB gzipped): Pure JS address derivation using `@noble/curves`, `@scure/bip32`

## Adding a New Cryptocurrency

**ECDSA coin**: Add a derive function in `internal/derive/ecdsa.go`, then add an entry to `getECDSACoinDefs()` in `internal/derive/coins.go`.

**EdDSA coin**: Add a derive function in `internal/derive/eddsa.go`, then add an entry to `getEdDSACoinDefs()` in `internal/derive/coins.go`.

The coin is automatically included in all recovery outputs.

## License

See [LICENSE](LICENSE).
