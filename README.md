# Vultisig Share Decoder

This is a simple "recovery" tool to see the public information on your vault share and recover private keys from vault shares. This tool supports both **GG20** and **DKLS** cryptographic schemes.

This is useful when you want to remember what share it is (if you changed the name) or recover your private keys for importing into other wallets.
You can (and should) run this locally.

## Supported Schemes
- **GG20**: Full support via CLI and web interface
- **DKLS**: Currently supported only via the web interface (CLI support coming soon)

## Demo
[Demo](https://vultisig-share-decoder.replit.app/?)

### Dependencies
[Go](https://go.dev/doc/install)

### Running the GO Binary
1. `git clone` or just download `dist/cli` binary
2. Once downloaded, make sure it is executable such as `chmod +x dist/cli`
3. Once its executable you can do the same CLI commands below. 
`./dist/cli recover --files .... --files ...`

Note: You should not trust this binary and create your own with `make all` or `make cli`

## CLI Commands

### Recover Keys from Vault Shares
**Note: DKLS recovery is currently only supported via the web interface**

Recover private keys from GG20 vault shares:
```bash
make cli && ./dist/cli recover --files "<vault_share1.dat|.bak|.vult>" --files "<vault_share2.dat|.bak|.vult>"
```

Example with included test files:
```bash
make cli && ./dist/cli recover --files "honeypot.bak"
make cli && ./dist/cli recover --files "Test-part1of2.vult,Test-part2of2.vult"
```

Force a specific scheme (auto-detection by default):
```bash
make cli && ./dist/cli recover --files "vault1.vult,vault2.vult" --scheme gg20
```

### Test Address Generation
Test HD derivation and address generation from a known private key:
```bash
make cli && ./dist/cli test-address --private-key <hex_private_key>
```

With custom chaincode:
```bash
make cli && ./dist/cli test-address --private-key <hex_private_key> --chaincode <hex_chaincode>
```

Example:
```bash
make cli && ./dist/cli test-address --private-key 2abbfad6ea48607d9665e123456789bed21204cfe479fdec40d33058c0a4e3feb
```

## Test Files Included

I included [JPThor's unencrypted honeypot](https://github.com/jpthor/blockchain/blob/master/vultisig-JP%20Honeypot%20Vault-2024-09-2of3-e8e5-iPad-D3842FFB838E.bak) to test against.

I also included:
- `Test-part1of2.vult` and `Test-part2of2.vult` (GG20 shares)
- `TestDKLS1of2.vult` and `TestDKLS2of2.vult` (DKLS shares - use web interface)

For `ETH` it will return something like this:
```
WIF Private Keys:
ethereum:2abbfad6ea48607d9665eXXXXXbed21204cfe479fdec40d33058c0a4e3feb
```

`2abbfad6ea48607d9665eXXXXXbed21204cfe479fdec40d33058c0a4e3feb` can be imported into [MetaMask](https://metamask.io/)

For `BTC` it will return something like this:
```
WIF Private Keys:
bitcoin: p2wpkh:L5P6V9eVkvy5H8stBGj7MhJxh8cCSLicYvGBcxfLxdFUzuktbEir
```

`p2wpkh:L5P6V9eVkvy5H8stBGj7MhJxh8cCSLicYvGBcxfLxdFUzuktbEir` can be imported into [Electrum](https://electrum.org/#download)

You can also validate that the private key is correct if it generates the Address that matches what you had in Vultisig.


## Running the server locally (which calls the CLI)
`make all && ./dist/webserver`

## Project Structure
```
├── cmd
│   ├── cli
│   │   ├── actions.go        # CLI-specific actions (decrypt, recover)
│   │   └── main.go          # CLI entry point and app configuration
│   ├── server
│   │   └── main.go          # Web server entry point
│   └── wasm
│       └── main.go          # WebAssembly entry point
├── pkg
│   ├── keyhandlers
│   │   └── key_handlers.go  # Cryptocurrency specific key handlers (BTC, ETH, etc.)
│   ├── keyprocessing
│   │   └── key_processing.go # Key processing and reconstruction logic
│   ├── shared
│   │   └── shared.go        # Core shared functionality
│   ├── types
│   │   └── types.go         # Shared type definitions
│   └── fileutils
│       └── fileutils.go     # File handling utilities
├── static                   # Web assets
│   ├── index.html          # Main web interface
│   ├── main.js             # Frontend JavaScript
│   ├── main.wasm           # Compiled WebAssembly binary
│   ├── style.css           # Styling
│   └── wasm_exec.js        # WebAssembly execution environment
├── go.mod                  # Go module definition
├── go.sum                  # Go module checksums
├── Makefile               # Build automation
└── README.md              # Project documentation
```

## Build Tags

The project uses Go build tags to manage different builds:
- `cli`: Command-line interface build
- `wasm`: WebAssembly build for browser
- `server`: Web server build


## Build Commands (in Makefile)

```bash
# Build CLI
go build -tags cli -o dist/cli ./cmd/cli

# Build WebAssembly
GOOS=js GOARCH=wasm go build -tags wasm -o static/main.wasm

# Build Web Server
go build -tags server -o dist/webserver ./cmd/server


98% of the code is from: [Mobile TSS Lib](https://github.com/vultisig/mobile-tss-lib/blob/main/cmd/recovery-cli/main.go)


