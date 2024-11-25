# Vultisig Share Decoder


This is a simple "recovery" tool to see the public information on your vault share.
This is useful when you want to remember what share it is (if you changed the name).
You can (and should) run this locally.

### Dependencies
[Go](https://go.dev/doc/install)

### Running the GO Binary
1. `git clone` or just download `cli/cli-recovery` binary
2. Once downloaded, make sure it is executable such as `chmod +x main`
3. Once its executable you can do the same CLI commands below. 
`./cli/cli-recovery recover --files .... --files ...`

Note: You should not trust this binary and create your own with `make all` or `make cli`

## Running the CLI locally
`make cli && ./cli/cli-recovery recover --files "<a vault share.dat|.bak|.vult>"`
`make cli && ./cli/cli-recovery recover --files "honeypot.bak"` 

I included included [JPThor's unencrypted honeypot](https://github.com/jpthor/blockchain/blob/master/vultisig-JP%20Honeypot%20Vault-2024-09-2of3-e8e5-iPad-D3842FFB838E.bak) to test against.

I also included a `Test-part1of2.vult` and `Test-part2of2.vult` 

`make cli && ./cli/cli-recovery recover --files "Test-part1of2.vult, Test-part2of2.vult"`

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
`make all && ./backend/main_backend`

## Viewing a Demo
[Demo](https://vultisig-share-decoder.replit.app/?)


98% of the code is from: [Mobile TSS Lib](https://github.com/vultisig/mobile-tss-lib/blob/main/cmd/recovery-cli/main.go)

