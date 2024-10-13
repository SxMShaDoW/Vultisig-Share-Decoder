# Vultisig Share Decoder


This is a simple "recovery" tool to see the public information on your vault share.
This is useful when you want to remember what share it is (if you changed the name).
You can (and should) run this locally.

## Running the CLI locally
`go run main.go recover --files "<a vault share.dat|.bak|.vult>"`
`go run main.go recover --files "honeypot.bak"` 

I included included [JPThor's unencrypted honeypot](https://github.com/jpthor/blockchain/blob/master/vultisig-JP%20Honeypot%20Vault-2024-09-2of3-e8e5-iPad-D3842FFB838E.bak) to test against.

## Running the server locally (which calls the CLI)
`go run *.go server`

## Viewing a Demo
[Demo](https://vultisig-share-decoder.replit.app/?)


98% of the code is from: [Mobile TSS Lib](https://github.com/vultisig/mobile-tss-lib/blob/main/cmd/recovery-cli/main.go)

