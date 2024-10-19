# Vultisig Share Decoder


This is a simple "recovery" tool to see the public information on your vault share.
This is useful when you want to remember what share it is (if you changed the name).
You can (and should) run this locally.

### Dependencies
[Go](https://go.dev/doc/install)

### Running the GO Binary
1. `git clone` or just download `main` binary
2. Once downloaded, make sure it is executable such as `chmod +x main`
3. Once its executable you can do the same CLI commands below. 
`./main recover --files ....`

Note: You should not trust this binary and create your own with `go build main.go server.go` or `go build main.go` (note: if you do not build with the server.go you are going to need to comment out StartServer)

## Running the CLI locally
`go run main.go recover --files "<a vault share.dat|.bak|.vult>"`
`go run main.go recover --files "honeypot.bak"` 

I included included [JPThor's unencrypted honeypot](https://github.com/jpthor/blockchain/blob/master/vultisig-JP%20Honeypot%20Vault-2024-09-2of3-e8e5-iPad-D3842FFB838E.bak) to test against.

I also included a `Test-part1of2.vult` and `Test-part2of2.vult` 

`go run main.go recover --files "Test-part1of2.vult, Test-part2of2.vult"`

This will return something like this:
```
hex encoded private key for ethereum:2abbfad6ea48607d9665eXXXXXbed21204cfe479fdec40d33058c0a4e3feb
```

That can be imported into [MetaMask](https://metamask.io/)

## Running the server locally (which calls the CLI)
`go run *.go server`

## Viewing a Demo
[Demo](https://vultisig-share-decoder.replit.app/?)


98% of the code is from: [Mobile TSS Lib](https://github.com/vultisig/mobile-tss-lib/blob/main/cmd/recovery-cli/main.go)

