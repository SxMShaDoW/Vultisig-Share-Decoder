# Vultisig Share Decoder


This is a simple "recovery" tool to see the public information on your vault share.
This is useful when you want to remember what share it is (if you changed the name).
You can run this locally.

## Running Locally
go run main.go recover --files "<a vault share.dat|.bak|.vult>"

## Running the server locally
go run *.go server

## Viewing a Demo
[Demo](https://vultisig-share-decoder.replit.app/?)


98% of the code is from: [Mobile TSS Lib](https://github.com/vultisig/mobile-tss-lib/blob/main/cmd/recovery-cli/main.go)

