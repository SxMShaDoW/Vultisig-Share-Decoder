module github.com/SxMShaDoW/Vultisig-Share-Decoder

go 1.25

require (
	github.com/bnb-chain/tss-lib/v2 v2.0.2
	github.com/btcsuite/btcd v0.24.0
	github.com/btcsuite/btcd/btcutil v1.1.5
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.3
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0
	github.com/eager7/dogd v0.0.0-20200427085516-2caf59f59dbb
	github.com/eager7/dogutil v0.0.0-20200427040807-200e961ba4b5
	github.com/ethereum/go-ethereum v1.14.13
	github.com/gcash/bchd v0.17.2-0.20201218180520-5708823e0e99
	github.com/gcash/bchutil v0.0.0-20210113190856-6ea28dff4000
	github.com/golang/protobuf v1.5.4
	github.com/ltcsuite/ltcd v0.23.5
	github.com/ltcsuite/ltcd/ltcutil v1.1.3
	github.com/tonkeeper/tongo v1.16.19
	github.com/urfave/cli/v2 v2.27.1
	github.com/vultisig/commondata v0.0.0-20241001024659-50cb6f1ca345
	github.com/vultisig/go-wrappers v0.0.0-20260223034715-9a5927a3c4c6
	golang.org/x/crypto v0.28.0
	golang.org/x/term v0.25.0
)

require (
	github.com/agl/ed25519 v0.0.0-20200225211852-fd4d107ace12 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.2 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.3 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dchest/siphash v1.2.2 // indirect
	github.com/gogo/protobuf v1.3.3 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/holiman/uint256 v1.3.1 // indirect
	github.com/ipfs/go-log v1.0.5 // indirect
	github.com/ipfs/go-log/v2 v2.1.3 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/ltcsuite/ltcd/btcec/v2 v2.3.2 // indirect
	github.com/ltcsuite/ltcd/chaincfg/chainhash v1.0.2 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/otiai10/primes v0.0.0-20210501021515-f1b2be525a11 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/snksoft/crc v1.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	go.uber.org/zap v1.24.0 // indirect
	golang.org/x/exp v0.0.0-20231110203233-9a3e6036ecaa // indirect
	golang.org/x/sys v0.26.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	lukechampine.com/blake3 v1.2.1 // indirect
)

replace (
	github.com/agl/ed25519 => github.com/binance-chain/edwards25519 v0.0.0-20200305024217-f36fc4b53d43
	github.com/bnb-chain/tss-lib/v2 => github.com/bnb-chain/tss-lib/v2 v2.0.2
	github.com/gogo/protobuf => github.com/regen-network/protobuf v1.3.2-alpha.regen.4
	github.com/gogo/protobuf/proto => github.com/gogo/protobuf/proto v1.3.2
)
