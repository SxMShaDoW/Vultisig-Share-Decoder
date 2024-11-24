package main

import (
    "encoding/hex"
    "fmt"
    "strings"

    "github.com/bnb-chain/tss-lib/v2/crypto/vss"
    binanceTss "github.com/bnb-chain/tss-lib/v2/tss"
    "github.com/btcsuite/btcd/btcutil/hdkeychain"
    "github.com/btcsuite/btcd/chaincfg"
    "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func getKeys(threshold int, allSecrets []tempLocalState, keyType TssKeyType, outputBuilder *strings.Builder) error {
    if len(allSecrets) == 0 {
        return fmt.Errorf("no secrets provided")
    }

    switch keyType {
    case ECDSA:
        return processECDSAKeys(threshold, allSecrets, outputBuilder)
    case EdDSA:
        return processEdDSAKeys(threshold, allSecrets, outputBuilder)
    default:
        return fmt.Errorf("unsupported key type: %v", keyType)
    }
}

func processECDSAKeys(threshold int, allSecrets []tempLocalState, outputBuilder *strings.Builder) error {
    vssShares := make(vss.Shares, len(allSecrets))
    for i, s := range allSecrets {
        fmt.Fprintf(outputBuilder, "\n Public Key(ECDSA): %v\n", s.LocalState[ECDSA].PubKey)
        share := vss.Share{
            Threshold: threshold,
            ID:        s.LocalState[ECDSA].ECDSALocalData.ShareID,
            Share:     s.LocalState[ECDSA].ECDSALocalData.Xi,
        }
        vssShares[i] = &share
    }

    curve := binanceTss.S256()
    tssPrivateKey, err := vssShares[:threshold].ReConstruct(curve)
    if err != nil {
        return err
    }
    privateKey := secp256k1.PrivKeyFromBytes(tssPrivateKey.Bytes())
    publicKey := privateKey.PubKey()

    hexPubKey := hex.EncodeToString(publicKey.SerializeCompressed())
    fmt.Fprintf(outputBuilder, "\nhex encoded root pubkey(ECDSA): %s\n", hexPubKey)
    fmt.Fprintf(outputBuilder, "\nhex encoded root privkey(ECDSA): %s\n", hex.EncodeToString(privateKey.Serialize()))

    // Example for Bitcoin derivation
    net := &chaincfg.MainNetParams
    chaincode := allSecrets[0].LocalState[ECDSA].ChainCodeHex
    fmt.Fprintf(outputBuilder, "\nchaincode: %s\n", chaincode)
    chaincodeBuf, err := hex.DecodeString(chaincode)
    if err != nil {
        return err
    }
    extendedPrivateKey := hdkeychain.NewExtendedKey(net.HDPrivateKeyID[:], privateKey.Serialize(), chaincodeBuf, []byte{0x00, 0x00, 0x00, 0x00}, 0, 0, true)
    fmt.Fprintf(outputBuilder, "\nextended private key full: %s\n", extendedPrivateKey.String())

    supportedCoins := []struct {
        name       string
        derivePath string
        action     func(*hdkeychain.ExtendedKey, *strings.Builder) error
    }{
        {
            name:       "bitcoin",
            derivePath: "m/84'/0'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return showBitcoinKey(key, output)
            },
        },
        {
            name:       "bitcoinCash",
            derivePath: "m/44'/145'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return showBitcoinCashKey(key, output)
            },
        },
        {
            name:       "dogecoin",
            derivePath: "m/44'/3'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return showDogecoinKey(key, output)
            },
        },
        {
            name:       "litecoin",
            derivePath: "m/84'/2'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return showLitecoinKey(key, output)
            },
        },
        {
            name:       "thorchain",
            derivePath: "m/44'/931'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return cosmosLikeKeyHandler(key, "thor", "v", "c", output, "THORChain")
            },
        },
        {
            name:       "mayachain",
            derivePath: "m/44'/931'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return cosmosLikeKeyHandler(key, "maya", "v", "c", output, "MayaChain")
            },
        },
        {
            name:       "atomchain",
            derivePath: "m/44'/118'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return cosmosLikeKeyHandler(key, "cosmos", "valoper", "valcons", output, "ATOMChain")
            },
        },
        {
            name:       "kujirachain",
            derivePath: "m/44'/118'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return cosmosLikeKeyHandler(key, "kujira", "valoper", "valcons", output, "KujiraChain")
            },
        },
        {
            name:       "dydxchain",
            derivePath: "m/44'/118'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return cosmosLikeKeyHandler(key, "dydx", "valoper", "valcons", output, "DydxChain")
            },
        },
        {
            name:       "terraclassicchain",
            derivePath: "m/44'/118'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return cosmosLikeKeyHandler(key, "terra", "valoper", "valcons", output, "terraclassicchain")
            },
        },
        {
            name:       "terrachain",
            derivePath: "m/44'/118'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return cosmosLikeKeyHandler(key, "terra", "valoper", "valcons", output, "terrachain")
            },
        },
        {
            name:       "ethereum",
            derivePath: "m/44'/60'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return showEthereumKey(key, output)
            },
        },
    }

    for _, coin := range supportedCoins {
        fmt.Fprintf(outputBuilder, "\nRecovering %s key....\n", coin.name)
        key, err := getDerivedPrivateKeys(coin.derivePath, extendedPrivateKey)
        if err != nil {
            return fmt.Errorf("error deriving private key for %s: %w", coin.name, err)
        }
        fmt.Fprintf(outputBuilder, "\nprivate key for %s: %s \n", coin.name, key.String())
        if err := coin.action(key, outputBuilder); err != nil {
            fmt.Println("error showing keys for", coin.name, "error:", err)
        }
    }

    return nil
}

func processEdDSAKeys(threshold int, allSecrets []tempLocalState, outputBuilder *strings.Builder) error {
    vssShares := make(vss.Shares, len(allSecrets))
    for i, s := range allSecrets {
        fmt.Fprintf(outputBuilder, "\n Public Key(EdDSA): %v\n", s.LocalState[EdDSA].PubKey)
        share := vss.Share{
            Threshold: threshold,
            ID:        s.LocalState[EdDSA].EDDSALocalData.ShareID,
            Share:     s.LocalState[EdDSA].EDDSALocalData.Xi,
        }
        vssShares[i] = &share
    }

    curve := binanceTss.Edwards()
    tssPrivateKey, err := vssShares[:threshold].ReConstruct(curve)
    if err != nil {
        return err
    }
    privateKey := secp256k1.PrivKeyFromBytes(tssPrivateKey.Bytes())
    publicKey := privateKey.PubKey()

    fmt.Fprintf(outputBuilder, "\nhex encoded root pubkey(EdDSA): %s\n", hex.EncodeToString(publicKey.SerializeCompressed()))
    fmt.Fprintf(outputBuilder, "\nhex encoded root privkey(EdDSA): %s\n", hex.EncodeToString(privateKey.Serialize()))

    return nil
}