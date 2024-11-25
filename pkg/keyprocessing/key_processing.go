package keyprocessing

import (
    "encoding/hex"
    "fmt"
    "strings"
    "log"
    "github.com/bnb-chain/tss-lib/v2/crypto/vss"
    binanceTss "github.com/bnb-chain/tss-lib/v2/tss"
    "github.com/btcsuite/btcd/btcutil/hdkeychain"
    "github.com/btcsuite/btcd/chaincfg"
    "github.com/decred/dcrd/dcrec/secp256k1/v4"
    "main/pkg/types"
    "main/pkg/keyhandlers"
)

func GetKeys(threshold int, allSecrets []types.TempLocalState, keyType types.TssKeyType, outputBuilder *strings.Builder) error {
    if len(allSecrets) == 0 {
        return fmt.Errorf("no secrets provided")
    }

    switch keyType {
    case types.ECDSA:
        return ProcessECDSAKeys(threshold, allSecrets, outputBuilder)
    case types.EdDSA:
        return ProcessEdDSAKeys(threshold, allSecrets, outputBuilder)
    default:
        return fmt.Errorf("unsupported key type: %v", keyType)
    }
}

func ProcessECDSAKeys(threshold int, allSecrets []types.TempLocalState, outputBuilder *strings.Builder) error {
    log.Printf("Processing ECDSA keys with threshold: %d, number of secrets: %d", threshold, len(allSecrets))

    // Validate input parameters
    if threshold <= 0 {
        return fmt.Errorf("invalid threshold: %d", threshold)
    }
    if len(allSecrets) == 0 {
        return fmt.Errorf("no secrets provided")
    }
    if threshold > len(allSecrets) {
        return fmt.Errorf("threshold (%d) cannot be greater than number of secrets (%d)", threshold, len(allSecrets))
    }
    vssShares := make(vss.Shares, len(allSecrets))
    for i, s := range allSecrets {
        // Check if LocalState exists
        if s.LocalState == nil {
            return fmt.Errorf("localState is nil for secret %d", i)
        }
        // Check if ECDSA key exists
        localState, exists := s.LocalState[types.ECDSA]
        if !exists {
            return fmt.Errorf("ECDSA key not found in secret %d", i)
        }
        log.Printf("Secret %d - ShareID: %v, Xi: %v", i, 
            localState.ECDSALocalData.ShareID != nil,
            localState.ECDSALocalData.Xi != nil)
        fmt.Fprintf(outputBuilder, "\nPublic Key(ECDSA): %v\n", localState.PubKey)

        // Validate ShareID and Xi
        if localState.ECDSALocalData.ShareID == nil {
            return fmt.Errorf("ShareID is nil for secret %d", i)
        }
        if localState.ECDSALocalData.Xi == nil {
            return fmt.Errorf("Xi is nil for secret %d", i)
        }
        share := vss.Share{
            Threshold: threshold,
            ID:        localState.ECDSALocalData.ShareID,
            Share:     localState.ECDSALocalData.Xi,
        }
        vssShares[i] = &share
    }
    log.Printf("Created %d vssShares", len(vssShares))
    curve := binanceTss.S256()
    if curve == nil {
        return fmt.Errorf("failed to get S256 curve")
    }
    log.Printf("Attempting to reconstruct with threshold %d from %d shares", threshold, len(vssShares))
    tssPrivateKey, err := vssShares[:threshold].ReConstruct(curve)
    if err != nil {
        return fmt.Errorf("failed to reconstruct private key: %w", err)
    }
    privateKey := secp256k1.PrivKeyFromBytes(tssPrivateKey.Bytes())
    publicKey := privateKey.PubKey()

    hexPubKey := hex.EncodeToString(publicKey.SerializeCompressed())
    fmt.Fprintf(outputBuilder, "\nhex encoded root pubkey(ECDSA): %s\n", hexPubKey)
    fmt.Fprintf(outputBuilder, "\nhex encoded root privkey(ECDSA): %s\n", hex.EncodeToString(privateKey.Serialize()))

    // Example for Bitcoin derivation
    net := &chaincfg.MainNetParams
    chaincode := allSecrets[0].LocalState[types.ECDSA].ChainCodeHex
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
                return keyhandlers.ShowBitcoinKey(key, output)
            },
        },
        {
            name:       "bitcoinCash",
            derivePath: "m/44'/145'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return keyhandlers.ShowBitcoinCashKey(key, output)
            },
        },
        {
            name:       "dogecoin",
            derivePath: "m/44'/3'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return keyhandlers.ShowDogecoinKey(key, output)
            },
        },
        {
            name:       "litecoin",
            derivePath: "m/84'/2'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return keyhandlers.ShowLitecoinKey(key, output)
            },
        },
        {
            name:       "thorchain",
            derivePath: "m/44'/931'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return keyhandlers.CosmosLikeKeyHandler(key, "thor", "v", "c", output, "THORChain")
            },
        },
        {
            name:       "mayachain",
            derivePath: "m/44'/931'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return keyhandlers.CosmosLikeKeyHandler(key, "maya", "v", "c", output, "MayaChain")
            },
        },
        {
            name:       "atomchain",
            derivePath: "m/44'/118'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return keyhandlers.CosmosLikeKeyHandler(key, "cosmos", "valoper", "valcons", output, "ATOMChain")
            },
        },
        {
            name:       "kujirachain",
            derivePath: "m/44'/118'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return keyhandlers.CosmosLikeKeyHandler(key, "kujira", "valoper", "valcons", output, "KujiraChain")
            },
        },
        {
            name:       "dydxchain",
            derivePath: "m/44'/118'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return keyhandlers.CosmosLikeKeyHandler(key, "dydx", "valoper", "valcons", output, "DydxChain")
            },
        },
        {
            name:       "terraclassicchain",
            derivePath: "m/44'/118'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return keyhandlers.CosmosLikeKeyHandler(key, "terra", "valoper", "valcons", output, "terraclassicchain")
            },
        },
        {
            name:       "terrachain",
            derivePath: "m/44'/118'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return keyhandlers.CosmosLikeKeyHandler(key, "terra", "valoper", "valcons", output, "terrachain")
            },
        },
        {
            name:       "ethereum",
            derivePath: "m/44'/60'/0'/0/0",
            action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
                return keyhandlers.ShowEthereumKey(key, output)
            },
        },
    }

    for _, coin := range supportedCoins {
        fmt.Fprintf(outputBuilder, "\nRecovering %s key....\n", coin.name)
        key, err := keyhandlers.GetDerivedPrivateKeys(coin.derivePath, extendedPrivateKey)
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

func ProcessEdDSAKeys(threshold int, allSecrets []types.TempLocalState, outputBuilder *strings.Builder) error {
    vssShares := make(vss.Shares, len(allSecrets))
    for i, s := range allSecrets {
        fmt.Fprintf(outputBuilder, "\n Public Key(EdDSA): %v\n", s.LocalState[types.EdDSA].PubKey)
        share := vss.Share{
            Threshold: threshold,
            ID:        s.LocalState[types.EdDSA].EDDSALocalData.ShareID,
            Share:     s.LocalState[types.EdDSA].EDDSALocalData.Xi,
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