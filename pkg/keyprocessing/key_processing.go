package keyprocessing

import (
    "encoding/hex"
    "fmt"
    "strings"
    "log"
    // "encoding/json"
    "github.com/bnb-chain/tss-lib/v2/crypto/vss"
    binanceTss "github.com/bnb-chain/tss-lib/v2/tss"
    "github.com/btcsuite/btcd/btcutil/hdkeychain"
    // "github.com/btcsuite/btcutil/base58"
    "github.com/btcsuite/btcd/chaincfg"
    "github.com/decred/dcrd/dcrec/secp256k1/v4"
    "main/pkg/types"
    "main/pkg/keyhandlers"
    edwards "github.com/decred/dcrd/dcrec/edwards/v2"

)

func GetKeys(threshold int, allSecrets []types.TempLocalState, keyType types.TssKeyType, outputBuilder *strings.Builder) error {
    if len(allSecrets) == 0 {
        return fmt.Errorf("no secrets provided")
    }

    // Check if we're dealing with DKLS scheme
    if len(allSecrets) > 0 && allSecrets[0].SchemeType == types.DKLS {
        return fmt.Errorf("DKLS scheme should use ProcessDKLSKeys function, not GetKeys")
    }

    // Handle GG20 scheme (original logic)
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
    
    // Output the public key once (they should all be the same for the same vault)
    if len(allSecrets) > 0 {
        if firstState, exists := allSecrets[0].LocalState[types.ECDSA]; exists {
            fmt.Fprintf(outputBuilder, "\nPublic Key(ECDSA): %v\n", firstState.PubKey)
        }
    }
    
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

    supportedCoins := keyhandlers.GetSupportedCoins()

    for _, coin := range supportedCoins {
        fmt.Fprintf(outputBuilder, "\nRecovering %s key....\n", coin.Name)
        key, err := keyhandlers.GetDerivedPrivateKeys(coin.DerivePath, extendedPrivateKey)
        if err != nil {
            return fmt.Errorf("error deriving private key for %s: %w", coin.Name, err)
        }
        fmt.Fprintf(outputBuilder, "\nprivate key for %s: %s \n", coin.Name, key.String())
        if err := coin.Action(key, outputBuilder); err != nil {
            fmt.Println("error showing keys for", coin.Name, "error:", err)
        }
    }

    return nil
}

func ProcessEdDSAKeys(threshold int, allSecrets []types.TempLocalState, outputBuilder *strings.Builder) error {
    vssShares := make(vss.Shares, len(allSecrets))
    
    // Output the public key once (they should all be the same for the same vault)
    if len(allSecrets) > 0 {
        fmt.Fprintf(outputBuilder, "\nPublic Key(EdDSA): %v\n", allSecrets[0].LocalState[types.EdDSA].PubKey)
    }
    
    for i, s := range allSecrets {
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
    
    // Generate Ed25519 key pair
    tssPrivateKeyScalar := tssPrivateKey.Bytes()
    privateKey, publicKey, _ := edwards.PrivKeyFromScalar(tssPrivateKeyScalar)
    publicKeyBytes := publicKey.Serialize()
    privateKeyBytes := privateKey.Serialize()

    // Now process EdDSA coins using the reconstructed root keys
    eddsaCoins := keyhandlers.GetEdDSACoins()
    return keyhandlers.ProcessEdDSAKeyForCoins(privateKeyBytes, publicKeyBytes, eddsaCoins, outputBuilder)
}
