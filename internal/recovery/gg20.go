package recovery

import (
	"encoding/hex"
	"fmt"

	"github.com/bnb-chain/tss-lib/v2/crypto/vss"
	binanceTss "github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	edwards "github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/vultisig/vsd/internal/derive"
	"github.com/vultisig/vsd/internal/vault"
)

func recoverGG20(inputs []vault.FileInput, passwords []string) (*RecoveryResult, error) {
	result := &RecoveryResult{
		Success:   true,
		Scheme:    "gg20",
		ECDSAKeys: make([]derive.CoinKey, 0),
		EdDSAKeys: make([]derive.CoinKey, 0),
	}

	var allSecrets []vault.TempLocalState
	for i, input := range inputs {
		password := ""
		if i < len(passwords) {
			password = passwords[i]
		}

		v, err := vault.ParseVaultFromFile(input.Content, input.Name, password, vault.CommandLine)
		if err != nil {
			return nil, fmt.Errorf("error parsing file %s: %w", input.Name, err)
		}

		localStates, err := vault.ExtractGG20LocalStates(v)
		if err != nil {
			return nil, fmt.Errorf("error extracting GG20 states from %s: %w", input.Name, err)
		}

		if eddsaState, ok := localStates[vault.EdDSA]; ok {
			result.ShareDetails = append(result.ShareDetails, ShareDetail{
				BackupName: input.Name,
				ThisShare:  eddsaState.LocalPartyKey,
				AllShares:  eddsaState.KeygenCommitteeKeys,
			})
		}

		allSecrets = append(allSecrets, vault.TempLocalState{
			FileName:   input.Name,
			LocalState: localStates,
		})
	}

	if len(allSecrets) == 0 {
		return nil, fmt.Errorf("no valid GG20 secrets found")
	}

	threshold := len(allSecrets)

	err := processGG20ECDSA(threshold, allSecrets, result)
	if err != nil {
		return nil, fmt.Errorf("error processing ECDSA keys: %w", err)
	}

	err = processGG20EdDSA(threshold, allSecrets, result)
	if err != nil {
		return nil, fmt.Errorf("error processing EdDSA keys: %w", err)
	}

	return result, nil
}

func processGG20ECDSA(threshold int, allSecrets []vault.TempLocalState, result *RecoveryResult) error {
	vssShares := make(vss.Shares, len(allSecrets))

	for i, s := range allSecrets {
		localState, exists := s.LocalState[vault.ECDSA]
		if !exists {
			return fmt.Errorf("ECDSA key not found in secret %d", i)
		}
		if localState.ECDSALocalData.ShareID == nil {
			return fmt.Errorf("ShareID is nil for secret %d", i)
		}
		if localState.ECDSALocalData.Xi == nil {
			return fmt.Errorf("Xi is nil for secret %d", i)
		}
		vssShares[i] = &vss.Share{
			Threshold: threshold,
			ID:        localState.ECDSALocalData.ShareID,
			Share:     localState.ECDSALocalData.Xi,
		}
	}

	curve := binanceTss.S256()
	tssPrivateKey, err := vssShares[:threshold].ReConstruct(curve)
	if err != nil {
		return fmt.Errorf("failed to reconstruct private key: %w", err)
	}

	privateKey := secp256k1.PrivKeyFromBytes(tssPrivateKey.Bytes())
	publicKey := privateKey.PubKey()

	privKeyBytes := privateKey.Serialize()
	pubKeyHex := hex.EncodeToString(publicKey.SerializeCompressed())

	chaincode := allSecrets[0].LocalState[vault.ECDSA].ChainCodeHex
	chaincodeBuf, err := hex.DecodeString(chaincode)
	if err != nil {
		return fmt.Errorf("failed to decode chaincode: %w", err)
	}

	net := &chaincfg.MainNetParams
	extKey := hdkeychain.NewExtendedKey(
		net.HDPrivateKeyID[:],
		privKeyBytes,
		chaincodeBuf,
		[]byte{0x00, 0x00, 0x00, 0x00},
		0, 0, true,
	)

	result.RootKeyInfo = &RootKeyInfo{
		HexPubKeyECDSA:  pubKeyHex,
		HexPrivKeyECDSA: hex.EncodeToString(privKeyBytes),
		ChainCode:       chaincode,
		ExtendedPrivKey: extKey.String(),
	}
	result.PublicKeys.ECDSA = pubKeyHex

	ecdsaKeys, err := derive.DeriveECDSACoins(privKeyBytes, chaincodeBuf)
	if err != nil {
		return fmt.Errorf("failed to derive ECDSA coin keys: %w", err)
	}
	result.ECDSAKeys = ecdsaKeys

	return nil
}

func processGG20EdDSA(threshold int, allSecrets []vault.TempLocalState, result *RecoveryResult) error {
	vssShares := make(vss.Shares, len(allSecrets))

	for i, s := range allSecrets {
		localState, exists := s.LocalState[vault.EdDSA]
		if !exists {
			return nil
		}
		if localState.EDDSALocalData.ShareID == nil || localState.EDDSALocalData.Xi == nil {
			return nil
		}
		vssShares[i] = &vss.Share{
			Threshold: threshold,
			ID:        localState.EDDSALocalData.ShareID,
			Share:     localState.EDDSALocalData.Xi,
		}
	}

	curve := binanceTss.Edwards()
	tssPrivateKey, err := vssShares[:threshold].ReConstruct(curve)
	if err != nil {
		return fmt.Errorf("failed to reconstruct EdDSA key: %w", err)
	}

	tssPrivateKeyScalar := tssPrivateKey.Bytes()
	privateKey, publicKey, _ := edwards.PrivKeyFromScalar(tssPrivateKeyScalar)
	pubKeyBytes := publicKey.Serialize()
	privKeyBytes := privateKey.Serialize()

	result.PublicKeys.EdDSA = hex.EncodeToString(pubKeyBytes)

	eddsaKeys, err := derive.DeriveEdDSACoins(privKeyBytes, pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to derive EdDSA coin keys: %w", err)
	}
	result.EdDSAKeys = eddsaKeys

	return nil
}
