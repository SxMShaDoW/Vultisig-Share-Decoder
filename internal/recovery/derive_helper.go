package recovery

import (
	"encoding/hex"
	"fmt"

	"github.com/vultisig/vsd/internal/derive"
)

func DeriveFromRootKey(privKeyHex, chainCodeHex string) (*RecoveryResult, error) {
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}
	chainCodeBytes, err := hex.DecodeString(chainCodeHex)
	if err != nil {
		return nil, fmt.Errorf("invalid chain code hex: %w", err)
	}

	result := &RecoveryResult{
		Success:   true,
		ECDSAKeys: make([]derive.CoinKey, 0),
		EdDSAKeys: make([]derive.CoinKey, 0),
	}

	ecdsaKeys, err := derive.DeriveECDSACoins(privKeyBytes, chainCodeBytes)
	if err != nil {
		return nil, fmt.Errorf("ECDSA derivation failed: %w", err)
	}
	result.ECDSAKeys = ecdsaKeys

	return result, nil
}

func DeriveEdDSAFromKeys(privKeyHex, pubKeyHex string) (*RecoveryResult, error) {
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid public key hex: %w", err)
	}

	result := &RecoveryResult{
		Success:   true,
		ECDSAKeys: make([]derive.CoinKey, 0),
		EdDSAKeys: make([]derive.CoinKey, 0),
	}

	eddsaKeys, err := derive.DeriveEdDSACoins(privKeyBytes, pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("EdDSA derivation failed: %w", err)
	}
	result.EdDSAKeys = eddsaKeys

	return result, nil
}
