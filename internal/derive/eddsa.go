package derive

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	"github.com/tonkeeper/tongo/wallet"
	"golang.org/x/crypto/blake2b"
)

func DeriveEdDSACoins(privKeyBytes, pubKeyBytes []byte) ([]CoinKey, error) {
	defs := getEdDSACoinDefs()
	var results []CoinKey

	for _, def := range defs {
		coinKey, err := def.Derive(privKeyBytes, pubKeyBytes)
		if err != nil {
			continue
		}
		coinKey.Name = def.Name
		coinKey.DerivePath = def.DerivePath
		results = append(results, coinKey)
	}

	return results, nil
}

func deriveSolana(privKey, pubKey []byte) (CoinKey, error) {
	return CoinKey{
		Address:       base58.Encode(pubKey),
		HexPrivateKey: hex.EncodeToString(privKey),
		HexPublicKey:  hex.EncodeToString(pubKey),
	}, nil
}

func deriveSui(privKey, pubKey []byte) (CoinKey, error) {
	input := make([]byte, 1+len(pubKey))
	input[0] = 0x00
	copy(input[1:], pubKey)

	hash := blake2b.Sum256(input)
	suiAddress := "0x" + hex.EncodeToString(hash[:])

	return CoinKey{
		Address:       suiAddress,
		HexPrivateKey: hex.EncodeToString(privKey),
		HexPublicKey:  hex.EncodeToString(pubKey),
	}, nil
}

func deriveTon(privKey, pubKey []byte) (CoinKey, error) {
	if len(privKey) != 32 {
		return CoinKey{}, fmt.Errorf("private key must be 32 bytes, got %d", len(privKey))
	}
	if len(pubKey) != 32 {
		return CoinKey{}, fmt.Errorf("public key must be 32 bytes, got %d", len(pubKey))
	}

	ver := wallet.V4R2
	workchain := 0
	networkGlobalID := int32(-239)
	subWalletId := uint32(698983191)

	addr, err := wallet.GenerateWalletAddress(
		ed25519.PublicKey(pubKey),
		ver,
		&networkGlobalID,
		workchain,
		&subWalletId,
	)
	if err != nil {
		return CoinKey{}, fmt.Errorf("error generating wallet address: %w", err)
	}

	tonAddress := addr.ToHuman(false, false)

	return CoinKey{
		Address:       tonAddress,
		HexPrivateKey: hex.EncodeToString(privKey),
		HexPublicKey:  hex.EncodeToString(pubKey),
	}, nil
}
