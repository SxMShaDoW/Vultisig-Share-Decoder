package derive

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

func cosmosAddress(compressedPubKey []byte, hrp string) (string, error) {
	hash160 := btcutil.Hash160(compressedPubKey)
	converted, err := bech32.ConvertBits(hash160, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %w", err)
	}
	addr, err := bech32.Encode(hrp, converted)
	if err != nil {
		return "", fmt.Errorf("failed to bech32 encode: %w", err)
	}
	return addr, nil
}
