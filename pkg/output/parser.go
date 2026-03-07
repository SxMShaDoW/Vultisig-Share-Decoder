package output

import (
	"encoding/hex"
	"strings"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"main/pkg/keyhandlers"
)

func BuildRootKeyInfo(rootPrivateKeyBytes, rootChainCodeBytes []byte) RootKeyInfo {
	privateKey := secp256k1.PrivKeyFromBytes(rootPrivateKeyBytes)
	publicKey := privateKey.PubKey()

	net := &chaincfg.MainNetParams
	extendedPrivateKey := hdkeychain.NewExtendedKey(
		net.HDPrivateKeyID[:],
		privateKey.Serialize(),
		rootChainCodeBytes,
		[]byte{0x00, 0x00, 0x00, 0x00},
		0, 0, true,
	)

	return RootKeyInfo{
		HexPubKeyECDSA:  hex.EncodeToString(publicKey.SerializeCompressed()),
		HexPrivKeyECDSA: hex.EncodeToString(privateKey.Serialize()),
		ChainCode:       hex.EncodeToString(rootChainCodeBytes),
		ExtendedPrivKey: extendedPrivateKey.String(),
	}
}

func BuildECDSACoinKeys(rootPrivateKeyBytes, rootChainCodeBytes []byte) ([]CoinKeyInfo, error) {
	privateKey := secp256k1.PrivKeyFromBytes(rootPrivateKeyBytes)
	net := &chaincfg.MainNetParams
	extendedPrivateKey := hdkeychain.NewExtendedKey(
		net.HDPrivateKeyID[:],
		privateKey.Serialize(),
		rootChainCodeBytes,
		[]byte{0x00, 0x00, 0x00, 0x00},
		0, 0, true,
	)

	coins := keyhandlers.GetSupportedCoins()
	var results []CoinKeyInfo

	for _, coin := range coins {
		key, err := keyhandlers.GetDerivedPrivateKeys(coin.DerivePath, extendedPrivateKey)
		if err != nil {
			continue
		}

		var out strings.Builder
		err = coin.Action(key, &out)
		if err != nil {
			continue
		}

		results = append(results, parseCoinOutput(coin.Name, coin.DerivePath, out.String()))
	}

	return results, nil
}

func BuildEdDSACoinKeys(privateKeyBytes, publicKeyBytes []byte) ([]CoinKeyInfo, error) {
	coins := keyhandlers.GetEdDSACoins()
	var results []CoinKeyInfo

	for _, coin := range coins {
		var out strings.Builder
		err := coin.Action(privateKeyBytes, publicKeyBytes, &out)
		if err != nil {
			continue
		}

		results = append(results, parseCoinOutput(coin.Name, coin.DerivePath, out.String()))
	}

	return results, nil
}

func parseCoinOutput(name, derivePath, text string) CoinKeyInfo {
	info := CoinKeyInfo{
		Name:       name,
		DerivePath: derivePath,
	}

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)

		switch {
		case strings.Contains(line, "hex encoded") && strings.Contains(line, "private key"):
			info.HexPrivateKey = extractValue(line)
		case strings.Contains(line, "hex encoded") && strings.Contains(line, "public key"):
			info.HexPublicKey = extractValue(line)
		case strings.HasPrefix(line, "address:") || strings.Contains(line, " address:"):
			info.Address = extractValue(line)
		case strings.Contains(line, "WIF private key"):
			info.WIFPrivateKey = extractValue(line)
		}
	}

	return info
}

func extractValue(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) < 2 {
		return ""
	}
	val := strings.TrimSpace(parts[1])
	if idx := strings.Index(val, "("); idx != -1 {
		val = strings.TrimSpace(val[:idx])
	}
	return val
}
