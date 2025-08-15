package keyhandlers

import (
	"strings"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

// CoinConfig represents configuration for a supported ECDSA-based cryptocurrency
type CoinConfig struct {
	Name       string
	DerivePath string
	Action     func(*hdkeychain.ExtendedKey, *strings.Builder) error
}

// CoinConfigEdDSA represents configuration for a supported EdDSA-based cryptocurrency
type CoinConfigEdDSA struct {
	Name       string
	DerivePath string
	Action     func([]byte, []byte, *strings.Builder) error // (privateKey, publicKey, output) -> error
}

// GetSupportedCoins returns the list of all supported cryptocurrencies with their configurations
func GetSupportedCoins() []CoinConfig {
	return []CoinConfig{
		{
			Name:       "bitcoin",
			DerivePath: "m/84'/0'/0'/0/0",
			Action:     ShowBitcoinKey,
		},
		{
			Name:       "bitcoinCash",
			DerivePath: "m/44'/145'/0'/0/0",
			Action:     ShowBitcoinCashKey,
		},
		{
			Name:       "dogecoin",
			DerivePath: "m/44'/3'/0'/0/0",
			Action:     ShowDogecoinKey,
		},
		{
			Name:       "litecoin",
			DerivePath: "m/84'/2'/0'/0/0",
			Action:     ShowLitecoinKey,
		},
		{
			Name:       "thorchain",
			DerivePath: "m/44'/931'/0'/0/0",
			Action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
				return CosmosLikeKeyHandler(key, "thor", "v", "c", output, "THORChain")
			},
		},
		{
			Name:       "mayachain",
			DerivePath: "m/44'/931'/0'/0/0",
			Action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
				return CosmosLikeKeyHandler(key, "maya", "v", "c", output, "MayaChain")
			},
		},
		{
			Name:       "atomchain",
			DerivePath: "m/44'/118'/0'/0/0",
			Action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
				return CosmosLikeKeyHandler(key, "cosmos", "valoper", "valcons", output, "ATOMChain")
			},
		},
		{
			Name:       "kujirachain",
			DerivePath: "m/44'/118'/0'/0/0",
			Action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
				return CosmosLikeKeyHandler(key, "kujira", "valoper", "valcons", output, "KujiraChain")
			},
		},
		{
			Name:       "dydxchain",
			DerivePath: "m/44'/118'/0'/0/0",
			Action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
				return CosmosLikeKeyHandler(key, "dydx", "valoper", "valcons", output, "DydxChain")
			},
		},
		{
			Name:       "terraclassicchain",
			DerivePath: "m/44'/118'/0'/0/0",
			Action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
				return CosmosLikeKeyHandler(key, "terra", "valoper", "valcons", output, "terraclassicchain")
			},
		},
		{
			Name:       "terrachain",
			DerivePath: "m/44'/118'/0'/0/0",
			Action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
				return CosmosLikeKeyHandler(key, "terra", "valoper", "valcons", output, "terrachain")
			},
		},
		{
			Name:       "ethereum",
			DerivePath: "m/44'/60'/0'/0/0",
			Action:     ShowEthereumKey,
		},
		{
			Name:       "tron",
			DerivePath: "m/44'/195'/0'/0/0",
			Action:     ShowTronKey,
		},
	}
}