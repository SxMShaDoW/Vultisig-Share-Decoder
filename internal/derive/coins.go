package derive

type CoinKey struct {
	Name          string `json:"name"`
	DerivePath    string `json:"derivePath"`
	Address       string `json:"address"`
	HexPrivateKey string `json:"hexPrivateKey"`
	HexPublicKey  string `json:"hexPublicKey"`
	WIFPrivateKey string `json:"wifPrivateKey,omitempty"`
}

type ecdsaCoinDef struct {
	Name       string
	DerivePath string
	Derive     func(privKey, pubKey []byte) (CoinKey, error)
}

type eddsaCoinDef struct {
	Name       string
	DerivePath string
	Derive     func(privKey, pubKey []byte) (CoinKey, error)
}

func getECDSACoinDefs() []ecdsaCoinDef {
	return []ecdsaCoinDef{
		{"bitcoin", "m/84'/0'/0'/0/0", deriveBitcoin},
		{"bitcoinCash", "m/44'/145'/0'/0/0", deriveBitcoinCash},
		{"dogecoin", "m/44'/3'/0'/0/0", deriveDogecoin},
		{"litecoin", "m/84'/2'/0'/0/0", deriveLitecoin},
		{"thorchain", "m/44'/931'/0'/0/0", cosmosDeriver("thor", "THORChain")},
		{"mayachain", "m/44'/931'/0'/0/0", cosmosDeriver("maya", "MayaChain")},
		{"atomchain", "m/44'/118'/0'/0/0", cosmosDeriver("cosmos", "ATOMChain")},
		{"kujirachain", "m/44'/118'/0'/0/0", cosmosDeriver("kujira", "KujiraChain")},
		{"dydxchain", "m/44'/118'/0'/0/0", cosmosDeriver("dydx", "DydxChain")},
		{"terraclassicchain", "m/44'/118'/0'/0/0", cosmosDeriver("terra", "terraclassicchain")},
		{"terrachain", "m/44'/118'/0'/0/0", cosmosDeriver("terra", "terrachain")},
		{"ethereum", "m/44'/60'/0'/0/0", deriveEthereum},
		{"tron", "m/44'/195'/0'/0/0", deriveTron},
	}
}

func getEdDSACoinDefs() []eddsaCoinDef {
	return []eddsaCoinDef{
		{"solana", "m/44'/501'/0'/0'", deriveSolana},
		{"sui", "m/44'/784'/0'/0'/0'", deriveSui},
		{"ton", "m/44'/607'/0'/0'/0'", deriveTon},
	}
}
