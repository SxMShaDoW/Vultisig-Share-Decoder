package output

type CoinKeyInfo struct {
	Name          string `json:"name"`
	DerivePath    string `json:"derivePath"`
	HexPrivateKey string `json:"hexPrivateKey"`
	HexPublicKey  string `json:"hexPublicKey"`
	Address       string `json:"address"`
	WIFPrivateKey string `json:"wifPrivateKey,omitempty"`
}

type RootKeyInfo struct {
	HexPubKeyECDSA  string `json:"hexPubKeyECDSA"`
	HexPrivKeyECDSA string `json:"hexPrivKeyECDSA"`
	ChainCode       string `json:"chainCode"`
	ExtendedPrivKey string `json:"extendedPrivateKey"`
}

type ShareDetails struct {
	BackupName string   `json:"backupName"`
	ThisShare  string   `json:"thisShare"`
	AllShares  []string `json:"allShares"`
}

type PublicKeyInfo struct {
	ECDSA string `json:"ecdsa,omitempty"`
	EdDSA string `json:"eddsa,omitempty"`
}

type RecoveryResult struct {
	Success      bool           `json:"success"`
	Error        string         `json:"error,omitempty"`
	Scheme       string         `json:"scheme"`
	ShareDetails []ShareDetails `json:"shareDetails,omitempty"`
	PublicKeys   PublicKeyInfo  `json:"publicKeys"`
	RootKeyInfo  *RootKeyInfo   `json:"rootKeyInfo,omitempty"`
	ECDSAKeys    []CoinKeyInfo  `json:"ecdsaKeys"`
	EdDSAKeys    []CoinKeyInfo  `json:"eddsaKeys,omitempty"`
}
