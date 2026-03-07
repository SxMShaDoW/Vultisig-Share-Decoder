package recovery

import (
	"github.com/vultisig/vsd/internal/derive"
)

type RootKeyInfo struct {
	HexPubKeyECDSA  string `json:"hexPubKeyECDSA"`
	HexPrivKeyECDSA string `json:"hexPrivKeyECDSA"`
	ChainCode       string `json:"chainCode"`
	ExtendedPrivKey string `json:"extendedPrivateKey"`
}

type ShareDetail struct {
	BackupName string   `json:"backupName"`
	ThisShare  string   `json:"thisShare"`
	AllShares  []string `json:"allShares"`
}

type PublicKeyInfo struct {
	ECDSA string `json:"ecdsa,omitempty"`
	EdDSA string `json:"eddsa,omitempty"`
}

type RecoveryResult struct {
	Success      bool             `json:"success"`
	Error        string           `json:"error,omitempty"`
	Scheme       string           `json:"scheme"`
	ShareDetails []ShareDetail    `json:"shareDetails,omitempty"`
	PublicKeys   PublicKeyInfo    `json:"publicKeys"`
	RootKeyInfo  *RootKeyInfo     `json:"rootKeyInfo,omitempty"`
	ECDSAKeys    []derive.CoinKey `json:"ecdsaKeys"`
	EdDSAKeys    []derive.CoinKey `json:"eddsaKeys,omitempty"`
}
