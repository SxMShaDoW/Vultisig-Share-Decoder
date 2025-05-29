// Updated DKLS types for protobuf handling
package dkls

import (
	"main/pkg/types"
	//"github.com/vultisig/mobile-tss-lib/tss"
)

// DKLSShareData represents a DKLS key share
type DKLSShareData struct {
	ID        string
	ShareData []byte
	PartyID   string
	PublicKey string // Added to store public key from vault
}

// KeyExportResponse represents the response from DKLS key export
type KeyExportResponse struct {
	PrivateKey string
	PublicKey  string
	Success    bool
	Error      string
}

// DKLSKeyResult represents the final result of DKLS key reconstruction
type DKLSKeyResult struct {
	PrivateKeyHex string
	PublicKeyHex  string
	Address       string
	KeyType       types.TssKeyType
}

// DKLSVaultData represents parsed DKLS vault information
type DKLSVaultData struct {
	Name           string
	LocalPartyID   string
	PublicKeyEcdsa string
	PublicKeyEddsa string
	KeyShares      []DKLSKeyShare
	ResharePrefix  string
	LibType        int32
}

// DKLSKeyShare represents a keyshare from the vault
type DKLSKeyShare struct {
	PublicKey string
	Keyshare  []byte // Raw keyshare bytes for WASM
}