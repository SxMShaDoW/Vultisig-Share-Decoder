
package dkls

import (
    "main/pkg/types"
)

// DKLSShare represents a DKLS threshold signature share
type DKLSShare struct {
	PartyID   string `json:"party_id"`
	ShareData []byte `json:"share_data"`
	PublicKey string `json:"public_key"`
}

// DKLSShareData represents the data structure for DKLS shares
type DKLSShareData struct {
	ID        string `json:"id"`
	PartyID   string `json:"party_id"`
	ShareData []byte `json:"share_data"`
}

// KeyExportResponse represents the response from DKLS key export
type KeyExportResponse struct {
    PrivateKey string `json:"private_key"`
    PublicKey  string `json:"public_key"`
    Success    bool   `json:"success"`
    Error      string `json:"error,omitempty"`
}

// DKLSKeyResult holds the reconstructed key information
type DKLSKeyResult struct {
    PrivateKeyHex string
    PublicKeyHex  string
    Address       string
    KeyType       types.TssKeyType
}

// DKLSSession represents an active DKLS key export session
type DKLSSession struct {
    SessionID string
    Shares    []DKLSShareData
    PartyIDs  []string
    Threshold int
    IsActive  bool
}
