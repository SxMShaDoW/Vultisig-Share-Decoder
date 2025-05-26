
package dkls

import (
    "main/pkg/types"
)

// DKLSShareData represents the internal structure of a DKLS share
type DKLSShareData struct {
    ID        string `json:"id"`
    ShareData []byte `json:"share_data"`
    PartyID   string `json:"party_id"`
}

// KeyExportResponse represents the response from DKLS key export
type KeyExportResponse struct {
    PrivateKey []byte `json:"private_key"`
    PublicKey  []byte `json:"public_key"`
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
