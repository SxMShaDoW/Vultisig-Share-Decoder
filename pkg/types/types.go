package types

import (
    //"github.com/vultisig/mobile-tss-lib/tss"
    "main/tss"
)

// SchemeType represents the cryptographic scheme type
type SchemeType int

const (
    GG20 SchemeType = iota
    DKLS
)

func (s SchemeType) String() string {
    return [...]string{"GG20", "DKLS"}[s]
}

// TssKeyType represents the type of TSS key
type TssKeyType int

const (
    ECDSA TssKeyType = iota
    EdDSA
)

func (t TssKeyType) String() string {
    return [...]string{"ECDSA", "EdDSA"}[t]
}

// InputSource defines the source of input for the application
type InputSource int

const (
    CommandLine InputSource = iota
    Web
)

// DKLSShare represents a DKLS key share
type DKLSShare struct {
    ID        string `json:"id"`
    ShareData []byte `json:"share_data"`
    Threshold int    `json:"threshold"`
    PartyID   string `json:"party_id"`
}

// DKLSLocalState holds DKLS-specific local state information
type DKLSLocalState struct {
    Share      DKLSShare `json:"share"`
    PubKey     string    `json:"pub_key"`
    PartyIDs   []string  `json:"party_ids"`
    Threshold  int       `json:"threshold"`
    SchemeType SchemeType `json:"scheme_type"`
}

// tempLocalState holds the filename and local state information
type TempLocalState struct {
    FileName    string
    LocalState  map[TssKeyType]tss.LocalState
    DKLSState   *DKLSLocalState
    SchemeType  SchemeType
}

type FileInfo struct {
    Name       string
    Content    []byte
    SchemeType SchemeType
}

// VaultContent represents the parsed content of a vault file
type VaultContent struct {
    SchemeType  SchemeType
    GG20Data    map[TssKeyType]tss.LocalState
    DKLSData    *DKLSLocalState
    IsEncrypted bool
}