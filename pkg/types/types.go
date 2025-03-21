package types

import (
    //"github.com/vultisig/mobile-tss-lib/tss"
    "main/tss"
)

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

// tempLocalState holds the filename and local state information
type TempLocalState struct {
    FileName   string
    LocalState map[TssKeyType]tss.LocalState
}

type FileInfo struct {
    Name    string
    Content []byte
}