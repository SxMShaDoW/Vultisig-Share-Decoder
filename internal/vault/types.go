package vault

import (
	"github.com/SxMShaDoW/Vultisig-Share-Decoder/internal/tss"
)

type SchemeType int

const (
	GG20 SchemeType = iota
	DKLS
)

func (s SchemeType) String() string {
	return [...]string{"gg20", "dkls"}[s]
}

type TssKeyType int

const (
	ECDSA TssKeyType = iota
	EdDSA
)

func (t TssKeyType) String() string {
	return [...]string{"ECDSA", "EdDSA"}[t]
}

type InputSource int

const (
	CommandLine InputSource = iota
	Web
)

type FileInput struct {
	Name    string
	Content []byte
}

type TempLocalState struct {
	FileName   string
	LocalState map[TssKeyType]tss.LocalState
}
