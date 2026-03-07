package recovery

import (
	"fmt"

	"github.com/vultisig/vsd/internal/vault"
)

func Recover(inputs []vault.FileInput, passwords []string, scheme string) (*RecoveryResult, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no files provided")
	}

	switch scheme {
	case "dkls":
		return recoverDKLS(inputs, passwords)
	case "gg20":
		return recoverGG20(inputs, passwords)
	case "auto":
		return recoverAuto(inputs, passwords)
	default:
		return nil, fmt.Errorf("unsupported scheme: %s (supported: auto, gg20, dkls)", scheme)
	}
}

func recoverAuto(inputs []vault.FileInput, passwords []string) (*RecoveryResult, error) {
	password := ""
	if len(passwords) > 0 {
		password = passwords[0]
	}
	v, err := vault.ParseVaultFromFile(inputs[0].Content, inputs[0].Name, password, vault.CommandLine)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vault: %w", err)
	}

	scheme := vault.DetectScheme(v)
	if scheme == vault.DKLS {
		return recoverDKLS(inputs, passwords)
	}
	return recoverGG20(inputs, passwords)
}
