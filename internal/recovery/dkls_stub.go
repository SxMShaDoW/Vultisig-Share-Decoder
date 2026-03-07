//go:build wasm

package recovery

import (
	"fmt"

	"github.com/SxMShaDoW/Vultisig-Share-Decoder/internal/vault"
)

func recoverDKLS(inputs []vault.FileInput, passwords []string) (*RecoveryResult, error) {
	return nil, fmt.Errorf("DKLS recovery is not available in WASM builds; use the Rust WASM module instead")
}
