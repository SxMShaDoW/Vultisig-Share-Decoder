package format

import (
	"encoding/json"

	"github.com/SxMShaDoW/Vultisig-Share-Decoder/internal/recovery"
)

func JSON(r *recovery.RecoveryResult) (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
