package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/golang/protobuf/proto"
	v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"

	"github.com/SxMShaDoW/Vultisig-Share-Decoder/internal/tss"
)

func ReadFileContent(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func DetectScheme(vault *v1.Vault) SchemeType {
	if len(vault.KeyShares) > 0 && !isJSONString(vault.KeyShares[0].Keyshare) {
		return DKLS
	}
	return GG20
}

func ParseVaultFromFile(content []byte, fileName string, password string, source InputSource) (*v1.Vault, error) {
	contentStr := strings.TrimSpace(string(content))

	decodedData, err := base64.StdEncoding.DecodeString(contentStr)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode file: %w", err)
	}

	var vaultContainer v1.VaultContainer
	err = proto.Unmarshal(decodedData, &vaultContainer)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal vault container: %w", err)
	}

	if vaultContainer.IsEncrypted {
		return decryptVault(&vaultContainer, fileName, password, source)
	}

	vaultData, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
	if err != nil {
		return nil, fmt.Errorf("failed to decode inner vault: %w", err)
	}
	var v v1.Vault
	err = proto.Unmarshal(vaultData, &v)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal vault: %w", err)
	}
	return &v, nil
}

func ExtractGG20LocalStates(vault *v1.Vault) (map[TssKeyType]tss.LocalState, error) {
	localStates := make(map[TssKeyType]tss.LocalState)
	for _, keyshare := range vault.KeyShares {
		var localState tss.LocalState
		err := json.Unmarshal([]byte(keyshare.Keyshare), &localState)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling keyshare: %w", err)
		}
		if keyshare.PublicKey == vault.PublicKeyEcdsa {
			localStates[ECDSA] = localState
		} else {
			localStates[EdDSA] = localState
		}
	}
	return localStates, nil
}

func isJSONString(s string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(s), &js) == nil
}
