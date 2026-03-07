package dkls

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/golang/protobuf/proto"
	v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"

	"main/pkg/encryption"
	"main/pkg/types"
)

type VaultKeyshares struct {
	ECDSAKeyshares [][]byte
	EdDSAKeyshares [][]byte
	PartyIDs       []string
}

func ExtractDKLSKeyshares(fileInfos []types.FileInfo, passwords []string, source types.InputSource) ([][]byte, []string, error) {
	result, err := ExtractAllKeyshares(fileInfos, passwords, source)
	if err != nil {
		return nil, nil, err
	}
	return result.ECDSAKeyshares, result.PartyIDs, nil
}

func ExtractAllKeyshares(fileInfos []types.FileInfo, passwords []string, source types.InputSource) (*VaultKeyshares, error) {
	if len(fileInfos) < 2 {
		return nil, fmt.Errorf("DKLS requires at least 2 keyshare files, got %d", len(fileInfos))
	}

	result := &VaultKeyshares{
		ECDSAKeyshares: make([][]byte, 0, len(fileInfos)),
		EdDSAKeyshares: make([][]byte, 0, len(fileInfos)),
		PartyIDs:       make([]string, 0, len(fileInfos)),
	}

	for i, file := range fileInfos {
		password := ""
		if i < len(passwords) {
			password = passwords[i]
		}

		vault, err := parseVaultFromFile(file.Content, file.Name, password, source)
		if err != nil {
			return nil, fmt.Errorf("failed to parse vault file %s: %w", file.Name, err)
		}

		if len(vault.KeyShares) == 0 {
			return nil, fmt.Errorf("no keyshares found in vault file %s", file.Name)
		}

		keyshareStr := vault.KeyShares[0].Keyshare
		if keyshareStr == "" {
			return nil, fmt.Errorf("empty ECDSA keyshare in vault file %s", file.Name)
		}

		ecdsaBytes, err := decodeKeyshare(keyshareStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode ECDSA keyshare from %s: %w", file.Name, err)
		}

		result.ECDSAKeyshares = append(result.ECDSAKeyshares, ecdsaBytes)

		if len(vault.KeyShares) > 1 && vault.KeyShares[1].Keyshare != "" {
			eddsaBytes, err := decodeKeyshare(vault.KeyShares[1].Keyshare)
			if err != nil {
				return nil, fmt.Errorf("failed to decode EdDSA keyshare from %s: %w", file.Name, err)
			}
			result.EdDSAKeyshares = append(result.EdDSAKeyshares, eddsaBytes)
		}

		partyID := vault.LocalPartyId
		if partyID == "" {
			return nil, fmt.Errorf("no party ID found in vault file %s", file.Name)
		}

		result.PartyIDs = append(result.PartyIDs, partyID)
	}

	return result, nil
}

func parseVaultFromFile(content []byte, fileName string, password string, source types.InputSource) (*v1.Vault, error) {
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

	var vault *v1.Vault
	if vaultContainer.IsEncrypted {
		vault, err = encryption.DecryptVault(&vaultContainer, fileName, password, source)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt vault: %w", err)
		}
	} else {
		vaultData, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
		if err != nil {
			return nil, fmt.Errorf("failed to decode inner vault: %w", err)
		}
		var v v1.Vault
		err = proto.Unmarshal(vaultData, &v)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal vault: %w", err)
		}
		vault = &v
	}

	return vault, nil
}

func decodeKeyshare(keyshareStr string) ([]byte, error) {
	trimmed := strings.TrimSpace(keyshareStr)

	// Try hex decoding first
	if isHexString(trimmed) {
		decoded, err := hex.DecodeString(trimmed)
		if err == nil && len(decoded) > 100 {
			return decoded, nil
		}
	}

	// Try base64 decoding
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err == nil && len(decoded) > 100 {
		return decoded, nil
	}

	// Try base64 raw (no padding)
	decoded, err = base64.RawStdEncoding.DecodeString(trimmed)
	if err == nil && len(decoded) > 100 {
		return decoded, nil
	}

	return nil, fmt.Errorf("keyshare string could not be decoded as hex or base64 (length: %d)", len(trimmed))
}

func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0 && len(s)%2 == 0
}
