package shared

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/golang/protobuf/proto"
	v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"main/pkg/fileutils"
	"main/pkg/keyprocessing"
	"main/pkg/types"
	"main/tss"

	"encoding/json"
)

func ProcessFileContent(fileInfos []types.FileInfo, passwords []string, source types.InputSource) (string, error) {
	var outputBuilder strings.Builder

	if os.Getenv("ENABLE_LOGGING") != "true" {
		log.SetOutput(io.Discard)
	}

	if len(fileInfos) == 0 {
		return "", fmt.Errorf("no files provided")
	}
	
	allSecret := make([]types.TempLocalState, 0, len(fileInfos))

	// Process each file
	for i, file := range fileInfos {
		contentStr := strings.TrimSpace(string(file.Content))

		log.Printf("Processing file %d, content starts with: %s", i, contentStr[:min(len(contentStr), 50)])

		password := ""
		if i < len(passwords) {
			password = passwords[i]
		}

		var localStates map[types.TssKeyType]tss.LocalState
		var err error

		decodedData, err := base64.StdEncoding.DecodeString(contentStr)
		if err != nil {
			log.Printf("File %d is not base64 encoded, trying direct parsing", i)
			decodedData = file.Content
		} else {
			log.Printf("File %d successfully decoded from base64", i)
		}

		var vaultContainer v1.VaultContainer
		if err := proto.Unmarshal(decodedData, &vaultContainer); err != nil {
			log.Printf("Failed to unmarshal as protobuf: %v", err)
			localStates, err = fileutils.GetLocalStateFromContent(decodedData)
			if err != nil {
				// Check if this error indicates a DKLS vault
				if strings.Contains(err.Error(), "DKLS vault detected") {
					log.Printf("File %d detected as DKLS format, skipping GG20 processing", i)
					continue // Skip this file for GG20 processing
				}
				return "", fmt.Errorf("error processing file %d: %w", i, err)
			}
		} else {
			log.Printf("Successfully unmarshalled as protobuf VaultContainer")
			localStates, err = fileutils.GetLocalStateFromBakContent([]byte(contentStr), password, source)
			if err != nil {
				// Check if this error indicates a DKLS vault
				if strings.Contains(err.Error(), "DKLS vault detected") {
					log.Printf("File %d detected as DKLS format, skipping GG20 processing", i)
					continue // Skip this file for GG20 processing
				}
				return "", fmt.Errorf("error processing vault container file %d: %w", i, err)
			}
		}

		// Add share details to output
		outputBuilder.WriteString(fmt.Sprintf("Backup name: %s\n", file.Name))
		if eddsaState, ok := localStates[types.EdDSA]; ok {
			outputBuilder.WriteString(fmt.Sprintf("This Share: %s\n", eddsaState.LocalPartyKey))
			outputBuilder.WriteString(fmt.Sprintf("All Shares: %v\n", eddsaState.KeygenCommitteeKeys))
		}

		allSecret = append(allSecret, types.TempLocalState{
			FileName:   fmt.Sprintf("file_%d", i),
			LocalState: localStates,
		})
	}

	threshold := len(allSecret)
	log.Printf("Using threshold %d for %d secrets", threshold, len(allSecret))

	// Process GG20 files
	if err := keyprocessing.GetKeys(threshold, allSecret, types.ECDSA, &outputBuilder); err != nil {
		return "", fmt.Errorf("error processing ECDSA keys: %w", err)
	}
	if err := keyprocessing.GetKeys(threshold, allSecret, types.EdDSA, &outputBuilder); err != nil {
		return "", fmt.Errorf("error processing EdDSA keys: %w", err)
	}
	return outputBuilder.String(), nil
}



func ParseLocalState(content []byte) (map[types.TssKeyType]tss.LocalState, error) {
	var vault v1.Vault
	if err := proto.Unmarshal(content, &vault); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vault: %w", err)
	}

	localStates := make(map[types.TssKeyType]tss.LocalState)
	for _, keyshare := range vault.KeyShares {
		var localState tss.LocalState
		if err := json.Unmarshal([]byte(keyshare.Keyshare), &localState); err != nil {
			return nil, fmt.Errorf("error unmarshalling keyshare: %w", err)
		}
		if keyshare.PublicKey == vault.PublicKeyEcdsa {
			localStates[types.ECDSA] = localState
		} else {
			localStates[types.EdDSA] = localState
		}
	}

	return localStates, nil
}


// ProcessGG20Files processes the original GG20 format files (existing functionality)
func ProcessGG20Files(fileInfos []types.FileInfo, outputBuilder *strings.Builder, threshold int) error {
	fmt.Fprintf(outputBuilder, "=== Processing GG20 Files ===\n\n")

	var tempLocalStates []types.TempLocalState

	for _, fileInfo := range fileInfos {
		log.Printf("Processing GG20 file: %s", fileInfo.Name)

		localStates, err := ParseLocalState(fileInfo.Content)
		if err != nil {
			return fmt.Errorf("error processing file %s: %w", fileInfo.Name, err)
		}

		tempLocalState := types.TempLocalState{
			FileName:   fileInfo.Name,
			LocalState: localStates,
			SchemeType: types.GG20,
		}
		tempLocalStates = append(tempLocalStates, tempLocalState)
	}

	if len(tempLocalStates) == 0 {
		return fmt.Errorf("no valid vault data found in any file")
	}

	fmt.Fprintf(outputBuilder, "Successfully loaded %d GG20 vault(s)\n\n", len(tempLocalStates))

	// Check if we have ECDSA keys
	hasECDSA := false
	hasEdDSA := false
	for _, tempState := range tempLocalStates {
		if _, exists := tempState.LocalState[types.ECDSA]; exists {
			hasECDSA = true
		}
		if _, exists := tempState.LocalState[types.EdDSA]; exists {
			hasEdDSA = true
		}
	}

	if hasECDSA {
		fmt.Fprintf(outputBuilder, "=== ECDSA Key Recovery ===\n")
		if err := keyprocessing.GetKeys(threshold, tempLocalStates, types.ECDSA, outputBuilder); err != nil {
			fmt.Fprintf(outputBuilder, "ECDSA key recovery failed: %v\n", err)
		}
		fmt.Fprintf(outputBuilder, "\n")
	}

	if hasEdDSA {
		fmt.Fprintf(outputBuilder, "=== EdDSA Key Recovery ===\n")
		if err := keyprocessing.GetKeys(threshold, tempLocalStates, types.EdDSA, outputBuilder); err != nil {
			fmt.Fprintf(outputBuilder, "EdDSA key recovery failed: %v\n", err)
		}
	}

	if !hasECDSA && !hasEdDSA {
		return fmt.Errorf("no valid key types found in vault files")
	}

	return nil
}