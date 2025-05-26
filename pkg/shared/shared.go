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
	"main/pkg/dkls"
	"main/pkg/fileutils"
	"main/pkg/keyprocessing"
	"main/pkg/types"
	"main/tss"

	"encoding/json"
)

// DetectSchemeType determines if the vault content is GG20 or DKLS
func DetectSchemeType(content []byte) types.SchemeType {
	// Try to decode as protobuf (GG20 format)
	vault := &v1.Vault{}
	if err := proto.Unmarshal(content, vault); err == nil && vault.Name != "" {
		log.Printf("Detected GG20 scheme based on protobuf structure")
		return types.GG20
	}

	// Try to decode as JSON (potential DKLS format)
	var jsonData map[string]interface{}
	if err := json.Unmarshal(content, &jsonData); err == nil {
		// Check for DKLS-specific fields
		if _, hasDKLSField := jsonData["dkls"]; hasDKLSField {
			log.Printf("Detected DKLS scheme based on JSON structure")
			return types.DKLS
		}
		if _, hasShareData := jsonData["share_data"]; hasShareData {
			log.Printf("Detected DKLS scheme based on share_data field")
			return types.DKLS
		}
	}

	// Default to GG20 for backward compatibility
	log.Printf("Defaulting to GG20 scheme (no clear DKLS indicators found)")
	return types.GG20
}

// ProcessDKLSFiles processes DKLS format files
func ProcessDKLSFiles(fileInfos []types.FileInfo, outputBuilder *strings.Builder, threshold int) error {
	log.Printf("Processing %d DKLS files with threshold %d", len(fileInfos), threshold)

	dklsWrapper := dkls.NewDKLSWrapper()
	if err := dklsWrapper.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize DKLS wrapper: %w", err)
	}

	var dklsShares []dkls.DKLSShareData
	var partyIDs []string

	for i, fileInfo := range fileInfos {
		log.Printf("Processing DKLS file %d: %s", i, fileInfo.Name)

		// Try to parse as DKLS share
		var shareData dkls.DKLSShareData
		if err := json.Unmarshal(fileInfo.Content, &shareData); err != nil {
			return fmt.Errorf("failed to parse DKLS share from file %s: %w", fileInfo.Name, err)
		}

		dklsShares = append(dklsShares, shareData)
		partyIDs = append(partyIDs, shareData.PartyID)

		fmt.Fprintf(outputBuilder, "DKLS Share %d (%s):\n", i+1, fileInfo.Name)
		fmt.Fprintf(outputBuilder, "  Party ID: %s\n", shareData.PartyID)
		fmt.Fprintf(outputBuilder, "  Share ID: %s\n", shareData.ID)
		fmt.Fprintf(outputBuilder, "  Share Data Length: %d bytes\n\n", len(shareData.ShareData))
	}

	if len(dklsShares) < threshold {
		return fmt.Errorf("insufficient DKLS shares: need %d, got %d", threshold, len(dklsShares))
	}

	// Process the DKLS shares
	return keyprocessing.ProcessDKLSKeys(threshold, dklsShares, partyIDs, outputBuilder)
}

func ProcessFileContent(fileInfos []types.FileInfo, passwords []string, source types.InputSource) (string, error) {
	var outputBuilder strings.Builder

	if os.Getenv("ENABLE_LOGGING") != "true" {
		log.SetOutput(io.Discard)
	}

	if len(fileInfos) == 0 {
		return "", fmt.Errorf("no files provided")
	}

	// Detect scheme from first file
	scheme := DetectSchemeType(fileInfos[0].Content)
	fmt.Fprintf(&outputBuilder, "Detected scheme: %s\n\n", scheme)

	if scheme == types.DKLS {
		// Process DKLS files
		threshold := len(fileInfos) // For DKLS, typically use all shares
		return ProcessDKLSFilesAndGetResult(fileInfos, &outputBuilder, threshold)
	}

	// Handle GG20 format (original logic)
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
				return "", fmt.Errorf("error processing file %d: %w", i, err)
			}
		} else {
			log.Printf("Successfully unmarshalled as protobuf VaultContainer")
			localStates, err = fileutils.GetLocalStateFromBakContent([]byte(contentStr), password, source)
			if err != nil {
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

	// Route to appropriate processing based on scheme
	switch scheme {
	case types.GG20:
		// Process GG20 files

		if err := keyprocessing.GetKeys(threshold, allSecret, types.ECDSA, &outputBuilder); err != nil {
			return "", fmt.Errorf("error processing ECDSA keys: %w", err)
		}
		if err := keyprocessing.GetKeys(threshold, allSecret, types.EdDSA, &outputBuilder); err != nil {
			return "", fmt.Errorf("error processing EdDSA keys: %w", err)
		}
		return outputBuilder.String(), nil
	default:
		return "", fmt.Errorf("unsupported scheme type: %s", scheme.String())
	}
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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

		localStates, err := fileutils.ParseVault(fileInfo.Content)
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

// ProcessDKLSFilesAndGetResult processes DKLS files and returns the result.
func ProcessDKLSFilesAndGetResult(fileInfos []types.FileInfo, outputBuilder *strings.Builder, threshold int) (string, error) {
	err := ProcessDKLSFiles(fileInfos, outputBuilder, threshold)
	if err != nil {
		return "", err
	}
	return outputBuilder.String(), nil
}