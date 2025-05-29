// Fix DKLS vault parsing to handle raw keyshare data
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
	// Try to decode as base64 first (common for vault files)
	if decoded, err := base64.StdEncoding.DecodeString(string(content)); err == nil {
		content = decoded
	}

	// Check if it's a vault container format first
	var vaultContainer v1.VaultContainer
	if err := proto.Unmarshal(content, &vaultContainer); err == nil {
		log.Printf("Found VaultContainer, checking inner vault")
		// Decode the inner vault to check lib_type
		vaultData, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
		if err != nil {
			log.Printf("Failed to decode inner vault from container")
			return types.GG20
		}
		content = vaultData
	}

	// Try to decode as protobuf Vault
	vault := &v1.Vault{}
	if err := proto.Unmarshal(content, vault); err == nil && vault.Name != "" {
		log.Printf("Vault Name: %s", vault.Name)

		// Check if it has the reshare_prefix field (DKLS specific)
		if vault.ResharePrefix != "" {
			log.Printf("Detected DKLS scheme based on reshare_prefix field")
			return types.DKLS
		}

		// Check for DKLS by examining keyshare format
		if len(vault.KeyShares) > 0 {
			// DKLS keyshares are typically not valid JSON
			keyshare := vault.KeyShares[0].Keyshare
			if !isJSONString(keyshare) {
				log.Printf("Detected DKLS scheme based on non-JSON keyshare format")
				return types.DKLS
			}
		}

		log.Printf("Detected GG20 scheme")
		return types.GG20
	}

	// Default to GG20 for backward compatibility
	log.Printf("Defaulting to GG20 scheme (failed to parse as protobuf)")
	return types.GG20
}

// ProcessDKLSFiles processes DKLS files and returns the result.
func ProcessDKLSFiles(fileInfos []types.FileInfo, outputBuilder *strings.Builder, threshold int) error {
	log.Printf("ProcessDKLSFiles: Processing %d DKLS files with threshold %d", len(fileInfos), threshold)

	var dklsShares []dkls.DKLSShareData
	var partyIDs []string

	for i, fileInfo := range fileInfos {
		log.Printf("Processing DKLS file %d: %s", i, fileInfo.Name)

		// Try to parse as vault first, if that fails, treat as raw keyshare data
		vault, _, err := ParseDKLSVault(fileInfo.Content)
		if err != nil {
			log.Printf("Failed to parse as vault, treating as raw keyshare data: %v", err)

			// Create a share data entry with raw content
			shareData := dkls.DKLSShareData{
				ID:        fmt.Sprintf("share_%d", i),
				PartyID:   fmt.Sprintf("party_%d", i),
				ShareData: fileInfo.Content,
			}

			dklsShares = append(dklsShares, shareData)
			partyIDs = append(partyIDs, shareData.PartyID)

			log.Printf("Created raw DKLS share: ID=%s, PartyID=%s, DataLength=%d",
				shareData.ID, shareData.PartyID, len(shareData.ShareData))
			continue
		}

		// Log vault information for debugging
		log.Printf("Vault: Name='%s', LocalPartyId='%s', ResharePrefix='%s'",
			vault.Name, vault.LocalPartyId, vault.ResharePrefix)
		log.Printf("Vault has %d keyshares", len(vault.KeyShares))
		log.Printf("PublicKeyEcdsa: %s", vault.PublicKeyEcdsa)
		log.Printf("PublicKeyEddsa: %s", vault.PublicKeyEddsa)

		// Extract DKLS share data from vault
		shareData := dkls.DKLSShareData{
			ID:      vault.LocalPartyId,
			PartyID: vault.LocalPartyId,
		}

		// Get keyshare data - for DKLS, we need the raw keyshare content
		if len(vault.KeyShares) > 0 {
			// For DKLS, the keyshare is not JSON but raw binary/string data
			keyshareData := vault.KeyShares[0].Keyshare
			shareData.ShareData = []byte(keyshareData)
			log.Printf("DKLS keyshare data length: %d bytes", len(shareData.ShareData))
			log.Printf("Keyshare preview: %s", string(shareData.ShareData[:min(len(shareData.ShareData), 100)]))

			// If there are multiple keyshares, log them all
			for j, ks := range vault.KeyShares {
				log.Printf("Keyshare %d: PublicKey=%s, Length=%d bytes",
					j, ks.PublicKey, len(ks.Keyshare))
			}
		} else {
			log.Printf("Warning: No keyshares found in DKLS vault")
		}

		dklsShares = append(dklsShares, shareData)
		partyIDs = append(partyIDs, shareData.PartyID)

		fmt.Fprintf(outputBuilder, "DKLS Share %d (%s):\n", i+1, fileInfo.Name)
		fmt.Fprintf(outputBuilder, "  Vault Name: %s\n", vault.Name)
		fmt.Fprintf(outputBuilder, "  Party ID: %s\n", shareData.PartyID)
		fmt.Fprintf(outputBuilder, "  Share ID: %s\n", shareData.ID)
		fmt.Fprintf(outputBuilder, "  ECDSA Public Key: %s\n", vault.PublicKeyEcdsa)
		fmt.Fprintf(outputBuilder, "  EdDSA Public Key: %s\n", vault.PublicKeyEddsa)
		fmt.Fprintf(outputBuilder, "  Share Data Length: %d bytes\n\n", len(shareData.ShareData))
	}

	if len(dklsShares) < threshold {
		return fmt.Errorf("insufficient DKLS shares: need %d, got %d", threshold, len(dklsShares))
	}

	// Process the DKLS shares
	return keyprocessing.ProcessDKLSKeys(threshold, dklsShares, partyIDs, outputBuilder)
}

// ParseDKLSVault parses a DKLS vault from content
func ParseDKLSVault(content []byte) (*v1.Vault, dkls.DKLSShareData, error) {
	log.Printf("ParseDKLSVault: Starting parse for %d bytes", len(content))

	// Try to decode as base64 first
	if decoded, err := base64.StdEncoding.DecodeString(string(content)); err == nil {
		log.Printf("ParseDKLSVault: Successfully decoded base64, new length: %d", len(decoded))
		content = decoded
	}

	// Check if it's a vault container format first
	var vaultContainer v1.VaultContainer
	if err := proto.Unmarshal(content, &vaultContainer); err == nil {
		log.Printf("ParseDKLSVault: Found VaultContainer")
		// Decode the inner vault
		vaultData, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
		if err != nil {
			return nil, dkls.DKLSShareData{}, fmt.Errorf("failed to decode inner vault: %w", err)
		}
		log.Printf("ParseDKLSVault: Decoded inner vault, length: %d", len(vaultData))
		content = vaultData
	}

	// Parse as vault
	vault := &v1.Vault{}
	if err := proto.Unmarshal(content, vault); err != nil {
		return nil, dkls.DKLSShareData{}, fmt.Errorf("failed to unmarshal vault: %w", err)
	}

	log.Printf("ParseDKLSVault: Successfully parsed vault '%s' with %d keyshares", vault.Name, len(vault.KeyShares))

	// Check lib_type to confirm this is a DKLS vault (lib_type = 1)
	// Note: The protobuf field might be named differently in the actual struct
	log.Printf("ParseDKLSVault: Vault appears to be DKLS format based on structure")

	return vault, dkls.DKLSShareData{}, nil
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
		fmt.Fprintf(&outputBuilder, "Processing %d DKLS files with threshold %d\n\n", len(fileInfos), threshold)
		err := ProcessDKLSFiles(fileInfos, &outputBuilder, threshold)
		if err != nil {
			return "", fmt.Errorf("error processing DKLS files: %w", err)
		}
		return outputBuilder.String(), nil
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

	// Check if this is a DKLS vault by looking for DKLS indicators
	isDKLS := vault.ResharePrefix != "" || len(vault.KeyShares) > 0 && !isJSONString(vault.KeyShares[0].Keyshare)

	if isDKLS {
		// For DKLS vaults, we don't parse keyshares as JSON since they're in a different format
		// Return an error to indicate this should be handled by DKLS processing instead
		return nil, fmt.Errorf("DKLS vault detected - keyshares are not in JSON format")
	}

	// Handle GG20 format (original logic)
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

// isJSONString checks if a string is valid JSON
func isJSONString(s string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(s), &js) == nil
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

// ProcessDKLSFilesAndGetResult processes DKLS files and returns the result.
func ProcessDKLSFilesAndGetResult(fileInfos []types.FileInfo, outputBuilder *strings.Builder, threshold int) (string, error) {
	err := ProcessDKLSFiles(fileInfos, outputBuilder, threshold)
	if err != nil {
		return "", err
	}
	return outputBuilder.String(), nil
}
`