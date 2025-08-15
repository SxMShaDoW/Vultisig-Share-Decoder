//go:build cli
// +build cli
package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/golang/protobuf/proto"
	"github.com/urfave/cli/v2"
	v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"main/pkg/types"
	"main/pkg/fileutils"
	"main/pkg/encryption"
	"main/pkg/keyhandlers"
	"main/pkg/keyprocessing"
	"main/pkg/shared"
)

func ProcessFiles(files []string, passwords []string, source types.InputSource) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("no files provided")
	}

	// Convert files to FileInfo format for scheme detection
	var fileInfos []types.FileInfo
	for _, f := range files {
		content, err := fileutils.ReadFileContent(f)
		if err != nil {
			return "", fmt.Errorf("error reading file %s: %w", f, err)
		}
		fileInfos = append(fileInfos, types.FileInfo{
			Name:    f,
			Content: content,
		})
	}

	// Use shared processing function which handles scheme detection
	return shared.ProcessFileContent(fileInfos, passwords, source)
}

func ProcessFilesContent(files []string, passwords []string, source types.InputSource) (string, error) {
	var outputBuilder strings.Builder
	var allSecret []types.TempLocalState

	if len(files) == 0 {
		return "", fmt.Errorf("no files provided")
	}

	for i, f := range files {
		var password string
		if i < len(passwords) {
			password = passwords[i] // Use the corresponding password if available
		} else {
			password = "" // Default to an empty string if passwords are missing
		}

		if fileutils.IsBakFile(f) {
			result, err := fileutils.GetLocalStateFromBak(f, password, source)
			if err != nil {
				return "", fmt.Errorf("error reading file %s: %w", f, err)
			}
			outputBuilder.WriteString(fmt.Sprintf("Backup name: %v\n", f))
			outputBuilder.WriteString(fmt.Sprintf("This Share: %s\n", result[types.EdDSA].LocalPartyKey))
			outputBuilder.WriteString(fmt.Sprintf("All Shares: %v\n", result[types.EdDSA].KeygenCommitteeKeys))
			allSecret = append(allSecret, types.TempLocalState{
				FileName:   f,
				LocalState: result,
			})
		} else if strings.HasSuffix(f, "dat") {
			result, err := fileutils.GetLocalStateFromFile(f)
			if err != nil {
				return "", fmt.Errorf("error reading file %s: %w", f, err)
			}
			outputBuilder.WriteString(fmt.Sprintf("This Share: %s\n", result[types.EdDSA].LocalPartyKey))
			outputBuilder.WriteString(fmt.Sprintf("All Shares: %v\n", result[types.EdDSA].KeygenCommitteeKeys))
			allSecret = append(allSecret, types.TempLocalState{
				FileName:   f,
				LocalState: result,
			})
		}
	}

	threshold := len(files)
	keyTypes := []types.TssKeyType{types.ECDSA, types.EdDSA}
	for _, keyType := range keyTypes {
		if err := keyprocessing.GetKeys(threshold, allSecret, keyType, &outputBuilder); err != nil {
			return "", err
		}
	}

	return outputBuilder.String(), nil
}

func RecoverAction(cCtx *cli.Context) error {
	files := cCtx.StringSlice("files")
	scheme := cCtx.String("scheme")
	// Create a slice of empty strings for passwords
	passwords := make([]string, len(files))
	source := types.CommandLine

	fmt.Printf("Processing %d files: %v\n", len(files), files)

	// Convert files to FileInfo format for scheme detection
	var fileInfos []types.FileInfo
	for _, f := range files {
		content, err := fileutils.ReadFileContent(f)
		if err != nil {
			return fmt.Errorf("error reading file %s: %w", f, err)
		}
		fmt.Printf("Read file %s, content length: %d bytes\n", f, len(content))
		fileInfos = append(fileInfos, types.FileInfo{
			Name:    f,
			Content: content,
		})
	}

	var output string
	var err error

	// Handle scheme selection
	switch scheme {
	case "dkls":
		fmt.Println("Using DKLS scheme")
		return fmt.Errorf("DKLS is unsupported on the CLI for now. Please use the web interface.")
	case "gg20":
		fmt.Println("Using GG20 scheme")
		output, err = ProcessGG20Files(fileInfos, passwords, source)
	case "auto":
		fmt.Println("Auto-detecting scheme")
		output, err = shared.ProcessFileContent(fileInfos, passwords, source)
	default:
		return fmt.Errorf("unsupported scheme: %s (supported: auto, gg20, dkls)", scheme)
	}

	if err != nil {
		return fmt.Errorf("error processing files: %w", err)
	}

	// If running in CLI mode, print to console
	fmt.Println(output)
	return nil
}

func DecryptFileAction(ctx *cli.Context) error {
	for _, item := range ctx.Args().Slice() {
		filePathName, err := filepath.Abs(item)
		if err != nil {
			fmt.Printf("error getting absolute path for file %s: %s\n", item, err)
			continue
		}
		_, err = os.Stat(filePathName)
		if err != nil {
			fmt.Printf("error reading file %s: %s\n", item, err)
			continue
		}

		fileContent, err := fileutils.ReadFileContent(filePathName)
		if err != nil {
			fmt.Printf("error reading file %s: %s\n", item, err)
			continue
		}

		if fileutils.IsBakFile(filePathName) {
			rawContent, err := base64.StdEncoding.DecodeString(string(fileContent))
			if err != nil {
				fmt.Printf("error decoding file %s: %s\n", item, err)
				continue
			}
			var vaultContainer v1.VaultContainer
			if err := proto.Unmarshal(rawContent, &vaultContainer); err != nil {
				fmt.Printf("error unmarshalling file %s: %s\n", item, err)
				continue
			}
			// file is encrypted
			if vaultContainer.IsEncrypted {
				password := ""
				source := types.CommandLine
				decryptedVault, err := encryption.DecryptVault(&vaultContainer, filePathName, password, source)
				if err != nil {
					fmt.Printf("error decrypting file %s: %s\n", item, err)
					continue
				}
				fmt.Printf("%+v", decryptedVault)
			} else {
				fmt.Println("File is not encrypted")
			}
		}
	}
	return nil
}

// deriveAndShowAllKeys derives keys for all supported cryptocurrencies from master key material
// This mirrors the WASM DeriveAndShowKeys function exactly
func deriveAndShowAllKeys(privateKeyHex, chaincodeHex string, outputBuilder *strings.Builder) error {
	// Decode hex strings
	rootPrivateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return fmt.Errorf("error decoding private key hex: %v", err)
	}

	rootChainCodeBytes, err := hex.DecodeString(chaincodeHex)
	if err != nil {
		return fmt.Errorf("error decoding chain code hex: %v", err)
	}

	// Get all supported coins (same as WASM)
	supportedCoins := keyhandlers.GetSupportedCoins()

	// Display the header like WASM does
	fmt.Fprintf(outputBuilder, "\n=== Deriving Keys for All Supported Cryptocurrencies ===\n")

	// Process the root key for all coins using the same function as WASM
	err = keyhandlers.ProcessRootKeyForCoins(rootPrivateKeyBytes, rootChainCodeBytes, supportedCoins, outputBuilder)
	if err != nil {
		return fmt.Errorf("error processing keys: %v", err)
	}

	return nil
}

func ProcessGG20Files(fileInfos []types.FileInfo, passwords []string, source types.InputSource) (string, error) {
	var outputBuilder strings.Builder
	var allSecret []types.TempLocalState

	for _, fileInfo := range fileInfos {
		// Note: passwords not currently used for GG20 parsing in shared.ParseLocalState
		// Process as GG20 format
		localStates, err := shared.ParseLocalState(fileInfo.Content)
		if err != nil {
			return "", fmt.Errorf("error processing file %s: %w", fileInfo.Name, err)
		}

		// Add share details to output
		fmt.Fprintf(&outputBuilder, "Backup name: %s\n", fileInfo.Name)
		if eddsaState, ok := localStates[types.EdDSA]; ok {
			fmt.Fprintf(&outputBuilder, "This Share: %s\n", eddsaState.LocalPartyKey)
			fmt.Fprintf(&outputBuilder, "All Shares: %v\n", eddsaState.KeygenCommitteeKeys)
		}

		allSecret = append(allSecret, types.TempLocalState{
			FileName:   fileInfo.Name,
			LocalState: localStates,
			SchemeType: types.GG20,
		})
	}

	if len(allSecret) == 0 {
		return "", fmt.Errorf("no valid GG20 secrets found")
	}

	threshold := len(allSecret)
	fmt.Fprintf(&outputBuilder, "\n=== Processing %d GG20 secrets with threshold %d ===\n", len(allSecret), threshold)

	// Process ECDSA keys
	if err := keyprocessing.GetKeys(threshold, allSecret, types.ECDSA, &outputBuilder); err != nil {
		return "", fmt.Errorf("error processing ECDSA keys: %w", err)
	}

	// Process EdDSA keys  
	if err := keyprocessing.GetKeys(threshold, allSecret, types.EdDSA, &outputBuilder); err != nil {
		return "", fmt.Errorf("error processing EdDSA keys: %w", err)
	}

	return outputBuilder.String(), nil
}

func TestAddressAction(c *cli.Context) error {
	privateKeyHex := c.String("private-key")
	chaincodeHex := c.String("chaincode")

	if chaincodeHex == "" {
		return fmt.Errorf("chaincode is required")
	}

	fmt.Printf("Testing HD derivation for root private key: %s\n", privateKeyHex)
	fmt.Printf("Using provided chaincode: %s\n\n", chaincodeHex)

	// Decode the hex private key
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return fmt.Errorf("invalid hex private key: %w", err)
	}

	if len(privateKeyBytes) != 32 {
		return fmt.Errorf("private key must be 32 bytes, got %d bytes", len(privateKeyBytes))
	}

	// Create secp256k1 private key
	privateKey := secp256k1.PrivKeyFromBytes(privateKeyBytes)

	// Decode the chaincode
	var chaincode [32]byte
	chaincodeBytes, err := hex.DecodeString(chaincodeHex)
	if err != nil {
		return fmt.Errorf("invalid hex chaincode: %w", err)
	}
	if len(chaincodeBytes) != 32 {
		return fmt.Errorf("chaincode must be 32 bytes, got %d bytes", len(chaincodeBytes))
	}
	copy(chaincode[:], chaincodeBytes)

	// Create extended private key (master key)
	net := &chaincfg.MainNetParams
	extendedPrivateKey := hdkeychain.NewExtendedKey(
		net.HDPrivateKeyID[:], 
		privateKey.Serialize(), 
		chaincode[:], 
		[]byte{0x00, 0x00, 0x00, 0x00}, 
		0, 
		0, 
		true,
	)

	fmt.Printf("✅ Created HD master key from private key\n")
	fmt.Printf("Extended master key: %s\n\n", extendedPrivateKey.String())

	// Define supported coins with their derivation paths
	supportedCoins := []struct {
		name       string
		derivePath string
		action     func(*hdkeychain.ExtendedKey, *strings.Builder) error
	}{
		{
			name:       "Bitcoin",
			derivePath: "m/84'/0'/0'/0/0",
			action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
				return keyhandlers.ShowBitcoinKey(key, output)
			},
		},
		{
			name:       "Bitcoin Cash",
			derivePath: "m/44'/145'/0'/0/0",
			action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
				return keyhandlers.ShowBitcoinCashKey(key, output)
			},
		},
		{
			name:       "Dogecoin",
			derivePath: "m/44'/3'/0'/0/0",
			action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
				return keyhandlers.ShowDogecoinKey(key, output)
			},
		},
		{
			name:       "Litecoin",
			derivePath: "m/84'/2'/0'/0/0",
			action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
				return keyhandlers.ShowLitecoinKey(key, output)
			},
		},
		{
			name:       "Ethereum",
			derivePath: "m/44'/60'/0'/0/0",
			action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
				return keyhandlers.ShowEthereumKey(key, output)
			},
		},
		{
			name:       "THORChain",
			derivePath: "m/44'/931'/0'/0/0",
			action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
				return keyhandlers.CosmosLikeKeyHandler(key, "thor", "thorv", "thorc", output, "THORChain")
			},
		},
		{
			name:       "MayaChain",
			derivePath: "m/44'/931'/0'/0/0",
			action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
				return keyhandlers.CosmosLikeKeyHandler(key, "maya", "mayav", "mayac", output, "MayaChain")
			},
		},
		{
			name:       "Cosmos",
			derivePath: "m/44'/118'/0'/0/0",
			action: func(key *hdkeychain.ExtendedKey, output *strings.Builder) error {
				return keyhandlers.CosmosLikeKeyHandler(key, "cosmos", "cosmosvaloper", "cosmosvalcons", output, "Cosmos")
			},
		},
	}

	// Derive keys for each supported cryptocurrency
	for _, coin := range supportedCoins {
		fmt.Printf("=== %s (%s) ===\n", coin.name, coin.derivePath)

		// Get derived private key
		derivedKey, err := keyhandlers.GetDerivedPrivateKeys(coin.derivePath, extendedPrivateKey)
		if err != nil {
			fmt.Printf("❌ Error deriving %s key: %v\n\n", coin.name, err)
			continue
		}

		// Create output builder for this coin
		var outputBuilder strings.Builder

		// Call the specific coin handler
		if err := coin.action(derivedKey, &outputBuilder); err != nil {
			fmt.Printf("❌ Error generating %s addresses: %v\n\n", coin.name, err)
			continue
		}

		// Print the results
		fmt.Print(outputBuilder.String())
		fmt.Println()
	}

	return nil
}

// extractDKLSMasterKey extracts master private key and chain code from DKLS vault files
// This function mimics the WASM extraction process for consistency
func extractDKLSMasterKey(fileInfos []types.FileInfo, passwords []string) (privateKeyHex, chaincodeHex string, err error) {
	// Process each vault file following the same pattern as main.js parseAndDecryptVault
	var allKeyshareData [][]byte
	
	for i, fileInfo := range fileInfos {
		password := ""
		if i < len(passwords) {
			password = passwords[i]
		}

		// Extract keyshare data following the WASM pattern
		keyshareData, _, err := parseDKLSVaultFile(fileInfo.Content, password, fileInfo.Name)
		if err != nil {
			return "", "", fmt.Errorf("failed to parse vault file %s: %v", fileInfo.Name, err)
		}

		allKeyshareData = append(allKeyshareData, keyshareData)
	}

	if len(allKeyshareData) == 0 {
		return "", "", fmt.Errorf("no valid keyshare data extracted")
	}

	// Try to use the same WASM processing to get the master key
	// This will call the WASM library if available
	result, err := shared.ProcessFileContent(fileInfos, passwords, types.CommandLine)
	if err != nil {
		return "", "", fmt.Errorf("failed to process DKLS files: %v", err)
	}

	// Parse the result to extract master private key and chaincode
	// The WASM result contains the hex values we need
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		if strings.Contains(line, "hex encoded root privkey(ECDSA):") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				privateKeyHex = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(line, "chaincode:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				chaincodeHex = strings.TrimSpace(parts[1])
			}
		}
	}

	if privateKeyHex == "" || chaincodeHex == "" {
		return "", "", fmt.Errorf("could not extract master key and chaincode from DKLS processing result")
	}

	return privateKeyHex, chaincodeHex, nil
}

// parseDKLSVaultFile parses a DKLS vault file and extracts the keyshare data
func parseDKLSVaultFile(fileContent []byte, password, filename string) ([]byte, string, error) {
	// Try to decode as base64 first
	var vaultContainerData []byte
	base64String := string(fileContent)
	decoded, err := base64.StdEncoding.DecodeString(base64String)
	if err == nil && len(decoded) > 100 {
		vaultContainerData = decoded
	} else {
		vaultContainerData = fileContent
	}

	// Parse as VaultContainer
	var vaultContainer v1.VaultContainer
	if err := proto.Unmarshal(vaultContainerData, &vaultContainer); err != nil {
		return nil, "", fmt.Errorf("failed to parse VaultContainer: %w", err)
	}

	// Handle encrypted/unencrypted vault
	var vaultData []byte
	if vaultContainer.IsEncrypted {
		decryptedVault, err := encryption.DecryptVault(&vaultContainer, filename, password, types.CommandLine)
		if err != nil {
			return nil, "", fmt.Errorf("failed to decrypt vault: %w", err)
		}
		vaultData, err = proto.Marshal(decryptedVault)
		if err != nil {
			return nil, "", fmt.Errorf("failed to marshal decrypted vault: %w", err)
		}
	} else {
		vaultData, err = base64.StdEncoding.DecodeString(vaultContainer.Vault)
		if err != nil {
			return nil, "", fmt.Errorf("failed to decode unencrypted vault: %w", err)
		}
	}

	// Parse the vault
	var vault v1.Vault
	if err := proto.Unmarshal(vaultData, &vault); err != nil {
		return nil, "", fmt.Errorf("failed to parse vault: %w", err)
	}

	if len(vault.KeyShares) == 0 {
		return nil, "", fmt.Errorf("no keyshares found in vault")
	}

	// Extract keyshare data
	keyshareString := vault.KeyShares[0].Keyshare
	if keyshareString == "" {
		return nil, "", fmt.Errorf("empty keyshare data")
	}

	// Try to decode the keyshare string
	var keyshareData []byte
	if strings.HasPrefix(keyshareString, "0x") || len(keyshareString)%2 == 0 {
		// Try hex decoding
		keyshareData, err = hex.DecodeString(strings.TrimPrefix(keyshareString, "0x"))
		if err != nil {
			// Try base64 decoding
			keyshareData, err = base64.StdEncoding.DecodeString(keyshareString)
			if err != nil {
				// Use raw bytes
				keyshareData = []byte(keyshareString)
			}
		}
	} else {
		// Try base64 first
		keyshareData, err = base64.StdEncoding.DecodeString(keyshareString)
		if err != nil {
			// Use raw bytes
			keyshareData = []byte(keyshareString)
		}
	}

	partyID := vault.LocalPartyId
	if partyID == "" {
		partyID = fmt.Sprintf("party_%s", filename)
	}

	return keyshareData, partyID, nil
}