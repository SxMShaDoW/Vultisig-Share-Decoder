//go:build cli
// +build cli
package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"io"
	"log"
	"path/filepath"
	"strings"
	"github.com/golang/protobuf/proto"
	"github.com/urfave/cli/v2"
	v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"github.com/vultisig/mobile-tss-lib/tss"
	"encoding/json"
)

func ProcessFileContent(files []FileInfo, passwords []string, source InputSource) (string, error) {
		var allSecrets []tempLocalState
		var outputBuilder strings.Builder

	if os.Getenv("ENABLE_LOGGING") != "true" {
			log.SetOutput(io.Discard)
	}

		// Process each file
		for i, file := range files {
			contentStr := strings.TrimSpace(string(file.Content))

				log.Printf("Processing file %d, content starts with: %s", i, contentStr[:min(len(contentStr), 50)])

				password := ""
				if i < len(passwords) {
						password = passwords[i]
				}

				var localStates map[TssKeyType]tss.LocalState
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
						localStates, err = getLocalStateFromContent(decodedData)
						if err != nil {
								return "", fmt.Errorf("error processing file %d: %w", i, err)
						}
				} else {
						log.Printf("Successfully unmarshalled as protobuf VaultContainer")
						localStates, err = getLocalStateFromBakContent([]byte(contentStr), password, source)
						if err != nil {
								return "", fmt.Errorf("error processing vault container file %d: %w", i, err)
						}
				}

				// Add share details to output
				outputBuilder.WriteString(fmt.Sprintf("Backup name: %s\n", file.Name))
				if eddsaState, ok := localStates[EdDSA]; ok {
						outputBuilder.WriteString(fmt.Sprintf("This Share: %s\n", eddsaState.LocalPartyKey))
						outputBuilder.WriteString(fmt.Sprintf("All Shares: %v\n", eddsaState.KeygenCommitteeKeys))
				}

				allSecrets = append(allSecrets, tempLocalState{
						FileName:   fmt.Sprintf("file_%d", i),
						LocalState: localStates,
				})
		}

		threshold := len(allSecrets)
		log.Printf("Using threshold %d for %d secrets", threshold, len(allSecrets))

		if err := getKeys(threshold, allSecrets, ECDSA, &outputBuilder); err != nil {
				return "", fmt.Errorf("error processing ECDSA keys: %w", err)
		}
		if err := getKeys(threshold, allSecrets, EdDSA, &outputBuilder); err != nil {
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

// Add this helper function to parse vault
func parseVault(vault *v1.Vault) (map[TssKeyType]tss.LocalState, error) {
	localStates := make(map[TssKeyType]tss.LocalState)
	for _, keyshare := range vault.KeyShares {
			var localState tss.LocalState
			if err := json.Unmarshal([]byte(keyshare.Keyshare), &localState); err != nil {
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



func parseLocalState(content []byte) (map[TssKeyType]tss.LocalState, error) {
		var vault v1.Vault
		if err := proto.Unmarshal(content, &vault); err != nil {
				return nil, fmt.Errorf("failed to unmarshal vault: %w", err)
		}

		localStates := make(map[TssKeyType]tss.LocalState)
		for _, keyshare := range vault.KeyShares {
				var localState tss.LocalState
				if err := json.Unmarshal([]byte(keyshare.Keyshare), &localState); err != nil {
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



func ProcessFiles(files []string, passwords []string, source InputSource) (string, error) {
	var outputBuilder strings.Builder

	if len(files) == 0 {
		return "", fmt.Errorf("no files provided")
	}

	allSecret := make([]tempLocalState, 0, len(files))

	for i, f := range files {
		var password string
		if i < len(passwords) {
			password = passwords[i] // Use the corresponding password if available
		} else {
			password = "" // Default to an empty string if passwords are missing
		}

		if isBakFile(f) {
			result, err := getLocalStateFromBak(f, password, source)
			if err != nil {
				return "", fmt.Errorf("error reading file %s: %w", f, err)
			}
			outputBuilder.WriteString(fmt.Sprintf("Backup name: %v\n", f))
			outputBuilder.WriteString(fmt.Sprintf("This Share: %s\n", result[EdDSA].LocalPartyKey))
			outputBuilder.WriteString(fmt.Sprintf("All Shares: %v\n", result[EdDSA].KeygenCommitteeKeys))
			allSecret = append(allSecret, tempLocalState{
				FileName:   f,
				LocalState: result,
			})
		} else if strings.HasSuffix(f, "dat") {
			result, err := getLocalStateFromFile(f)
			if err != nil {
				return "", fmt.Errorf("error reading file %s: %w", f, err)
			}
			outputBuilder.WriteString(fmt.Sprintf("This Share: %s\n", result[EdDSA].LocalPartyKey))
			outputBuilder.WriteString(fmt.Sprintf("All Shares: %v\n", result[EdDSA].KeygenCommitteeKeys))
			allSecret = append(allSecret, tempLocalState{
				FileName:   f,
				LocalState: result,
			})
		}
	}

	threshold := len(files)
	keyTypes := []TssKeyType{ECDSA, EdDSA}
	for _, keyType := range keyTypes {
		if err := getKeys(threshold, allSecret, keyType, &outputBuilder); err != nil {
			return "", err
		}
	}

	return outputBuilder.String(), nil
}

func RecoverAction(cCtx *cli.Context) error {
	files := cCtx.StringSlice("files")
	//password := cCtx.StringSlice("password")
	// Create a slice of empty strings for passwords
	passwords := make([]string, len(files))
	source := CommandLine

	output, err := ProcessFiles(files, passwords, source)
	if err != nil {
		return err
	}

	// If running in CLI mode, print to console
	fmt.Println(output)
	return nil
}

func decryptFileAction(ctx *cli.Context) error {
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

		fileContent, err := readFileContent(filePathName)
		if err != nil {
			fmt.Printf("error reading file %s: %s\n", item, err)
			continue
		}

		if isBakFile(filePathName) {
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
				source := CommandLine
				decryptedVault, err := decryptVault(&vaultContainer, filePathName, password, source)
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