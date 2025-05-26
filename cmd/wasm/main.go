
//go:build wasm
// +build wasm

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"log"
	"os"
	"io"
	"syscall/js"
	
	"google.golang.org/protobuf/proto"
	v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"main/pkg/types"
	"main/pkg/shared"
)

func main() {
    if os.Getenv("ENABLE_LOGGING") != "true" {
        log.SetOutput(io.Discard)
    }
    log.SetFlags(log.Lshortfile | log.LstdFlags)
    log.Println("Starting WASM application...")

    c := make(chan struct{}, 0)

    js.Global().Set("ProcessFiles", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
        // args[0] = file contents
        // args[1] = passwords
        // args[2] = filenames
        // args[3] = scheme (optional)
        var fileInfos []types.FileInfo
        passwords := make([]string, args[1].Length())

        // Convert file data and create FileInfo objects
        for i := 0; i < args[0].Length(); i++ {
            jsArray := args[0].Index(i)
            data := make([]byte, jsArray.Length())
            for j := 0; j < jsArray.Length(); j++ {
                data[j] = byte(jsArray.Index(j).Int())
            }

            // Get the actual filename from the third argument
            filename := args[2].Index(i).String()

            fileInfos = append(fileInfos, types.FileInfo{
                Name:    filename,
                Content: data,
            })
        }

        // Convert passwords
        for i := 0; i < args[1].Length(); i++ {
            passwords[i] = args[1].Index(i).String()
        }

        // Process the files with thresholds
        result, err := shared.ProcessFileContent(fileInfos, passwords, types.Web)
        if err != nil {
            return err.Error()
        }
        return result
    }))

    // Add vault decryption function
    js.Global().Set("DecryptVault", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
        if len(args) < 2 {
            return "Error: DecryptVault requires base64 vault data and password"
        }

        base64Data := args[0].String()
        password := args[1].String()

        // Decode base64
        vaultData, err := base64.StdEncoding.DecodeString(base64Data)
        if err != nil {
            return "Error decoding base64: " + err.Error()
        }

        // Decrypt with AES-GCM
        decryptedData, err := decryptWithAesGcm(vaultData, password)
        if err != nil {
            return "Error decrypting vault: " + err.Error()
        }

        // Parse protobuf
        vault := &v1.Vault{}
        if err := proto.Unmarshal(decryptedData, vault); err != nil {
            return "Error parsing protobuf: " + err.Error()
        }

        // Return formatted vault info
        return formatVaultInfo(vault)
    }))

    log.Println("WASM initialization complete, waiting for JS calls...")
    <-c
}

func decryptWithAesGcm(data []byte, password string) ([]byte, error) {
    key := []byte(password)
    if len(key) < 32 {
        // Pad key to 32 bytes
        padded := make([]byte, 32)
        copy(padded, key)
        key = padded
    } else if len(key) > 32 {
        key = key[:32]
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return nil, err
    }

    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }

    return plaintext, nil
}

func formatVaultInfo(vault *v1.Vault) map[string]interface{} {
	keyShares := make([]map[string]interface{}, len(vault.KeyShares))
	for i, ks := range vault.KeyShares {
		keyShares[i] = map[string]interface{}{
			"publicKey": ks.PublicKey,
			"keyshare":  ks.Keyshare[:min(100, len(ks.Keyshare))] + "...", // Truncate for display
		}
	}

	// Determine scheme type based on vault characteristics
	schemeType := "GG20" // Default
	if vault.ResharePrefix != "" {
		schemeType = "DKLS"
	}

	return map[string]interface{}{
		"name":            vault.Name,
		"publicKeyEcdsa":  vault.PublicKeyEcdsa,
		"publicKeyEddsa":  vault.PublicKeyEddsa,
		"signers":         vault.Signers,
		"keyShares":       keyShares,
		"localPartyId":    vault.LocalPartyId,
		"resharePrefix":   vault.ResharePrefix,
		"schemeType":      schemeType,
		"type":           "vault",
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
