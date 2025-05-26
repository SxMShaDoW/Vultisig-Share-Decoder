//go:build wasm
// +build wasm

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/golang/protobuf/proto"
	v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
)

import (
    "log"
    "syscall/js"
    "os"
    "io"
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

    log.Println("WASM initialization complete, waiting for JS calls...")
    <-c
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

	// Check if keyshares are JSON (GG20) or binary (DKLS)
	if len(vault.KeyShares) > 0 {
		keyshareData := vault.KeyShares[0].Keyshare
		var js interface{}
		if json.Unmarshal([]byte(keyshareData), &js) != nil {
			// If JSON unmarshal fails, likely DKLS
			schemeType = "DKLS"
		}
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