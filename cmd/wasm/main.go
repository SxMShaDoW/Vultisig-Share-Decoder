//go:build wasm
// +build wasm

package main

import (
	"log"
	"syscall/js"
	"os"
	"io"
	"main/pkg/types"
	"main/pkg/shared"
	"fmt"
	"main/pkg/keyhandlers"
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

	js.Global().Set("getDerivedPrivateKey", js.FuncOf(getDerivedPrivateKey))
	js.Global().Set("showXKeys", js.FuncOf(showXKeys))

    log.Println("WASM initialization complete, waiting for JS calls...")
    <-c
}

// getDerivedPrivateKey derives private keys for different chains using HD derivation
func getDerivedPrivateKey(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return "Error: getDerivedPrivateKey requires privateKey and rootChainCode arguments"
	}

	privateKeyHex := args[0].String()
	rootChainCodeHex := args[1].String()

	// Validate input format
	if privateKeyHex == "" || rootChainCodeHex == "" {
		return "Error: privateKey and rootChainCode cannot be empty"
	}

	// Use the existing key handlers to derive keys
	result, err := keyhandlers.DeriveKeysFromPrivateKey(privateKeyHex, rootChainCodeHex)
	if err != nil {
		return fmt.Sprintf("Error deriving keys: %v", err)
	}

	return result
}

// showXKeys shows extended public keys and addresses
func showXKeys(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return "Error: showXKeys requires privateKey and rootChainCode arguments"
	}

	privateKeyHex := args[0].String()
	rootChainCodeHex := args[1].String()

	// Validate input format
	if privateKeyHex == "" || rootChainCodeHex == "" {
		return "Error: privateKey and rootChainCode cannot be empty"
	}

	// Use the existing key handlers to show extended keys
	result, err := keyhandlers.ShowExtendedKeys(privateKeyHex, rootChainCodeHex)
	if err != nil {
		return fmt.Sprintf("Error showing extended keys: %v", err)
	}

	return result
}