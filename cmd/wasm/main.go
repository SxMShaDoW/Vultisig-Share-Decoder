//go:build wasm

package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/vultisig/vsd/internal/format"
	"github.com/vultisig/vsd/internal/recovery"
	"github.com/vultisig/vsd/internal/vault"
)

func recoverGG20(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return errorJSON("RecoverGG20 requires 2 arguments: fileContents ([]Uint8Array), passwords ([]string)")
	}

	filesJS := args[0]
	passwordsJS := args[1]

	fileCount := filesJS.Length()
	inputs := make([]vault.FileInput, 0, fileCount)
	passwords := make([]string, 0, fileCount)

	for i := 0; i < fileCount; i++ {
		fileData := filesJS.Index(i)
		length := fileData.Length()
		buf := make([]byte, length)
		js.CopyBytesToGo(buf, fileData)
		inputs = append(inputs, vault.FileInput{
			Name:    "file" + string(rune('1'+i)),
			Content: buf,
		})
	}

	pwCount := passwordsJS.Length()
	for i := 0; i < pwCount; i++ {
		passwords = append(passwords, passwordsJS.Index(i).String())
	}

	result, err := recovery.Recover(inputs, passwords, "gg20")
	if err != nil {
		return errorJSON(err.Error())
	}

	jsonOut, err := format.JSON(result)
	if err != nil {
		return errorJSON(err.Error())
	}
	return jsonOut
}

func errorJSON(msg string) string {
	result := &recovery.RecoveryResult{
		Success: false,
		Error:   msg,
	}
	data, _ := json.Marshal(result)
	return string(data)
}

func main() {
	js.Global().Set("RecoverGG20", js.FuncOf(recoverGG20))
	select {}
}
