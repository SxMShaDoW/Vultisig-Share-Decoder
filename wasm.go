//go:build wasm
// +build wasm

package main

import (
    "log"
    "syscall/js"
)

func main() {
    // Set up logging to console for WASM
    log.SetFlags(log.Lshortfile | log.LstdFlags)
    log.Println("Starting WASM application...")

    c := make(chan struct{}, 0)

    // wasm.go modifications:

    js.Global().Set("ProcessFiles", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
        // Convert JS arrays to Go slices
        fileData := make([][]byte, args[0].Length())
        passwords := make([]string, args[1].Length())

        // Convert file data
        for i := 0; i < args[0].Length(); i++ {
            jsArray := args[0].Index(i)
            data := make([]byte, jsArray.Length())
            for j := 0; j < jsArray.Length(); j++ {
                data[j] = byte(jsArray.Index(j).Int())
            }
            fileData[i] = data
        }

        // Convert passwords
        for i := 0; i < args[1].Length(); i++ {
            passwords[i] = args[1].Index(i).String()
        }

        // Process the files with thresholds
        result, err := ProcessFileContent(fileData, passwords, Web)
        if err != nil {
            return err.Error()
        }
        return result
    }))

    log.Println("WASM initialization complete, waiting for JS calls...")
    <-c
}