//go:build server
// +build server

package main

import "main/backend"

func main() {
    backend.StartServer()
}