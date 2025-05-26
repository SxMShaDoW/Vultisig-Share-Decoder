//go:build server
// +build server

package main

import (
    "log"
    "net/http"
    "strings"
)

func enableCORS(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
        
        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusOK)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}

func startServer() {
    // Create a custom file server that handles WASM MIME types
    fs := http.FileServer(http.Dir("static"))
    
    // Wrap with MIME type handler
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if strings.HasSuffix(r.URL.Path, ".wasm") {
            w.Header().Set("Content-Type", "application/wasm")
            log.Printf("Serving WASM file: %s", r.URL.Path)
        }
        fs.ServeHTTP(w, r)
    })
    
    http.Handle("/", enableCORS(handler))

    log.Print("Listening on :8080...")
    err := http.ListenAndServe(":8080", nil)
    if err != nil {
        log.Fatal(err)
    }
}

func main() {
    startServer()
}