// backend/backend.go
package backend

import (
    "log"
    "net/http"
)

func StartServer() {
    fs := http.FileServer(http.Dir("static"))
    http.Handle("/", fs)

    log.Print("Listening on :8080...")
    err := http.ListenAndServe(":8080", nil)
    if err != nil {
        log.Fatal(err)
    }
}