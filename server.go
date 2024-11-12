package main

import (
  //"flag"
  "fmt"
  "io"
    "strings"
  "net/http"
    "html/template"
  "os"

  //"github.com/urfave/cli/v2"
)

type ErrorData struct {
    Message string
}

type SuccessData struct {
    Output string
}

// Add struct for JSON response
type AirdropResponse struct {
    Balance int `json:"balance"`
}

type DecodedOutput struct {
        PublicKeyECDSA  string
        PublicKeyEDDSA  string
        PrivateKeys     map[string]string  // e.g. "ethereum" -> "key"
        WIFPrivateKeys  map[string]string  // e.g. "bitcoin WIF" -> "key"
        ShareName       string
        Addresses       map[string]string  // e.g. "bitcoin" -> "address"
        ShareDetails    string
        RawOutput       string             // For any other unstructured data
}

func StartServer() {
  http.HandleFunc("/", uploadForm)           // Serve the upload form
  http.HandleFunc("/upload", handleUpload)   // Handle file upload
http.HandleFunc("/api/balance/", handleBalanceCheck)
  fmt.Println("Starting server on :8080...")
  if err := http.ListenAndServe(":8080", nil); err != nil {
    fmt.Println("Server failed:", err)
  }
}

func uploadForm(w http.ResponseWriter, r *http.Request) {
    // Parse both the main template and the footer template
    tmpl, err := template.ParseFiles("templates/upload_form.html", "templates/footer.html")
    if err != nil {
        http.Error(w, "Could not load templates", http.StatusInternalServerError)
        return
    }

    // Execute the main template
    if err := tmpl.Execute(w, nil); err != nil {
        http.Error(w, "Failed to render template", http.StatusInternalServerError)
        return
    }
}

func handleBalanceCheck(w http.ResponseWriter, r *http.Request) {
    // Extract keys from URL path
    parts := strings.Split(r.URL.Path, "/")
    if len(parts) < 5 {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    ecdsaKey := parts[3]
    eddsaKey := parts[4]

    // Fetch balance from airdrop API
    url := fmt.Sprintf("https://airdrop.vultisig.com/api/vault/%s/%s", ecdsaKey, eddsaKey)

    resp, err := http.Get(url)
    if err != nil {
        http.Error(w, "Failed to fetch balance", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    // Read and forward the response
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        http.Error(w, "Failed to read response", http.StatusInternalServerError)
        return
    }

    // Set JSON content type
    w.Header().Set("Content-Type", "application/json")
    w.Write(body)
}

func renderErrorPage(w http.ResponseWriter, err error) {
    // Prepare the data to pass to the template
    data := ErrorData{
        Message: "Decoded action failed: \n" + err.Error(),
    }
    
    tmpl, templateErr := template.ParseFiles("templates/error_server.html", "templates/footer.html")
    if templateErr != nil {
        http.Error(w, "Could not load templates", http.StatusInternalServerError)
        return
    }
    // Execute the template with the data
    if execErr := tmpl.Execute(w, data); execErr != nil {
        http.Error(w, "Failed to render template", http.StatusInternalServerError)
        return
    }
}

func renderSuccess(w http.ResponseWriter, output DecodedOutput) {
    tmpl, templateErr := template.ParseFiles("templates/success.html", "templates/footer.html")
    if templateErr != nil {
        fmt.Printf("Error loading templates: %v", templateErr)
        http.Error(w, "Could not load templates", http.StatusInternalServerError)
        return
    }

    if err := tmpl.Execute(w, output); err != nil {
        http.Error(w, "Failed to render template", http.StatusInternalServerError)
    }
}




func handleUpload(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html")

    if r.Method != "POST" {
        // Parse both the main template and the footer template
        tmpl, err := template.ParseFiles("templates/error_noupload.html", "templates/footer.html")
        if err != nil {
            http.Error(w, "Could not load templates", http.StatusInternalServerError)
            return
        }
        // Execute the template with the data
        if execErr := tmpl.Execute(w, nil); execErr != nil {
            http.Error(w, "Failed to render template", http.StatusInternalServerError)
        }
        return
    }

    err := r.ParseMultipartForm(10 << 20) // 10 MB limit
    if err != nil {
        http.Error(w, "Could not parse form", http.StatusBadRequest)
        return
    }

    var uploadedFiles []string
    var passwords []string

    files := r.MultipartForm.File["file"]
    passwords = r.MultipartForm.Value["password"]

    // Loop through each file upload
    for i, fileHeader := range files {
        file, err := fileHeader.Open()
        if err != nil {
            http.Error(w, "Could not open uploaded file", http.StatusBadRequest)
            return
        }
        defer file.Close()

        // Save the file locally
        dst, err := os.Create(fileHeader.Filename)
        if err != nil {
            http.Error(w, "Could not create file", http.StatusInternalServerError)
            return
        }
        defer dst.Close()

        _, err = io.Copy(dst, file)
        if err != nil {
            http.Error(w, "Could not save file", http.StatusInternalServerError)
            return
        }

        // Collect file names and passwords
        uploadedFiles = append(uploadedFiles, fileHeader.Filename)
        if i < len(passwords) {
            passwords = append(passwords, passwords[i])
        } else {
            passwords = append(passwords, "")
        }
    }

    // Process the files and passwords (to be implemented in the backend)
    output, err := ProcessFiles(uploadedFiles, passwords, Web)
    if err != nil {
        renderErrorPage(w, err)
        // Delete the uploaded file after processing
        for _, fileHeader := range files {
             errRemove := os.Remove(fileHeader.Filename)
             if errRemove != nil {
                 fmt.Fprintf(w, "<p>Warning: Failed to delete the uploaded file: %s</p>", err.Error())
             }
        }
        return
    }
    

    decoded := parseOutput(output)
    renderSuccess(w, decoded)

    // Delete the uploaded files
    for _, file := range uploadedFiles {
        os.Remove(file)
    }
    return
}

func parseOutput(rawOutput string) DecodedOutput {
    decoded := DecodedOutput{
        PrivateKeys: make(map[string]string),
        Addresses:   make(map[string]string),
        WIFPrivateKeys: make(map[string]string),
    }

    // Split the output into lines
    lines := strings.Split(rawOutput, "\n")
    var currentChain string

    for _, line := range lines {
        line = strings.TrimSpace(line)

        // Parse backup details
        if strings.HasPrefix(line, "Backup name:") {
            decoded.ShareDetails += line + "\n"
        } else if strings.HasPrefix(line, "This Share:") {
            decoded.ShareDetails += line + "\n"
        } else if strings.HasPrefix(line, "All Shares:") {
            decoded.ShareDetails += line + "\n"
        }

        // Parse Public Keys
        if strings.HasPrefix(line, "Public Key(ECDSA):") {
            decoded.PublicKeyECDSA = strings.TrimSpace(strings.Split(line, ":")[1])
        } else if strings.HasPrefix(line, "Public Key(EdDSA):") {
            decoded.PublicKeyEDDSA = strings.TrimSpace(strings.Split(line, ":")[1])
        }

        // Track current chain context
        if strings.HasPrefix(line, "Recovering") && strings.HasSuffix(line, "key....") {
            currentChain = strings.TrimSuffix(strings.TrimPrefix(line, "Recovering "), " key....")
        }

        if strings.HasPrefix(line, "WIF private key for") {
            parts := strings.LastIndex(line, ":")
            if parts != -1 {
                chainFull := line[len("WIF private key for "):parts]
                chainFull = strings.TrimSpace(chainFull)
                chainFull = strings.ToLower(chainFull)
                privateKey := strings.TrimSpace(line[parts+1:])
                decoded.WIFPrivateKeys[chainFull] = privateKey
            }
            continue
        }

        // Parse private keys
        if strings.HasPrefix(line, "hex encoded private key for") || 
           strings.HasPrefix(line, "hex encoded non-hardened private key for") {
            parts := strings.Split(line, ":")
            if len(parts) == 2 {
                var chain string
                if strings.HasPrefix(line, "hex encoded private key for") {
                    chain = strings.TrimPrefix(parts[0], "hex encoded private key for ")
                } else if strings.HasPrefix(line, "hex encoded non-hardened private key for") {
                    chain = strings.TrimPrefix(parts[0], "hex encoded non-hardened private key for ")
                }
                chain = strings.TrimSpace(chain)
                chain = strings.ToLower(chain)
                decoded.PrivateKeys[chain] = strings.TrimSpace(parts[1])
            }
        }

        // Parse addresses
        if strings.HasPrefix(line, "address:") {
            if currentChain != "" {
                decoded.Addresses[currentChain] = strings.TrimSpace(strings.Split(line, ":")[1])
            }
        }

        // Store ethereum address specifically (since it's formatted differently)
        if strings.HasPrefix(line, "ethereum address:") {
            decoded.Addresses["ethereum"] = strings.TrimSpace(strings.Split(line, ":")[1])
        }
    }

    // Store raw output for reference
    decoded.RawOutput = rawOutput

    return decoded
}