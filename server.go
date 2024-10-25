package main

import (
  //"flag"
  "fmt"
  "io"
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

func StartServer() {
  http.HandleFunc("/", uploadForm)           // Serve the upload form
  http.HandleFunc("/upload", handleUpload)   // Handle file upload
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

func renderSuccess(w http.ResponseWriter, output string) {
    tmpl, templateErr := template.ParseFiles("templates/success.html", "templates/footer.html")
    if templateErr != nil {
        http.Error(w, "Could not load templates", http.StatusInternalServerError)
        return
    }

    data := SuccessData{Output: output}

    if err := tmpl.Execute(w, data); err != nil {
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

    renderSuccess(w, output)

    // Delete the uploaded files
    for _, file := range uploadedFiles {
        os.Remove(file)
    }
    return
}
