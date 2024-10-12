package main

import (
  "flag"
  "fmt"
  "io"
  "net/http"
  "os"

  "github.com/urfave/cli/v2"
)

func StartServer() {
  http.HandleFunc("/", uploadForm)           // Serve the upload form
  http.HandleFunc("/upload", handleUpload)   // Handle file upload
  fmt.Println("Starting server on :8080...")
  if err := http.ListenAndServe(":8080", nil); err != nil {
    fmt.Println("Server failed:", err)
  }
}

func uploadForm(w http.ResponseWriter, r *http.Request) {
    html := `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Upload File</title>
      <style>
        body {
            background-color: #1a1a2e; /* Dark background */
            color: #e94560; /* Neon pink text */
            font-family: 'Arial', sans-serif;
            text-align: center;
            padding: 20px;
        }
        h2 {
            color: #00ffcc; /* Neon green */
        }
        p {
            color: #a9a9e9; /* Light gray */
        }
        .form-group {
            display: flex; /* Use flexbox for layout */
            justify-content: space-between; /* Space between label and input */
            align-items: center; /* Center align items vertically */
            width: 300px; /* Set a uniform width */
            margin: 0 auto; /* Center align the form groups */
            text-align: left; /* Align text to the left */
        }
        label {
            margin-right: 10px; /* Add space between label and input */
            flex: 1; /* Allow label to grow */
        }
        input[type="file"], input[type="password"], input[type="submit"], button {
            flex: 2; /* Allow inputs to grow, making them wider */
            padding: 10px;
            margin: 10px 0;
            border: none;
            border-radius: 5px;
            background-color: #0f3460; /* Dark blue */
            color: #ffffff; /* White text */
            font-size: 16px;
            cursor: pointer;
        }
        input[type="submit"], button {
            transition: background-color 0.3s;
        }
        pre {
            background-color: #0f3460; /* Dark blue for preformatted text */
            color: #ffffff; /* White text for preformatted */
            padding: 10px;
            border-radius: 5px;
            overflow-wrap: break-word; /* Ensure long words wrap */
            max-width: 100%; /* Responsive max width */
            white-space: pre-wrap; /* Preserve whitespace */
            word-wrap: break-word; /* Break long words */
        }
        /* Tooltip styles */
        .tooltip {
            position: relative;
            display: inline-block;
            cursor: pointer;
            color: #ffcc00; /* Tooltip color */
        }
        .tooltip .tooltiptext {
            visibility: hidden;
            width: 300px;
            background-color: #ff4444; /* Red background */
            color: #ffffff; /* White text */
            text-align: center;
            border-radius: 5px;
            padding: 5px 10px;
            position: absolute;
            z-index: 1;
            bottom: 125%; /* Position above the text */
            left: 50%;
            margin-left: -150px; /* Center the tooltip */
            opacity: 0;
            transition: opacity 0.3s;
        }
        .tooltip:hover .tooltiptext {
            visibility: visible;
            opacity: 1;
        }
      </style>
      <script>
        function togglePassword() {
          var passwordField = document.getElementById("password");
          var toggleButton = document.getElementById("toggleButton");
          if (passwordField.type === "password") {
            passwordField.type = "text";
            toggleButton.textContent = "Hide";
          } else {
            passwordField.type = "password";
            toggleButton.textContent = "Show";
          }
        }
      </script>
    </head>
    <body>
      <h2>Decode a Vultisig Share</h2>
      <p>Why is this tool useful? It can provide you information about your backup without having to import it into the app. It can, in the future, also extract your private key information in case you need to migrate to a traditional seed based app.</p>
      <form enctype="multipart/form-data" action="/upload" method="post">
        <div class="form-group">
          <label for="file">Select a file:</label>
          <input type="file" name="file" required />
        </div>
        <div class="form-group">
          <label for="password">Decryption Password:</label>
          <div class="tooltip">
            ?
            <span class="tooltiptext">Use this only if necessary; try without providing it first.</span>
          </div>
          <input type="password" name="password" id="password" />
          <button type="button" id="toggleButton" onclick="togglePassword()">Show</button>
        </div>
        <div class="form-group">
          <input type="submit" value="Upload" />
        </div>
      </form>
      <p> In the future, we can also extract the private keys (it is commented out in the code for now) </p>
      <p> The file you uploaded is deleted right away and we never store the password anywhere. You can check the github and the replit </p>
    </body>
    </html>
    `
    fmt.Fprint(w, html)
}




func handleUpload(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html")

    if r.Method != "POST" {
        fmt.Fprintf(w, `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Error</title>
            <style>
                body {
                    background-color: #1a1a2e; /* Dark background */
                    color: #e94560; /* Neon pink text */
                    font-family: 'Arial', sans-serif;
                    text-align: center;
                    padding: 20px;
                }
                h2 {
                    color: #ff4444; /* Bright red for error */
                }
                p {
                    color: #a9a9e9; /* Light gray */
                }
                input[type="submit"] {
                    background-color: #00ffcc; /* Neon green for buttons */
                }
            </style>
        </head>
        <body>
            <h2>Error:</h2>
            <p>Looks like you got here by mistake without uploading a file.</p>
            <form action="/" method="get">
                <input type="submit" value="Check another share" />
            </form>
        </body>
        </html>
        `)
        return
    }

    // Parse the multipart form with a maximum memory of 10MB
    err := r.ParseMultipartForm(10 << 20) // 10 MB
    if err != nil {
        http.Error(w, "Could not parse form", http.StatusBadRequest)
        return
    }

    // Retrieve the uploaded file
    file, handler, err := r.FormFile("file")
    if err != nil {
        http.Error(w, "Could not retrieve file", http.StatusBadRequest)
        return
    }
    defer file.Close()

    // Retrieve the password from the form
    password := r.FormValue("password")

    // Create a new file in the local filesystem
    dst, err := os.Create(handler.Filename)
    if err != nil {
        http.Error(w, "Could not create file", http.StatusInternalServerError)
        return
    }
    defer dst.Close()

    // Copy the uploaded file data to the new file
    _, err = io.Copy(dst, file)
    if err != nil {
        http.Error(w, "Could not save file", http.StatusInternalServerError)
        return
    }

    // Set up the CLI context to pass the uploaded file and password to RecoverAction
    set := flag.NewFlagSet("flags", 0)
    filesFlag := cli.NewStringSlice(handler.Filename)
    set.Var(filesFlag, "files", "List of files")

    // Add password as a string flag
    set.String("password", password, "Decryption password")

    // Run the RecoverAction on the uploaded file with the password
    output, err := ProcessFiles([]string{handler.Filename}, password, Web)
    if err != nil {
        // Delete the uploaded file after processing
        errRemove := os.Remove(handler.Filename)
        if errRemove != nil {
            fmt.Fprintf(w, "<p>Warning: Failed to delete the uploaded file: %s</p>", err.Error())
        }
        msg := "Decoded action failed: " + err.Error()
        fmt.Fprintf(w, `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Error</title>
            <style>
                body {
                    background-color: #1a1a2e; /* Dark background */
                    color: #e94560; /* Neon pink text */
                    font-family: 'Arial', sans-serif;
                    text-align: center;
                    padding: 20px;
                }
                h2 {
                    color: #ff4444; /* Bright red for error */
                }
                p {
                    color: #a9a9e9; /* Light gray */
                }
                pre {
                    background-color: #0f3460; /* Dark blue for preformatted text */
                    color: #ffffff; /* White text for preformatted */
                    padding: 10px;
                    border-radius: 5px;
                    overflow-wrap: break-word; /* Ensure long words wrap */
                    max-width: 700px; /* Set a max width */
                    white-space: pre-wrap; /* Preserve whitespace */
                    word-wrap: break-word; /* Break long words */
                    margin: 10px auto; /* Center align */
                }
                input[type="submit"] {
                    background-color: #00ffcc; /* Neon green for buttons */
                }
            </style>
        </head>
        <body>
            <h2>Decoded Output:</h2>
            <p>Looks like authentication failed or there was some other error.</p>
            <div style="word-wrap: break-word; width: 700px;">%s</div>
            <form action="/" method="get">
                <input type="submit" value="Check another share" />
            </form>
        </body>
        </html>
        `, msg)
        return
    }

    // Respond with the output in HTML
    fmt.Fprintf(w, `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Decoded Output</title>
        <style>
            body {
                background-color: #1a1a2e; /* Dark background */
                color: #e94560; /* Neon pink text */
                font-family: 'Arial', sans-serif;
                text-align: center;
                padding: 20px;
            }
            h2 {
                color: #00ffcc; /* Neon green for headers */
            }
            pre {
                background-color: #0f3460; /* Dark blue for preformatted text */
                color: #ffffff; /* White text for preformatted */
                padding: 10px;
                border-radius: 5px;
                overflow-wrap: break-word; /* Ensure long words wrap */
                max-width: 700px; /* Set a max width */
                white-space: pre-wrap; /* Preserve whitespace */
                word-wrap: break-word; /* Break long words */
                margin: 10px auto; /* Center align */
            }
            input[type="submit"] {
                background-color: #00ffcc; /* Neon green for buttons */
            }
        </style>
    </head>
    <body>
        <h2>Decoded Output:</h2>
        <pre>%s</pre>
        <form action="/" method="get">
            <input type="submit" value="Check another share" />
        </form>
    </body>
    </html>
    `, output)

    // Delete the uploaded file after processing
    err = os.Remove(handler.Filename)
    if err != nil {
        fmt.Fprintf(w, "<p>Warning: Failed to delete the uploaded file: %s</p>", err.Error())
    }
}


