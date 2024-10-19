package main

import (
  //"flag"
  "fmt"
  "io"
  "net/http"
  "os"

  //"github.com/urfave/cli/v2"
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
      <title>Upload Files</title>
        <style>
            body {
                background-color: #1a1a2e; /* Dark background */
                color: #e94560; /* Neon pink text */
                font-family: 'Arial', sans-serif;
                text-align: center;
                padding: 20px;
            }
            a {
                color: yellow;
            }
            h2 {
                color: #00ffcc; /* Neon green */
            }
            p {
                color: #a9a9e9; /* Light gray */
            }
            .form-table {
                width: 100%;
                margin: 0 auto; /* Center align the table */
                border-collapse: collapse; /* Remove space between table cells */
            }
            .form-table th,
            .form-table td {
                border: 1px solid #0f3460; /* Add border to cells */
                padding: 10px;
                text-align: center; /* Center align text in table cells */
            }
            .form-table th {
                background-color: #1a1a2e; /* Dark background for header */
                color: #00ffcc; /* Neon green text */
                font-weight: bold;
            }
            /* Ensuring file and password inputs take full width but have a max width to prevent overflow */
            input[type="file"],
            input[type="password"],
            input[type="submit"] {
                width: 90%; /* Make inputs 90% of the cell width */
                max-width: 300px; /* Set a max width to prevent overflow */
                padding: 8px; /* Slightly reduced padding */
                border: none;
                border-radius: 5px;
                background-color: #0f3460; /* Dark blue */
                color: #ffffff; /* White text */
                font-size: 16px;
                display: block; /* Ensure it occupies full width */
                margin: 0 auto; /* Center inputs in their cells */
            }
            input[type="submit"], button {
                transition: background-color 0.3s;
            }
            .styled-button {
                padding: 10px 20px; /* Add padding for size */
                margin: 10px 0; /* Add margin for spacing */
                border: none; /* Remove default border */
                border-radius: 5px; /* Rounded corners */
                background-color: #0f3460; /* Dark blue background */
                color: #ffffff; /* White text */
                font-size: 16px; /* Font size */
                cursor: pointer; /* Pointer cursor on hover */
                transition: background-color 0.3s; /* Smooth background change */
            }
            .styled-button:hover {
                background-color: #1a1a2e; /* Change background on hover */
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
            .remove-button {
                background-color: #e94560; /* Neon pink for the remove button */
                color: #ffffff; /* White text */
                border: none; /* Remove default border */
                border-radius: 5px; /* Rounded corners */
                padding: 5px 10px; /* Padding for the button */
                cursor: pointer; /* Pointer cursor on hover */
            }
    
            .remove-button:hover {
                background-color: #ff4d4d; /* Change color on hover */
            }
        </style>
        <script>
            // Function to add a new file and password input
            function addFileInput() {
                const container = document.getElementById("fileContainer");

                // Create a new row for the new inputs
                const newRow = document.createElement("tr");
                newRow.className = "form-group"; // You can keep this for styling if needed

                // Create file input cell
                const fileCell = document.createElement("td");

                // Create file input
                const fileInput = document.createElement("input");
                fileInput.type = "file";
                fileInput.name = "file";
                fileInput.required = true;

                // Append file input to its cell
                fileCell.appendChild(fileInput);

                // Create password input cell
                const passwordCell = document.createElement("td");

                // Create password input
                const passwordInput = document.createElement("input");
                passwordInput.type = "password";
                passwordInput.name = "password";

                // Append password input to its cell
                passwordCell.appendChild(passwordInput);

                // Create remove button cell
                const removeCell = document.createElement("td");
                const removeButton = document.createElement("button");
                removeButton.textContent = "X"; // Text for the button
                removeButton.className = "remove-button"; // Add class for styling

                // Inline remove function
                removeButton.onclick = function () {
                    // Check if there's more than one row before removing
                    if (container.rows.length > 1) {
                        container.removeChild(newRow); // Remove the row when clicked
                    } else {
                        alert("You cannot remove the last row."); // Alert user if only one row exists
                    }
                };

                // Append the remove button to its cell
                removeCell.appendChild(removeButton);

                // Append all cells to the new row
                newRow.appendChild(fileCell);
                newRow.appendChild(passwordCell);
                newRow.appendChild(removeCell);

                // Add the new row to the container (tbody)
                container.appendChild(newRow);
            }

        function removeRow(button) {
            const row = button.closest('tr'); // Get the closest row
            const container = document.getElementById("fileContainer");
            // Check if there's more than one row before removing
            if (container.rows.length > 1) {
                container.removeChild(row); // Remove the row when clicked
            } else {
                alert("You cannot remove the last row."); // Alert user if only one row exists
            }
        }
        </script>
    </head>
    <body>
      <h2>Decode Vultisig Shares</h2>
        <p>Why is this tool useful? </p>
            <p>It can provide you information about your backup without having to import it into the app. It will also extract your private key information in case you need to migrate to a traditional seed based app. Note: It will only extract the correct private key information if you provide more than half of the threshold files (2of2,2of3,4of6, etc)</p>
        <form enctype="multipart/form-data" action="/upload" method="post">
        <form enctype="multipart/form-data" action="/upload" method="post">
            <table class="form-table">
                <thead>
                    <tr>
                        <th>Select a File</th>
                        <th>Password (Optional)</th>
                        <th>Action</th> <!-- New header for the remove action -->
                    </tr>
                </thead>
                <tbody id="fileContainer">
                    <tr class="form-group">
                        <td>
                            <input type="file" name="file" required />
                        </td>
                        <td>
                            <input type="password" name="password" />
                        </td>
                        <td>
                            <button type="button" class="remove-button" onclick="removeRow(this)">X</button>
                        </td>
                    </tr>
                </tbody>
            </table>
            <button type="button" class="styled-button" onclick="addFileInput()">+ Add Another Share</button>
            <div class="form-group">
                <input type="submit" class="styled-button" value="Upload" />
            </div>
        </form>

        <h5> The file you uploaded is deleted right away and we never store the password anywhere. </h5>
        <p style="color: white"> If you are looking for some examples on how to use it. You can find shares in the Github Repo to download. Just download them and upload it here.</p>
        <ul>
        <li> <a href="https://github.com/SxMShaDoW/Vultisig-Share-Decoder/blob/main/Test-part1of2.vult">Test Vault 1/2 Share Android</a> </li>
        <li><a href="https://github.com/SxMShaDoW/Vultisig-Share-Decoder/blob/main/Test-part2of2.vult">Test Vault 2/2 Share iPhone</a> </li>
       <li> <a href="https://github.com/SxMShaDoW/Vultisig-Share-Decoder/blob/main/honeypot.bak">JP's Honeypot</a>
        </li>
        </ul>
        <p> You can check the code (and run it locally) from <a href="https://github.com/SxMShaDoW/Vultisig-Share-Decoder/tree/main">Github</a> and see the code deployed from <a href="http://replit.com/@kersch/VultisigShareDecoder">Replit</a> </p>
            ` + footerHTML + `
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
            ` + footerHTML + `
        </body>
        </html>
        `)
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
        // Delete the uploaded file after processing
        for _, fileHeader := range files {
             errRemove := os.Remove(fileHeader.Filename)
             if errRemove != nil {
                 fmt.Fprintf(w, "<p>Warning: Failed to delete the uploaded file: %s</p>", err.Error())
             }
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
            ` + footerHTML + `
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
            <p> What are some relevant things to look for: </p>
            <ul>
                <li>Make sure the Public Key(ECDSA) and Public Key (EDDSA) are what you expect</li>
                </br>
                <li>The "hex encoded private key for ..." is the private key you can import into Unisat/MetaMask, etc</li>
                </br>
                <li>You can validate that your addresses (etherum, bitcoin, etc) match the addresses in your wallet </li>
                </br>
                <li>Validate the share name and all the Shares match what you expect</li>
            </ul>
        <pre>%s</pre>
        <form action="/" method="get">
            <input type="submit" value="Check another share" />
        </form>
        ` + footerHTML + `
    </body>
    </html>
    `, output)

    // Delete the uploaded files
    for _, file := range uploadedFiles {
        os.Remove(file)
    }
}


const footerHTML = `
    <script>
        function toggleSection(sectionId) {
            const content = document.getElementById(sectionId);
            const arrow = content.previousElementSibling.querySelector('.toggle-arrow');

            // Toggle the display property
            if (content.style.display === "block") {
                content.style.display = "none";
                arrow.style.transform = "rotate(0deg)"; // Rotate arrow back to normal
            } else {
                content.style.display = "block";
                arrow.style.transform = "rotate(180deg)"; // Rotate arrow to indicate open
            }
        }
    </script>
    <style>
        ul {
            list-style-type: none; /* Remove bullets */
            padding: 0;           /* Remove default padding */
            margin: 0;            /* Remove default margin */
            color: #ffcc00
        }
        p {
            color: #a9a9e9; /* Light gray */
        }
    .footer {
        background-color: #0f3460; /* Dark blue background for the footer */
        color: #ffffff; /* White text color */
        padding: 20px; /* Padding around the footer */
        border-radius: 5px; /* Rounded corners */
        margin-top: 20px; /* Margin to separate from content above */
    }

    .toggle-header {
        cursor: pointer; /* Change cursor to pointer for clickable headers */
        display: flex; /* Flexbox for alignment */
        justify-content: space-between; /* Space between title and arrow */
        align-items: center; /* Center items vertically */
        background-color: #1a1a2e; /* Slightly lighter background for headers */
        padding: 10px; /* Padding inside headers */
        border: 1px solid #00ffcc; /* Border for headers */
        border-radius: 5px; /* Rounded corners for headers */
        margin: 5px 0; /* Margin between headers */
        transition: background-color 0.3s; /* Transition for background change */
    }

    .toggle-header:hover {
        background-color: #00ffcc; /* Change background color on hover */
        color: #1a1a2e; /* Change text color on hover */
    }

    .content {
        display: none; /* Initially hidden */
        padding: 10px; /* Padding inside content */
        background-color: #1a1a2e; /* Background for content */
        border-radius: 5px; /* Rounded corners for content */
    }

    .toggle-arrow {
        margin-left: 10px; /* Space between text and arrow */
        transition: transform 0.3s; /* Smooth transition for arrow rotation */
    }

    </style>
<div>
<div class="donate-section">
    <h2>Support This Project</h2>
    <p>If you find this tool helpful, please consider making a donation as it will be passed on to tools supporting this project.</p>
    <div class="donation-addresses">
        <div class="address-item">
            <span class="currency">BTC:</span>
            <span class="address">bc1qed9kurz5045myzsm25gdq52tcntpaj8x8zlat2</span>
        <div class="address-item">
            <span class="currency">ETH:</span>
            <span class="address">0x5D4892B1b76157ed0b209c065F9753a55795b257</span>
        </div>
    </div>
</div>

    <div class="footer">
        <div class="disclaimer-section">
            <h2 class="toggle-header" onclick="toggleSection('disclaimerContent')">Disclaimer <span class="toggle-arrow">▼</span></h2>
            <div class="content" id="disclaimerContent">
                <p>Use this tool and its data at your own risk. While we strive for accuracy, it is essential that you independently verify all transaction information. The user bears sole responsibility for confirming the accuracy of any data obtained through this service.</p>
                <p>All information provided on this site is on an "as is" basis, without any guarantees of completeness, accuracy, timeliness or of the results obtained from the use of this information. We make no representations or warranties of any kind, express or implied, about the completeness, accuracy, reliability, suitability or availability with respect to the website or the information contained on the site for any purpose.</p>
                <p>This website is for informational purposes only and does not constitute financial, tax, or legal advice. For professional guidance, please consult with qualified financial, tax, or legal advisors. We cannot guarantee the absence of errors or full tax compliance. Consequently, we will not be liable for any losses or damages, including but not limited to indirect or consequential loss or damage, or any loss or damage whatsoever arising from loss of data or profits arising out of, or in connection with, the use of this tool.</p>
                <p>By using this tool, you acknowledge and agree to these terms. If you do not agree with this disclaimer, please refrain from using the service.</p>
            </div>
        </div>

        <div class="legal-section">
            <h2 class="toggle-header" onclick="toggleSection('legalContent')">Terms of Service and Privacy Policy <span class="toggle-arrow">▼</span></h2>
            <div class="content" id="legalContent">
                <h3>1. Terms of Service</h3>
                <p>By using this service, you agree to the following terms:</p>
                <ul>
                    <li>You will use this service responsibly and not attempt to overload or damage the system.</li>
                    <li>You understand that the data provided is for informational purposes only and should not be considered as financial, tax, or legal advice.</li>
                    <li>You agree not to use this service for any illegal activities or in violation of any applicable laws.</li>
                    <li>We reserve the right to terminate or suspend access to our service for any reason, without prior notice.</li>
                </ul>

                <h3>2. Privacy Policy</h3>
                <p>We respect your privacy and are committed to protecting your personal data. This privacy policy will inform you about how we handle your data:</p>
                <ul>
                    <li>We collect a vultisig share and then delete it after processing it. We do not store or collect logs.</li>
                    <li>We do not sell, trade, or otherwise transfer your personally identifiable information to third parties, because we do not track anything.</li>
                    <li>We do use Replit for deployment and hosting and their privacy policy may apply.</li>
                </ul>

                <h3>3. Cookies</h3>
                <p>We do not use Cookies.</p>

                <h3>4. Changes to Our Policies</h3>
                <p>We may update our Terms of Service and Privacy Policy from time to time. We will notify you of any changes by posting the new policies on this page.</p>

                <h3>5. Contact Us</h3>
                <p>If you have any questions about these policies, please contact us at <a href="mailto:kuji.refute847@8alias.com">kuji.refute847@8alias.com</a>.</p>
            </div>
        </div>
    </div>
</div>
`
