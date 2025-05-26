// Debug logging function
function debugLog(message) {
    console.log(`[DEBUG] ${message}`);
    const debugOutput = document.getElementById('debug-output');
    if (debugOutput) {
        debugOutput.innerHTML += `${message}<br>`;
        debugOutput.scrollTop = debugOutput.scrollHeight;
    }
}

function displayResults(results) {
    const output = document.getElementById('output');
    if (output) {
        output.innerHTML = `<pre>${results}</pre>`;
        debugLog("Results displayed successfully");
    }
}

function toggleSection(sectionId) {
    const section = document.getElementById(sectionId);
    if (section) {
        section.style.display = section.style.display === 'none' ? 'block' : 'none';
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        debugLog("Copied to clipboard");
    }).catch(err => {
        debugLog("Failed to copy: " + err);
    });
}

function checkBalance() {
    debugLog("Balance check functionality not implemented yet");
}

let fileInputCounter = 0;

function addFileInput() {
    fileInputCounter++;
    const container = document.getElementById('file-inputs-container');
    const fileGroup = document.createElement('div');
    fileGroup.className = 'file-group';
    fileGroup.id = `fileGroup${fileInputCounter}`;

    fileGroup.innerHTML = `
        <div class="file-input-wrapper">
            <input type="file" class="file-input" accept=".vult,.bak,.dat" />
            <input type="password" class="password-input" placeholder="Password (if encrypted)" />
            <button type="button" onclick="removeFileInput(${fileInputCounter})">Remove</button>
        </div>
    `;

    container.appendChild(fileGroup);
    debugLog(`Added file input group ${fileInputCounter}`);
}

function removeFileInput(id) {
    const element = document.getElementById(`fileGroup${id}`);
    if (element) {
        element.remove();
        debugLog(`Removed file input group ${id}`);
    }
}

function extractField(content, fieldName) {
    try {
        // Simple field extraction - look for field patterns
        const patterns = [
            new RegExp(`${fieldName}[\\s\\S]{1,10}([A-Za-z0-9+/=]{10,})`, 'i'),
            new RegExp(`"${fieldName}"\\s*:\\s*"([^"]+)"`, 'i'),
            new RegExp(`${fieldName}\\x12([\\s\\S]{1,100})`, 'i')
        ];

        for (const pattern of patterns) {
            const match = content.match(pattern);
            if (match && match[1]) {
                return match[1].trim();
            }
        }
        return null;
    } catch (e) {
        return null;
    }
}

function parseVaultFromBytes(fileBytes) {
    try {
        // Convert bytes to string for parsing
        const content = new TextDecoder().decode(fileBytes);

        // Try to parse as JSON first
        try {
            return JSON.parse(content);
        } catch (e) {
            debugLog("Not a JSON file, trying binary parsing...");
        }

        // For binary vault files, extract key fields
        const vault = {
            name: extractField(content, "name") || "Unknown",
            localPartyId: extractField(content, "localPartyId") || extractField(content, "local_party_id") || "unknown",
            publicKeyEcdsa: extractField(content, "publicKeyEcdsa") || extractField(content, "public_key_ecdsa") || "",
            publicKeyEddsa: extractField(content, "publicKeyEddsa") || extractField(content, "public_key_eddsa") || "",
            keyShares: []
        };

        debugLog(`Parsed vault: ${vault.name}, Party: ${vault.localPartyId}`);
        return vault;
    } catch (error) {
        debugLog(`Error parsing vault: ${error.message}`);
        throw new Error(`Failed to parse vault: ${error.message}`);
    }
}

async function processDKLSWithWASM(files, passwords, fileNames) {
    try {
        // Check if vs_wasm module is available
        if (!window.vsWasmModule) {
            throw new Error("DKLS WASM module not available. Please reload the page.");
        }

        debugLog("DKLS WASM module available, processing shares...");

        // Parse the vault files to extract DKLS shares
        const dklsShares = [];
        const partyIds = [];

        for (let i = 0; i < files.length; i++) {
            try {
                debugLog(`Processing file ${i + 1}: ${fileNames[i]}`);

                const vault = parseVaultFromBytes(files[i]);

                // Extract DKLS share information
                const shareData = {
                    id: vault.localPartyId,
                    partyId: vault.localPartyId,
                    shareData: files[i] // Use raw file data
                };

                dklsShares.push(shareData);
                partyIds.push(vault.localPartyId);

                debugLog(`Added DKLS share for party: ${vault.localPartyId}`);
            } catch (error) {
                debugLog(`Error processing file ${fileNames[i]}: ${error.message}`);
                throw error;
            }
        }

        if (dklsShares.length === 0) {
            throw new Error("No valid DKLS shares found");
        }

        debugLog(`Found ${dklsShares.length} DKLS shares, attempting reconstruction...`);

        // Use WASM module for key reconstruction
        try {
            const result = await window.vsWasmModule.exportKey(dklsShares, partyIds, dklsShares.length);

            if (result && result.success) {
                let output = "=== DKLS Key Reconstruction Successful! ===\n\n";
                output += `Private Key: ${result.privateKey}\n`;
                output += `Public Key: ${result.publicKey}\n`;
                displayResults(output);
            } else {
                throw new Error(result ? result.error : "Unknown WASM error");
            }
        } catch (wasmError) {
            debugLog(`WASM reconstruction failed: ${wasmError.message}`);
            throw new Error(`DKLS reconstruction failed: ${wasmError.message}`);
        }

    } catch (error) {
        displayResults(`DKLS Error: ${error.message}`);
        debugLog(`Error in processDKLSWithWASM: ${error.message}`);
    }
}

async function recoverKeys() {
    const fileGroups = document.querySelectorAll('.file-group');
    const files = [];
    const passwords = [];
    const fileNames = [];

    try {
        for (let fileGroup of fileGroups) {
            const fileInput = fileGroup.querySelector('.file-input');
            const passwordInput = fileGroup.querySelector('.password-input');

            if (fileInput.files.length > 0) {
                const file = fileInput.files[0];

                if (fileNames.includes(file.name)) {
                    debugLog(`Duplicate file detected: ${file.name}`);
                }

                const fileData = await file.arrayBuffer();
                files.push(new Uint8Array(fileData));
                passwords.push(passwordInput.value || "");
                fileNames.push(file.name);
            }
        }

        if (files.length === 0) {
            debugLog("Please select at least one file to process.");
            return;
        }

        debugLog(`Processing ${files.length} files: ${fileNames.join(', ')}`);

        // Check which scheme is selected
        const selectedScheme = document.querySelector('input[name="scheme"]:checked').value;
        debugLog(`Selected scheme: ${selectedScheme}`);

        if (selectedScheme === 'dkls') {
            debugLog("Processing with DKLS scheme using WASM library...");
            await processDKLSWithWASM(files, passwords, fileNames);
        } else {
            // Use the existing Go WASM processing for GG20 or auto-detect
            debugLog("Processing with Go WASM (GG20/auto-detect)...");
            const result = window.ProcessFiles(files, passwords, fileNames);
            if (!result || result === "undefined") {
                debugLog("No results were generated. Reload the page and make sure you are using different shares.");
                return;
            }
            displayResults(result);
        }

    } catch (error) {
        displayResults(`Error: ${error.message}`);
        debugLog(`Error in recoverKeys: ${error.message}`);
    }
}

// Make functions globally available for HTML onclick handlers
window.addFileInput = addFileInput;
window.removeFileInput = removeFileInput;
window.recoverKeys = recoverKeys;
window.toggleSection = toggleSection;
window.checkBalance = checkBalance;
window.copyToClipboard = copyToClipboard;

// Initialize the page
document.addEventListener('DOMContentLoaded', function() {
    debugLog("Page loaded, initializing...");

    // Add initial file input
    addFileInput();

    // Check if WASM modules are loading
    if (typeof Go !== 'undefined') {
        debugLog("Go WASM support detected");
    }

    if (window.vsWasmModule) {
        debugLog("DKLS WASM module detected");
    }
});