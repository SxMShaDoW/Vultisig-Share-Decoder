let fileGroupCounter = 1;

function hideLoader() {
    document.getElementById('loader').style.display = 'none';
    document.getElementById('content').style.display = 'block';
    debugLog("UI initialized and ready");
}

function debugLog(message) {
    const debugOutput = document.getElementById('debugOutput');
    const timestamp = new Date().toISOString();
    debugOutput.innerHTML += `${timestamp}: ${message}\n`;
}

// Initialize WASM modules
const go = new Go();

// Initialize main.wasm (Go WASM)
const initMainWasm = WebAssembly.instantiateStreaming(fetch("main.wasm"), go.importObject)
    .then((result) => {
        go.run(result.instance);
        debugLog("Main WASM initialized successfully");
        return result;
    });

// Initialize vs_wasm_bg.wasm (additional WASM module)
const initVsWasm = fetch('./vs_wasm_bg.wasm')
    .then(response => {
        if (!response.ok) {
            throw new Error(`Failed to fetch vs_wasm_bg.wasm: ${response.status} ${response.statusText}`);
        }
        debugLog(`vs_wasm_bg.wasm fetched successfully, size: ${response.headers.get('content-length')} bytes`);
        return response.arrayBuffer();
    })
    .then(bytes => {
        debugLog(`vs_wasm_bg.wasm loaded, size: ${bytes.byteLength} bytes`);
        if (bytes.byteLength === 0) {
            throw new Error('vs_wasm_bg.wasm file is empty');
        }
        return import('./vs_wasm.js');
    })
    .then(async (vsWasmModule) => {
        debugLog("vs_wasm module loaded, initializing...");
        const result = await vsWasmModule.default('./vs_wasm_bg.wasm');
        debugLog("vs_wasm initialized successfully");
        window.vsWasmModule = vsWasmModule;
        window.vsWasmInstance = result;
        return result;
    })
    .catch((error) => {
        debugLog(`vs_wasm initialization failed: ${error.message}`);
        debugLog("Note: vs_wasm is optional for DKLS processing");
        // Don't reject, just resolve with null to allow main app to continue
        return null;
    });

// Wait for both WASM modules to initialize
Promise.all([initMainWasm, initVsWasm])
    .then((results) => {
        const [mainResult, vsResult] = results;
        if (mainResult) {
            debugLog("Main WASM module initialized successfully");
        }
        if (vsResult) {
            debugLog("vs_wasm module initialized successfully");
        } else {
            debugLog("vs_wasm module failed to initialize - continuing without it");
        }
        debugLog("Application initialization complete");
        hideLoader();
    })
    .catch(err => {
        debugLog(`WASM initialization error: ${err}`);
        // Try to continue with just the main WASM module
        initMainWasm.then(() => {
            debugLog("Continuing with main WASM only");
            hideLoader();
        }).catch(mainErr => {
            debugLog(`Critical error - main WASM failed: ${mainErr}`);
            document.querySelector('.loader-container').innerHTML = 
                `<div style="color: var(--error-color);">Error loading application: ${mainErr}</div>`;
        });
    });

function addFileInput() {
    const container = document.getElementById('fileInputs');
    const groupDiv = document.createElement('div');
    groupDiv.className = 'file-group';
    groupDiv.id = `fileGroup${fileGroupCounter}`;

    groupDiv.innerHTML = `
        <div class="input-wrapper">
            <input type="file" accept=".bak,.vult" class="file-input" />
            <input type="password" placeholder="Password (optional)" class="password-input" />
        </div>
        <button class="btn remove-file-btn" onclick="removeFileInput(${fileGroupCounter})">
            <span class="btn-icon">×</span>
        </button>
    `;

    container.appendChild(groupDiv);
    fileGroupCounter++;
    debugLog(`Added new file input group ${fileGroupCounter}`);
}

function removeFileInput(id) {
    const element = document.getElementById(`fileGroup${id}`);
    if (element) {
        element.remove();
        debugLog(`Removed file input group ${id}`);
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
                fileNames.push(file.name); // Store the filename
            }
        }

        if (files.length === 0) {
            debugLog("Please select at least one file to process.");
            return;
        }

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

function parseOutput(rawOutput) {
    const decoded = {
        PrivateKeys: {},
        Addresses: {},
        WIFPrivateKeys: {},
        ShareDetails: '',
        PublicKeyECDSA: '',
        PublicKeyEDDSA: '',
        RawOutput: rawOutput
    };

    // Split the output into lines
    const lines = rawOutput.split('\n');
    let currentChain = '';

    for (const line of lines) {
        const trimmedLine = line.trim();

        // Parse backup details
        if (trimmedLine.startsWith('Backup name:') || 
            trimmedLine.startsWith('This Share:') || 
            trimmedLine.startsWith('All Shares:')) {
            decoded.ShareDetails += trimmedLine + '\n';
        }

        // Parse Public Keys
        if (trimmedLine.startsWith('Public Key(ECDSA):')) {
            decoded.PublicKeyECDSA = trimmedLine.split(':')[1].trim();
        } else if (trimmedLine.startsWith('Public Key(EdDSA):')) {
            decoded.PublicKeyEDDSA = trimmedLine.split(':')[1].trim();
        }

        // Track current chain context
        if (trimmedLine.startsWith('Recovering') && trimmedLine.endsWith('key....')) {
            currentChain = trimmedLine
                .replace('Recovering ', '')
                .replace(' key....', '')
                .trim();
        }

        // Parse WIF private keys
        if (trimmedLine.startsWith('WIF private key for')) {
            const parts = trimmedLine.lastIndexOf(':');
            if (parts !== -1) {
                const chainFull = trimmedLine
                    .substring('WIF private key for '.length, parts)
                    .trim()
                    .toLowerCase();
                const privateKey = trimmedLine.substring(parts + 1).trim();
                decoded.WIFPrivateKeys[chainFull] = privateKey;
            }
            continue;
        }

        // Parse private keys
        if (trimmedLine.startsWith('hex encoded private key for') || 
            trimmedLine.startsWith('hex encoded non-hardened private key for')) {
            const parts = trimmedLine.split(':');
            if (parts.length === 2) {
                let chain;
                if (trimmedLine.startsWith('hex encoded private key for')) {
                    chain = trimmedLine
                        .replace('hex encoded private key for ', '')
                        .split(':')[0]
                        .trim()
                        .toLowerCase();
                } else if (trimmedLine.startsWith('hex encoded non-hardened private key for')) {
                    chain = trimmedLine
                        .replace('hex encoded non-hardened private key for ', '')
                        .split(':')[0]
                        .trim()
                        .toLowerCase();
                }
                decoded.PrivateKeys[chain] = parts[1].trim();
            }
        }

        // Parse addresses
        if (trimmedLine.startsWith('address:')) {
            if (currentChain) {
                decoded.Addresses[currentChain] = trimmedLine.split(':')[1].trim();
            }
        }

        // Store ethereum address specifically
        if (trimmedLine.startsWith('ethereum address:')) {
            decoded.Addresses['ethereum'] = trimmedLine.split(':')[1].trim();
        }
    }

    return decoded;
}

// Function to display the parsed results
function displayResults(result) {
    const resultDiv = document.getElementById('results');
    resultDiv.innerHTML = ''; // Clear previous results

    if (typeof result === 'string' && result.toLowerCase().includes('error')) {
        resultDiv.innerHTML = `<div class="error-message">${result}</div>`;
        debugLog(`Error in results: ${result}`);
        return;
    }

    function addCopyButton(text) {
        return `<span class="copy-icon" onclick="copyToClipboard('${text.replace(/'/g, "\\'")}', event)">📋</span>`;
    }

    const parsed = parseOutput(result);

    // Create results HTML
    let html = `
        <h2>Results</h2>
        <div class="result-section">
            <h3>Share Details</h3>
            <pre>${parsed.ShareDetails}</pre>
        </div>`;

    if (parsed.PublicKeyECDSA || parsed.PublicKeyEDDSA) {
        html += `
            <div class="result-section">
                <h3>Public Keys</h3>
                ${parsed.PublicKeyECDSA ? `<pre>ECDSA: ${parsed.PublicKeyECDSA}</pre>` : ''}
                ${parsed.PublicKeyEDDSA ? `<pre>EdDSA: ${parsed.PublicKeyEDDSA} </pre>` : ''}
                <button class="btn check-balance-btn" onclick="checkBalance('${parsed.PublicKeyECDSA}', '${parsed.PublicKeyEDDSA}')">
                    Check Airdrop Balance
                </button>
                <pre id="balanceDisplay"></pre>
            </div>`;
    }

    if (Object.keys(parsed.WIFPrivateKeys).length > 0) {
        html += `
            <div class="result-section">
                <h3>WIF Private Keys</h3>
                ${Object.entries(parsed.WIFPrivateKeys)
                    .map(([chain, key]) => `
                        <div class="copy-wrapper">
                            <pre>${chain}:${key} ${addCopyButton(key)}</pre>
                        </div>`)
                    .join('')}
            </div>`;
    }
    if (Object.keys(parsed.PrivateKeys).length > 0) {
        html += `
            <div class="result-section">
                <h3>Private Keys</h3>
                ${Object.entries(parsed.PrivateKeys)
                    .map(([chain, key]) => `
                        <div class="copy-wrapper">
                            <pre>${chain}: ${key} ${addCopyButton(key)}</pre>
                        </div>`)
                    .join('')}
            </div>`;
    }
    if (Object.keys(parsed.Addresses).length > 0) {
        html += `
            <div class="result-section">
                <h3>Addresses</h3>
                ${Object.entries(parsed.Addresses)
                    .map(([chain, address]) => `
                        <div class="copy-wrapper">
                            <pre>${chain}: ${address} ${addCopyButton(address)}</pre>
                        </div>`)
                    .join('')}
            </div>`;
    }

    html += `
    <div class="result-section">
        <h3 class="toggle-header" onclick="toggleSection('rawOutput')">
        Full Output <span class="toggle-arrow">▼</span> 
        </h3>
        <div class="content" id="rawOutput"">
            <pre class="debug-output">${parsed.RawOutput}</pre>
        </div>
    </div>`

    resultDiv.innerHTML = html;
    debugLog('Results displayed successfully');
}

function toggleSection(sectionId) {
    const content = document.getElementById(sectionId);
    const arrow = content.previousElementSibling.querySelector('.toggle-arrow');

    if (content.style.display === "block") {
        content.style.display = "none";
        arrow.style.transform = "rotate(0deg)";
    } else {
        content.style.display = "block";
        arrow.style.transform = "rotate(180deg)";
    }
}

async function checkBalance(ecdsaKey, eddsaKey) {
    const display = document.getElementById('balanceDisplay');
    const button = event.target;

    try {
        // Show loading state
        button.disabled = true;
        button.textContent = 'Checking...';
        display.style.display = 'block';
        display.textContent = 'Fetching balance...';

        const response = await fetch(`https://airdrop.vultisig.com/api/vault/${ecdsaKey}/${eddsaKey}`);
        const data = await response.json();

        // Show result with animation
        if (!data || data.balance === undefined) {
            display.textContent = 'Not registered for the airdrop. Sign up for the airdrop here: https://airdrop.vultisig.com/';
        } else {
            display.textContent = `Airdrop Balance: ${data.balance}`;
        }
        display.classList.add('show');
    } catch (error) {
        display.textContent = 'Error fetching balance';
    } finally {
        // Reset button
        button.disabled = false;
        button.textContent = 'Check Airdrop Balance';
    }
}

// Simple protobuf-like parser for DKLS vaults
function parseVaultFromBytes(bytes) {
    try {
        debugLog(`Parsing vault from ${bytes.length} bytes`);
        
        // Try to decode as base64 first if it looks like base64
        let workingBytes = bytes;
        try {
            const contentStr = new TextDecoder().decode(bytes);
            if (/^[A-Za-z0-9+/]+=*$/.test(contentStr.trim())) {
                workingBytes = new Uint8Array(atob(contentStr.trim()).split('').map(c => c.charCodeAt(0)));
                debugLog(`Decoded base64 content, new length: ${workingBytes.length}`);
            }
        } catch (e) {
            debugLog("Not base64 encoded, using raw bytes");
        }
        
        // Parse as protobuf vault container first
        const vault = parseProtobufVault(workingBytes);
        
        return vault;
    } catch (error) {
        throw new Error(`Failed to parse vault: ${error.message}`);
    }
}

function parseProtobufVault(bytes) {
    let offset = 0;
    const vault = {
        name: '',
        localPartyId: 'party_0',
        publicKeyEcdsa: '',
        publicKeyEddsa: '',
        keyshares: []
    };
    
    // Simple protobuf parser - look for known field patterns
    while (offset < bytes.length - 10) {
        const fieldHeader = bytes[offset];
        const wireType = fieldHeader & 0x07;
        const fieldNumber = fieldHeader >>> 3;
        
        offset++;
        
        if (wireType === 2) { // Length-delimited (strings, bytes)
            const length = readVarint(bytes, offset);
            offset += getVarintLength(bytes, offset);
            
            if (length.value > 0 && length.value < bytes.length && offset + length.value <= bytes.length) {
                const fieldData = bytes.slice(offset, offset + length.value);
                
                // Try to decode as string first
                try {
                    const stringValue = new TextDecoder().decode(fieldData);
                    
                    // Identify fields by content patterns
                    if (stringValue.includes('vault') || stringValue.includes('DKLS') || stringValue.includes('Fast')) {
                        vault.name = stringValue;
                        debugLog(`Found vault name: ${vault.name}`);
                    } else if (stringValue.startsWith('party_') || stringValue === 'party_0' || stringValue === 'party_1') {
                        vault.localPartyId = stringValue;
                        debugLog(`Found party ID: ${vault.localPartyId}`);
                    } else if (stringValue.length === 66 && /^[0-9a-fA-F]+$/.test(stringValue)) {
                        // Looks like a hex public key
                        if (!vault.publicKeyEcdsa) {
                            vault.publicKeyEcdsa = stringValue;
                            debugLog(`Found ECDSA public key: ${stringValue.substring(0, 20)}...`);
                        } else if (!vault.publicKeyEddsa) {
                            vault.publicKeyEddsa = stringValue;
                            debugLog(`Found EdDSA public key: ${stringValue.substring(0, 20)}...`);
                        }
                    } else if (fieldData.length > 100) {
                        // Large binary data - likely keyshare
                        vault.keyshares.push({
                            publicKey: vault.publicKeyEcdsa,
                            keyshare: fieldData
                        });
                        debugLog(`Found keyshare data: ${fieldData.length} bytes`);
                    }
                } catch (e) {
                    // Not a string, might be binary keyshare data
                    if (fieldData.length > 100) {
                        vault.keyshares.push({
                            publicKey: vault.publicKeyEcdsa,
                            keyshare: fieldData
                        });
                        debugLog(`Found binary keyshare data: ${fieldData.length} bytes`);
                    }
                }
                
                offset += length.value;
            } else {
                offset++;
            }
        } else {
            // Skip other wire types
            offset++;
        }
    }
    
    // If we still don't have keyshare data, try a different approach
    if (vault.keyshares.length === 0) {
        // Look for large chunks of data that could be keyshares
        const potentialKeyshares = findLargeDataChunks(bytes, 1000); // At least 1000 bytes
        for (const chunk of potentialKeyshares) {
            vault.keyshares.push({
                publicKey: vault.publicKeyEcdsa,
                keyshare: chunk
            });
            debugLog(`Found potential keyshare chunk: ${chunk.length} bytes`);
        }
    }
    
    return vault;
}

function readVarint(bytes, offset) {
    let value = 0;
    let shift = 0;
    let byte;
    let bytesRead = 0;
    
    do {
        if (offset + bytesRead >= bytes.length) break;
        byte = bytes[offset + bytesRead];
        value |= (byte & 0x7F) << shift;
        shift += 7;
        bytesRead++;
    } while ((byte & 0x80) !== 0 && bytesRead < 5);
    
    return { value, bytesRead };
}

function getVarintLength(bytes, offset) {
    let length = 0;
    let byte;
    
    do {
        if (offset + length >= bytes.length) break;
        byte = bytes[offset + length];
        length++;
    } while ((byte & 0x80) !== 0 && length < 5);
    
    return length;
}

function findLargeDataChunks(bytes, minSize) {
    const chunks = [];
    let currentChunk = [];
    
    for (let i = 0; i < bytes.length; i++) {
        // Look for sequences of non-zero bytes that might be keyshare data
        if (bytes[i] !== 0) {
            currentChunk.push(bytes[i]);
        } else {
            if (currentChunk.length >= minSize) {
                chunks.push(new Uint8Array(currentChunk));
            }
            currentChunk = [];
        }
    }
    
    // Check final chunk
    if (currentChunk.length >= minSize) {
        chunks.push(new Uint8Array(currentChunk));
    }
    
    return chunks;
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

async function processDKLSWithWASM(files, passwords, fileNames) {
    try {
        // Check if vs_wasm module is available
        if (!window.vsWasmModule || !window.vsWasmInstance) {
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
                
                const shareData = {
                    id: `share_${i}`,
                    partyId: vault.localPartyId,
                    vault: vault,
                    keyshareData: vault.keyshares.length > 0 ? vault.keyshares[0].keyshare : null
                };
                
                dklsShares.push(shareData);
                partyIds.push(vault.localPartyId);
                
                debugLog(`Extracted DKLS share ${i + 1}, data length: ${shareData.keyshareData ? shareData.keyshareData.length : 0}`);
                
            } catch (parseError) {
                debugLog(`Error parsing file ${fileNames[i]}: ${parseError.message}`);
                throw parseError;
            }
        }
        
        if (dklsShares.length === 0) {
            throw new Error("No valid DKLS shares found in the uploaded files");
        }
        
        debugLog(`Found ${dklsShares.length} DKLS shares, attempting key export...`);
        
        // Display detailed share information
        let result = `=== DKLS Share Information ===

Found ${dklsShares.length} DKLS shares:

`;

        for (let i = 0; i < dklsShares.length; i++) {
            const share = dklsShares[i];
            const vault = share.vault;
            
            result += `
Share ${i + 1} (${fileNames[i]}):
  Party ID: ${share.partyId}
  Share Data Length: ${share.keyshareData ? share.keyshareData.length : 0} bytes
  Share Data Preview: ${share.keyshareData ? Array.from(share.keyshareData.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join('') : 'N/A'}...
`;
        }

        // Try to use the vs_wasm module for key reconstruction
        try {
            const { KeyExportSession, Keyshare } = window.vsWasmModule;
            
            // Get the first share with keyshare data
            const firstShare = dklsShares.find(s => s.keyshareData && s.keyshareData.length > 0);
            if (!firstShare) {
                throw new Error("No valid keyshare data found");
            }
            
            debugLog(`Attempting to create Keyshare from ${firstShare.keyshareData.length} bytes`);
            
            // Convert keyshare data to proper format for vs_wasm
            let keyshareBytes;
            
            // Check if keyshare data is hex-encoded string
            try {
                const keyshareStr = new TextDecoder().decode(firstShare.keyshareData);
                if (/^[0-9a-fA-F]+$/.test(keyshareStr.trim())) {
                    // It's hex-encoded, decode it
                    const hexStr = keyshareStr.trim();
                    keyshareBytes = new Uint8Array(hexStr.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                    debugLog(`Decoded hex keyshare to ${keyshareBytes.length} bytes`);
                } else {
                    // Try as raw binary data
                    keyshareBytes = firstShare.keyshareData;
                }
            } catch (e) {
                // Use raw data if text decoding fails
                keyshareBytes = firstShare.keyshareData;
            }
            
            // Try to create a keyshare object from the processed data
            const keyshare = Keyshare.fromBytes(keyshareBytes);
            
            // Create key export session
            const session = KeyExportSession.new(keyshare, partyIds);
            
            // Get the setup message
            const setupMsg = session.setup;
            debugLog(`DKLS setup message created, length: ${setupMsg.length}`);
            
            // For single-party reconstruction, directly finish
            const privateKeyBytes = session.finish();
            const privateKey = Array.from(privateKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            
            // Get public key from keyshare
            const publicKeyBytes = keyshare.publicKey();
            const publicKey = Array.from(publicKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            
            result = `=== DKLS Key Reconstruction Successful! ===

Private Key: ${privateKey}
Public Key: ${publicKey}

${result}

Note: DKLS key reconstruction completed using WASM library.
`;
            
        } catch (wasmError) {
            debugLog(`WASM processing error: ${wasmError}`);
            
            // Try alternative approach with base64 decoding
            try {
                debugLog("Trying alternative keyshare processing...");
                const firstShare = dklsShares.find(s => s.keyshareData && s.keyshareData.length > 0);
                
                // Try base64 decoding the keyshare data
                const keyshareStr = new TextDecoder().decode(firstShare.keyshareData);
                const base64Decoded = new Uint8Array(atob(keyshareStr).split('').map(c => c.charCodeAt(0)));
                
                const { Keyshare } = window.vsWasmModule;
                const keyshare = Keyshare.fromBytes(base64Decoded);
                
                debugLog("Alternative processing successful!");
                
                // Get public key from keyshare
                const publicKeyBytes = keyshare.publicKey();
                const publicKey = Array.from(publicKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                
                result = `=== DKLS Key Information (Partial) ===

Public Key: ${publicKey}

${result}

Note: Could not complete full key reconstruction, but extracted public key.
`;
                
            } catch (altError) {
                debugLog(`Alternative processing also failed: ${altError}`);
                
                result += `

Error: ${wasmError}

Note: Key reconstruction failed, but share information is displayed above.
`;
            }
        }
        
        displayResults(result);
        debugLog("DKLS processing completed");
        
    } catch (error) {
        debugLog(`DKLS processing failed: ${error.message}`);
        displayResults(`DKLS Error: ${error.message}`);
    }
}

function copyToClipboard(text, event) {
    event.stopPropagation();
    navigator.clipboard.writeText(text).then(() => {
        // Get the clicked element directly
        const btn = event.currentTarget;
        const originalText = btn.textContent;
        btn.textContent = '✓';
        setTimeout(() => {
            btn.textContent = '📋';
        }, 1000);
    }).catch(err => {
        //console.error('Failed to copy:', err);
    });
}