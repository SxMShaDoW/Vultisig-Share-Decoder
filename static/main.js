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

// Import vanilla JS protobuf functions
import { parseVaultContainer, parseVault, LibType } from './vault_pb.js';
import { decryptWithAesGcm, fromBase64 } from './aes_gcm.js';

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
const initVsWasm = (async () => {
    try {
        debugLog("Starting vs_wasm module import...");

        // Import the vs_wasm module as ES6 module
        const vsWasmModule = await import('./vs_wasm.js');
        debugLog("vs_wasm module imported successfully");

        // Initialize the WASM module with proper path
        debugLog("Initializing WASM binary...");
        await vsWasmModule.default('./vs_wasm_bg.wasm');
        debugLog("vs_wasm WASM binary initialized successfully");

        // Verify classes are available
        if (!vsWasmModule.Keyshare || !vsWasmModule.KeyExportSession) {
            throw new Error("Required WASM classes (Keyshare, KeyExportSession) not found in module");
        }

        // Set up the module classes
        window.vsWasmModule = {
            Keyshare: vsWasmModule.Keyshare,
            KeyExportSession: vsWasmModule.KeyExportSession,
            Message: vsWasmModule.Message
        };

        debugLog("vs_wasm classes configured successfully");
        debugLog(`Available classes: ${Object.keys(window.vsWasmModule).join(', ')}`);
        return window.vsWasmModule;
    } catch (error) {
        debugLog(`vs_wasm initialization failed: ${error.message}`);
        debugLog(`Error stack: ${error.stack}`);
        debugLog("Note: vs_wasm is optional for DKLS processing");
        return null;
    }
})();

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

// Make functions globally available for HTML onclick handlers
window.addFileInput = addFileInput;
window.removeFileInput = removeFileInput;
window.recoverKeys = recoverKeys;
window.toggleSection = toggleSection;
window.checkBalance = checkBalance;
window.copyToClipboard = copyToClipboard;

// Parse and decrypt vault container following the reference implementation pattern
async function parseAndDecryptVault(fileData, password) {
    debugLog("Starting vault container parsing and decryption...");

    try {
        // Step 1: Try to decode as base64 if it's a string
        let vaultContainerData = fileData;
        try {
            const base64String = new TextDecoder().decode(fileData);
            const decoded = fromBase64(base64String);
            if (decoded.length > 100) {
                vaultContainerData = decoded;
                debugLog("Successfully decoded base64 vault container data");
            }
        } catch (e) {
            debugLog("Not base64 encoded, using raw data");
        }

        // Step 2: Parse as VaultContainer (encrypted vault)
        let vaultContainer;
        try {
            vaultContainer = parseVaultContainer(vaultContainerData);
            debugLog(`Parsed VaultContainer - version: ${vaultContainer.version}, encrypted: ${vaultContainer.isEncrypted}`);
        } catch (error) {
            debugLog(`Failed to parse as VaultContainer: ${error.message}`);
            throw new Error("Could not parse file as VaultContainer");
        }

        // Step 3: Handle both encrypted and unencrypted vaults
        let vaultData;
        if (vaultContainer.isEncrypted) {
            // Step 4a: Decrypt the vault using password
            try {
                const encryptedVaultBytes = fromBase64(vaultContainer.vault);
                vaultData = await decryptWithAesGcm({
                    key: password,
                    value: encryptedVaultBytes
                });
                debugLog(`Successfully decrypted vault, ${vaultData.length} bytes`);
            } catch (error) {
                debugLog(`Decryption failed: ${error.message}`);
                throw new Error(`Failed to decrypt vault: ${error.message}`);
            }
        } else {
            // Step 4b: Use vault data directly (unencrypted)
            try {
                vaultData = fromBase64(vaultContainer.vault);
                debugLog(`Using unencrypted vault data, ${vaultData.length} bytes`);
            } catch (error) {
                debugLog(`Failed to decode unencrypted vault: ${error.message}`);
                throw new Error(`Failed to decode unencrypted vault: ${error.message}`);
            }
        }

        // Step 5: Parse the vault protobuf to extract keyshare
        let vault;
        try {
            vault = parseVault(vaultData);
            debugLog(`Parsed vault: ${vault.name}, keyshares: ${vault.keyShares.length}, libType: ${vault.libType}`);
        } catch (error) {
            debugLog(`Failed to parse vault protobuf: ${error.message}`);
            throw new Error("Could not parse vault protobuf");
        }

        // Step 6: Extract keyshare data for DKLS
        if (vault.keyShares.length === 0) {
            throw new Error("No keyshares found in vault");
        }

        // For DKLS, we need the keyshare string (which should be hex or base64 encoded)
        const keyshareString = vault.keyShares[0].keyshare;
        if (!keyshareString) {
            throw new Error("No keyshare data found");
        }

        debugLog(`Found keyshare string: ${keyshareString.length} characters`);
        debugLog(`Keyshare preview: ${keyshareString.substring(0, 100)}...`);

        // Try to decode the keyshare string as hex first, then base64
        let keyshareData;
        try {
            if (/^[0-9a-fA-F]+$/.test(keyshareString.trim())) {
                // Hex encoded
                const hexStr = keyshareString.trim();
                keyshareData = new Uint8Array(hexStr.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                debugLog(`Decoded keyshare from hex, length: ${keyshareData.length}`);
            } else if (/^[A-Za-z0-9+/]+=*$/.test(keyshareString.trim())) {
                // Base64 encoded
                keyshareData = fromBase64(keyshareString.trim());
                debugLog(`Decoded keyshare from base64, length: ${keyshareData.length}`);
            } else {
                // Use raw string bytes as fallback
                keyshareData = new TextEncoder().encode(keyshareString);
                debugLog(`Using raw keyshare string bytes, length: ${keyshareData.length}`);
            }
        } catch (e) {
            // Use raw string bytes as fallback
            keyshareData = new TextEncoder().encode(keyshareString);
            debugLog(`Decoding failed, using raw string bytes, length: ${keyshareData.length}`);
        }

        if (keyshareData.length < 100) {
            throw new Error("Keyshare data too small, likely invalid");
        }

        debugLog(`Successfully extracted keyshare data, length: ${keyshareData.length} bytes`);
        debugLog(`First 32 bytes: ${Array.from(keyshareData.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);

        return keyshareData;

    } catch (error) {
        debugLog(`Vault parsing failed: ${error.message}`);
        throw new Error(`Failed to parse vault: ${error.message}`);
    }
}

async function processDKLSWithWASM(files, passwords, fileNames) {
    if (!window.vsWasmModule) {
        throw new Error("DKLS WASM module not available. Please reload the page.");
    }

    debugLog("Starting DKLS processing with vs_wasm...");
    const { KeyExportSession, Keyshare } = window.vsWasmModule;

    if (!Keyshare || !KeyExportSession) {
        throw new Error("WASM classes not properly initialized");
    }

    if (files.length < 2) {
        throw new Error("DKLS requires at least 2 keyshare files.");
    }

    try {
        debugLog(`Processing ${files.length} DKLS files...`);
        const keyshares = [];
        const keyIds = [];

        // Process each vault file and extract vault info
        const vaultInfos = [];
        
        for (let i = 0; i < files.length; i++) {
            debugLog(`Processing file ${i + 1}: ${fileNames[i]}`);
            const password = passwords[i] || "";

            try {
                // Parse and decrypt vault container first to get vault info
                let vaultContainerData = files[i];
                try {
                    const base64String = new TextDecoder().decode(files[i]);
                    const decoded = fromBase64(base64String);
                    if (decoded.length > 100) {
                        vaultContainerData = decoded;
                    }
                } catch (e) {
                    // Not base64, use raw data
                }

                const vaultContainer = parseVaultContainer(vaultContainerData);
                let vaultData;
                if (vaultContainer.isEncrypted) {
                    const encryptedVaultBytes = fromBase64(vaultContainer.vault);
                    vaultData = await decryptWithAesGcm({
                        key: password,
                        value: encryptedVaultBytes
                    });
                } else {
                    vaultData = fromBase64(vaultContainer.vault);
                }

                const vault = parseVault(vaultData);
                
                // Store vault info for later use
                vaultInfos.push({
                    name: vault.name || fileNames[i],
                    localPartyId: vault.localPartyId || `party${i + 1}`,
                    resharePrefix: vault.resharePrefix || '',
                    filename: fileNames[i],
                    publicKeyEddsa: vault.publicKeyEddsa || ''
                });

                // Parse and decrypt vault container for keyshare data
                const keyshareData = await parseAndDecryptVault(files[i], password);
                debugLog(`Extracted keyshare data for file ${i + 1}, length: ${keyshareData.length} bytes`);

                // Create Keyshare from extracted keyshare data
                debugLog(`Creating WASM Keyshare object for file ${i + 1}...`);
                const keyshare = Keyshare.fromBytes(keyshareData);

                if (!keyshare) {
                    throw new Error(`Failed to create keyshare from file ${i + 1}`);
                }

                keyshares.push(keyshare);
                debugLog(`Successfully created keyshare ${i + 1}`);

                // Get the key ID for this keyshare
                let keyId;
                try {
                    keyId = keyshare.keyId();
                    if (!keyId) {
                        throw new Error(`keyId() returned null/undefined`);
                    }
                    debugLog(`Raw keyId type: ${typeof keyId}, value: ${keyId}`);
                } catch (keyIdError) {
                    debugLog(`Error getting keyId: ${keyIdError.message}`);
                    throw new Error(`Failed to get key ID for keyshare ${i + 1}: ${keyIdError.message}`);
                }

                // Convert keyId to string
                let keyIdStr;
                if (keyId instanceof Uint8Array) {
                    keyIdStr = Array.from(keyId).map(b => b.toString(16).padStart(2, '0')).join('');
                } else if (typeof keyId === 'string') {
                    keyIdStr = keyId;
                } else {
                    keyIdStr = String(keyId);
                }

                keyIds.push(keyIdStr);
                debugLog(`Created keyshare ${i + 1} with ID: ${keyIdStr}`);

            } catch (error) {
                debugLog(`Error processing file ${i + 1}: ${error.message}`);
                throw new Error(`Failed to process file ${fileNames[i]}: ${error.message}`);
            }
        }

        if (keyshares.length === 0) {
            throw new Error("No valid keyshares were created");
        }

        debugLog(`Successfully created ${keyshares.length} keyshares`);
        
        // Verify all keyshares have the same key ID (they should be shares of the same key)
        const firstKeyId = keyIds[0];
        for (let i = 1; i < keyIds.length; i++) {
            if (keyIds[i] !== firstKeyId) {
                debugLog(`Key ID mismatch - Share 1: ${firstKeyId}, Share ${i + 1}: ${keyIds[i]}`);
            }
        }

        debugLog("Creating KeyExportSession...");
        debugLog(`Using key IDs: ${keyIds.join(', ')}`);

        // Create the export session with the first keyshare and all party IDs as strings
        // Use simple string party IDs instead of trying to use hex key IDs
        const partyIds = keyshares.map((_, index) => `party${index + 1}`);
        debugLog(`Using party IDs: ${partyIds.join(', ')}`);
        
        let session;
        try {
            debugLog("Creating session with first keyshare and party IDs...");
            session = KeyExportSession.new(keyshares[0], partyIds);
            if (!session) {
                throw new Error("KeyExportSession.new returned null/undefined");
            }
            debugLog("Session created successfully");
        } catch (sessionError) {
            debugLog(`Session creation failed: ${sessionError.message}`);
            throw new Error(`Failed to create KeyExportSession: ${sessionError.message}`);
        }

        debugLog("Getting setup message...");
        let setupMessage;
        try {
            setupMessage = session.setup;
            if (!setupMessage) {
                throw new Error("setup property returned null/undefined");
            }
            debugLog(`Setup message obtained, length: ${setupMessage.length} bytes`);
        } catch (setupError) {
            debugLog(`Setup message retrieval failed: ${setupError.message}`);
            throw new Error(`Failed to get setup message: ${setupError.message}`);
        }
        if (!setupMessage) {
            throw new Error("Failed to get setup message");
        }

        debugLog(`Setup message length: ${setupMessage.length} bytes`);

        // Process remaining keyshares to extract encrypted material
        debugLog("Processing remaining keyshares...");
        for (let i = 1; i < keyshares.length; i++) {
            debugLog(`Processing keyshare ${i + 1} with party ID: ${partyIds[i]}...`);
            
            try {
                // Export the encrypted material from this keyshare using party ID
                debugLog(`Calling exportShare with setup length: ${setupMessage.length}, party ID: "${partyIds[i]}", keyshare type: ${typeof keyshares[i]}`);
                
                let message;
                try {
                    message = KeyExportSession.exportShare(setupMessage, partyIds[i], keyshares[i]);
                    debugLog(`exportShare call completed for keyshare ${i + 1}`);
                } catch (exportError) {
                    debugLog(`exportShare call failed: ${exportError.message}`);
                    debugLog(`Error type: ${exportError.constructor.name}`);
                    debugLog(`Error stack: ${exportError.stack}`);
                    throw exportError;
                }

                if (!message) {
                    throw new Error(`exportShare returned null for keyshare ${i + 1}`);
                }

                if (!message.body) {
                    throw new Error(`exportShare returned message without body for keyshare ${i + 1}`);
                }

                const messageBody = message.body;
                debugLog(`Keyshare ${i + 1} exported message, length: ${messageBody.length} bytes`);

                // Input the encrypted message to the session
                const isComplete = session.inputMessage(messageBody);
                debugLog(`Message ${i + 1} processed, session complete: ${isComplete}`);

            } catch (shareError) {
                debugLog(`Error processing keyshare ${i + 1}: ${shareError.message}`);
                throw new Error(`Failed to process keyshare ${i + 1}: ${shareError.message}`);
            }
        }

        debugLog("Finishing session to extract private key...");
        let privateKeyBytes;
        try {
            privateKeyBytes = session.finish();
        } catch (finishError) {
            debugLog(`Session finish failed: ${finishError.message}`);
            throw new Error(`Failed to finish DKLS session: ${finishError.message}`);
        }

        if (!privateKeyBytes || privateKeyBytes.length === 0) {
            throw new Error("Session finished but returned empty private key");
        }

        const privateKeyHex = Array.from(privateKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        debugLog(`Extracted private key: ${privateKeyHex}... (${privateKeyBytes.length} bytes)`);

        debugLog("Getting public key...");
        const publicKeyBytes = keyshares[0].publicKey();
        const publicKeyHex = Array.from(publicKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');

        debugLog("Getting EdDSA public key from vault...");
        const eddsaPublicKey = vaultInfos[0] ? vaultInfos.find(v => v.publicKeyEddsa)?.publicKeyEddsa || '' : '';
        if (eddsaPublicKey) {
            debugLog(`EdDSA Public Key: ${eddsaPublicKey}`);
        } else {
            debugLog("No EdDSA public key found in vault");
        }

        debugLog("Getting root chain code...");
        const rootChainCodeBytes = keyshares[0].rootChainCode();
        const rootChainCodeHex = Array.from(rootChainCodeBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        debugLog(`Root Chain Code: ${rootChainCodeHex}`);

        // Call the new WASM function to derive keys for all supported coins
        debugLog("Calling WASM DeriveAndShowKeys function...");
        let derivedKeysOutput = "";
        try {
            if (window.DeriveAndShowKeys) {
                derivedKeysOutput = window.DeriveAndShowKeys(privateKeyHex, rootChainCodeHex);
                debugLog("Successfully derived keys using WASM");
            } else {
                debugLog("DeriveAndShowKeys function not available");
            }
        } catch (wasmError) {
            debugLog(`WASM key derivation error: ${wasmError.message}`);
            derivedKeysOutput = `\nError deriving keys: ${wasmError.message}`;
        }

        // Collect all party IDs from vault info
        const allPartyIds = vaultInfos.map(info => info.localPartyId).sort();
        
        // Create results in GG20 format
        const results = `
${vaultInfos.map((vaultInfo, i) => {
            return `Backup name: ${vaultInfo.filename}
This Share: ${vaultInfo.localPartyId}
All Shares: [${allPartyIds.join(' ')}]`;
        }).join('\n\n')}

Public Key(ECDSA): ${publicKeyHex}
${eddsaPublicKey ? `Public Key(EdDSA): ${eddsaPublicKey}` : ''}

${derivedKeysOutput}
        `.trim();

        debugLog("DKLS processing completed successfully");
        debugLog("Results:\n")
        debugLog(results)
        displayResults(results);

    } catch (error) {
        const errorMsg = error.message || error || "Unknown error";
        debugLog(`DKLS processing error: ${errorMsg}`);
        throw new Error(`DKLS processing failed: ${errorMsg}`);
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
                .trim()
                .toLowerCase();
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
            trimmedLine.startsWith('hex encoded non-hardened private key for') ||
            trimmedLine.startsWith('hex encoded Ed25519 private key for')) {
            
            let chain;
            let privateKey;
            
            if (trimmedLine.startsWith('hex encoded private key for')) {
                const afterPrefix = trimmedLine.replace('hex encoded private key for ', '');
                const colonIndex = afterPrefix.indexOf(':');
                if (colonIndex !== -1) {
                    chain = afterPrefix.substring(0, colonIndex).trim().toLowerCase();
                    privateKey = afterPrefix.substring(colonIndex + 1).split(' ')[0].trim(); // Take only the hex part before any notes
                }
            } else if (trimmedLine.startsWith('hex encoded non-hardened private key for')) {
                const afterPrefix = trimmedLine.replace('hex encoded non-hardened private key for ', '');
                const colonIndex = afterPrefix.indexOf(':');
                if (colonIndex !== -1) {
                    chain = afterPrefix.substring(0, colonIndex).trim().toLowerCase();
                    privateKey = afterPrefix.substring(colonIndex + 1).split(' ')[0].trim(); // Take only the hex part before any notes
                }
            } else if (trimmedLine.startsWith('hex encoded Ed25519 private key for')) {
                const afterPrefix = trimmedLine.replace('hex encoded Ed25519 private key for ', '');
                const colonIndex = afterPrefix.indexOf(':');
                if (colonIndex !== -1) {
                    chain = afterPrefix.substring(0, colonIndex).trim().toLowerCase();
                    privateKey = afterPrefix.substring(colonIndex + 1).split(' ')[0].trim(); // Take only the hex part before any notes
                }
            }
            
            if (chain && privateKey) {
                decoded.PrivateKeys[chain] = privateKey;
            }
        }

        // Parse addresses - handle both generic and specific formats
        if (trimmedLine.includes('address:')) {
            const colonIndex = trimmedLine.lastIndexOf(':');
            if (colonIndex !== -1) {
                const address = trimmedLine.substring(colonIndex + 1).trim();
                
                if (trimmedLine.startsWith('ethereum address:')) {
                    decoded.Addresses['ethereum'] = address;
                } else if (trimmedLine.startsWith('solana address:')) {
                    decoded.Addresses['solana'] = address;
                } else if (trimmedLine.startsWith('sui address:')) {
                    decoded.Addresses['sui'] = address;
                } else if (trimmedLine.startsWith('ton address:')) {
                    decoded.Addresses['ton'] = address;
                } else if (trimmedLine.startsWith('address:') && currentChain) {
                    decoded.Addresses[currentChain] = address;
                } else {
                    // Try to extract chain name from the address line itself
                    const words = trimmedLine.split(/\s+/);
                    for (let i = 0; i < words.length - 1; i++) {
                        if (words[i + 1] === 'address:') {
                            const chainName = words[i].toLowerCase();
                            decoded.Addresses[chainName] = address;
                            break;
                        }
                    }
                }
            }
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