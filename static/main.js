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
            const decoded = Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
            if (decoded.length > 100) {
                vaultContainerData = decoded;
                debugLog("Successfully decoded base64 vault container data");
            }
        } catch (e) {
            debugLog("Not base64 encoded, using raw data");
        }

        // Step 2: Parse as VaultContainer protobuf
        const vaultContainer = parseProtobufVaultContainer(vaultContainerData);
        if (!vaultContainer) {
            throw new Error("Could not parse as VaultContainer protobuf");
        }

        debugLog(`Parsed VaultContainer - version: ${vaultContainer.version}, encrypted: ${vaultContainer.isEncrypted}`);

        // Step 3: Get vault data (base64 string in the container)
        let vaultData = vaultContainer.vault;
        if (!vaultData) {
            throw new Error("No vault data found in container");
        }

        // Step 4: If encrypted, decrypt using password
        if (vaultContainer.isEncrypted) {
            if (!password) {
                throw new Error("Vault is encrypted but no password provided");
            }
            
            debugLog("Vault is encrypted, attempting decryption...");
            try {
                // Decode the base64 vault data first
                const encryptedVaultBytes = Uint8Array.from(atob(vaultData), c => c.charCodeAt(0));
                
                // Decrypt using AES-GCM with SHA256(password) as key
                const decryptedVaultBytes = await decryptVaultWithPassword(encryptedVaultBytes, password);
                
                // The decrypted data should be the vault protobuf
                vaultData = new TextDecoder().decode(decryptedVaultBytes);
                debugLog("Successfully decrypted vault data");
            } catch (decryptError) {
                debugLog(`Decryption failed: ${decryptError.message}`);
                throw new Error(`Failed to decrypt vault: ${decryptError.message}`);
            }
        } else {
            debugLog("Vault is not encrypted, proceeding with direct parsing");
            // For unencrypted vaults, decode base64 to get protobuf bytes
            try {
                const vaultBytes = Uint8Array.from(atob(vaultData), c => c.charCodeAt(0));
                vaultData = new TextDecoder().decode(vaultBytes);
            } catch (e) {
                // If not base64, use as is
                debugLog("Vault data is not base64, using directly");
            }
        }

        // Step 5: Parse the vault protobuf to extract keyshare
        const vault = parseProtobufVault(new TextEncoder().encode(vaultData));
        if (!vault) {
            throw new Error("Could not parse vault protobuf");
        }

        debugLog(`Parsed vault: ${vault.name}, keyshares: ${vault.keyshares.length}`);

        // Step 6: Extract keyshare data for DKLS
        if (vault.keyshares.length === 0) {
            throw new Error("No keyshares found in vault");
        }

        // For DKLS, the keyshare data should be hex-encoded
        const keyshareString = vault.keyshares[0].keyshare;
        if (!keyshareString) {
            throw new Error("No keyshare data found");
        }

        // Try to decode as hex
        let keyshareData;
        try {
            if (/^[0-9a-fA-F]+$/.test(keyshareString.trim())) {
                const hexStr = keyshareString.trim();
                keyshareData = new Uint8Array(hexStr.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                debugLog(`Decoded keyshare from hex, length: ${keyshareData.length}`);
            } else {
                // Try base64
                keyshareData = Uint8Array.from(atob(keyshareString), c => c.charCodeAt(0));
                debugLog(`Decoded keyshare from base64, length: ${keyshareData.length}`);
            }
        } catch (e) {
            // Use raw string bytes as fallback
            keyshareData = new TextEncoder().encode(keyshareString);
            debugLog(`Using raw keyshare string bytes, length: ${keyshareData.length}`);
        }

        if (keyshareData.length < 100) {
            throw new Error("Keyshare data too small, likely invalid");
        }

        debugLog(`Successfully extracted keyshare data, length: ${keyshareData.length} bytes`);
        return keyshareData;

    } catch (error) {
        debugLog(`Vault parsing failed: ${error.message}`);
        throw new Error(`Failed to parse vault: ${error.message}`);
    }
}

// AES-GCM decryption function (following reference implementation)
async function decryptVaultWithPassword(encryptedData, password) {
    try {
        // Hash password with SHA256 to create key
        const encoder = new TextEncoder();
        const passwordData = encoder.encode(password);
        const keyMaterial = await crypto.subtle.digest('SHA-256', passwordData);
        
        // Import key for AES-GCM
        const key = await crypto.subtle.importKey(
            'raw',
            keyMaterial,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );

        // Extract nonce (first 12 bytes for GCM)
        const nonce = encryptedData.slice(0, 12);
        const ciphertext = encryptedData.slice(12);

        debugLog(`Decrypting with nonce length: ${nonce.length}, ciphertext length: ${ciphertext.length}`);

        // Decrypt
        const decryptedBuffer = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: nonce
            },
            key,
            ciphertext
        );

        return new Uint8Array(decryptedBuffer);
    } catch (error) {
        throw new Error(`Decryption failed: ${error.message}`);
    }
}

function parseProtobufVaultContainer(bytes) {
    let offset = 0;
    const container = {
        version: 0,
        vault: '',
        isEncrypted: false
    };

    while (offset < bytes.length - 1) {
        if (offset >= bytes.length) break;
        
        const fieldHeader = bytes[offset];
        const wireType = fieldHeader & 0x07;
        const fieldNumber = fieldHeader >>> 3;

        offset++;

        if (fieldNumber === 1 && wireType === 0) { // version (varint)
            const version = readVarint(bytes, offset);
            container.version = version.value;
            offset += version.bytesRead;
        } else if (fieldNumber === 2 && wireType === 2) { // vault (string)
            const length = readVarint(bytes, offset);
            offset += length.bytesRead;

            if (length.value > 0 && offset + length.value <= bytes.length) {
                const vaultBytes = bytes.slice(offset, offset + length.value);
                container.vault = new TextDecoder().decode(vaultBytes);
                offset += length.value;
            }
        } else if (fieldNumber === 3 && wireType === 0) { // isEncrypted (bool)
            const encrypted = readVarint(bytes, offset);
            container.isEncrypted = encrypted.value !== 0;
            offset += encrypted.bytesRead;
        } else if (wireType === 2) {
            // Skip unknown string fields
            const length = readVarint(bytes, offset);
            offset += length.bytesRead + length.value;
        } else if (wireType === 0) {
            // Skip unknown varint fields
            const varint = readVarint(bytes, offset);
            offset += varint.bytesRead;
        } else {
            offset++;
        }
    }

    return container.vault ? container : null;
}

function extractKeyshareFromProtobuf(keyshareFieldData) {
    // Parse the keyshare protobuf message
    // KeyShare has fields: public_key (1, string), keyshare (2, string)
    let offset = 0;
    let keyshareData = null;

    debugLog(`Extracting keyshare from protobuf message, length: ${keyshareFieldData.length}`);
    debugLog(`First 32 bytes: ${Array.from(keyshareFieldData.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);

    while (offset < keyshareFieldData.length - 10) {
        const fieldHeader = keyshareFieldData[offset];
        const wireType = fieldHeader & 0x07;
        const fieldNumber = fieldHeader >>> 3;

        debugLog(`At offset ${offset}: field ${fieldNumber}, wire type ${wireType}`);
        offset++;

        if (fieldNumber === 2 && wireType === 2) { // keyshare field
            const lengthInfo = readVarint(keyshareFieldData, offset);
            offset += lengthInfo.bytesRead;

            debugLog(`Found keyshare field, length: ${lengthInfo.value}`);

            if (lengthInfo.value > 0 && offset + lengthInfo.value <= keyshareFieldData.length) {
                const keyshareBytes = keyshareFieldData.slice(offset, offset + lengthInfo.value);

                // For DKLS, the keyshare data is hex-encoded string in protobuf
                try {
                    const keyshareString = new TextDecoder().decode(keyshareBytes);
                    debugLog(`Keyshare string preview: ${keyshareString.substring(0, 100)}...`);
                    
                    // Check if it looks like hex-encoded
                    if (/^[0-9a-fA-F]+$/.test(keyshareString.trim())) {
                        debugLog("String appears to be hex-encoded, decoding...");
                        const hexStr = keyshareString.trim();
                        const decoded = new Uint8Array(hexStr.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                        keyshareData = decoded;
                        debugLog(`Decoded DKLS keyshare from hex, length: ${keyshareData.length}`);
                        debugLog(`First 32 bytes of decoded keyshare: ${Array.from(keyshareData.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);
                        return keyshareData; // Return immediately if we found and decoded successfully
                    } else if (/^[A-Za-z0-9+/]+=*$/.test(keyshareString.trim())) {
                        // Check if it looks like base64
                        debugLog("String appears to be base64, decoding...");
                        const decoded = Uint8Array.from(atob(keyshareString), c => c.charCodeAt(0));
                        keyshareData = decoded;
                        debugLog(`Decoded DKLS keyshare from base64, length: ${keyshareData.length}`);
                        debugLog(`First 32 bytes of decoded keyshare: ${Array.from(keyshareData.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);
                        return keyshareData; // Return immediately if we found and decoded successfully
                    } else {
                        debugLog("String doesn't look like base64 or hex, using as binary");
                        keyshareData = keyshareBytes;
                        return keyshareData; // Return the raw bytes
                    }
                } catch (e) {
                    debugLog(`String decode failed: ${e.message}, trying raw bytes`);
                    // If not base64, use raw bytes
                    keyshareData = keyshareBytes;
                    debugLog(`Using raw DKLS keyshare bytes, length: ${keyshareData.length}`);
                    return keyshareData;
                }
            }
        } else if (wireType === 2) {
            // Skip other string fields
            const lengthInfo = readVarint(keyshareFieldData, offset);
            offset += lengthInfo.bytesRead;
            debugLog(`Skipping field ${fieldNumber}, length: ${lengthInfo.value}`);
            offset += lengthInfo.value;
        } else if (wireType === 0) {
            // Skip varint fields
            const varintInfo = readVarint(keyshareFieldData, offset);
            offset += varintInfo.bytesRead;
            debugLog(`Skipping varint field ${fieldNumber}, value: ${varintInfo.value}`);
        } else {
            offset++;
        }
    }

    // If we didn't find field 2, try to decode the entire message as hex
    if (!keyshareData) {
        debugLog("No keyshare field found, trying to decode the entire message as hex...");
        
        try {
            // Skip the protobuf header (0a 42) and decode the payload as hex
            let hexStr;
            if (keyshareFieldData[0] === 0x0a && keyshareFieldData[1] === 0x42) {
                // Skip protobuf field header
                hexStr = new TextDecoder().decode(keyshareFieldData.slice(2));
            } else {
                hexStr = new TextDecoder().decode(keyshareFieldData);
            }
            
            debugLog(`Attempting to decode as hex string: ${hexStr.substring(0, 100)}...`);
            
            if (/^[0-9a-fA-F]+$/.test(hexStr.trim())) {
                const decoded = new Uint8Array(hexStr.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                keyshareData = decoded;
                debugLog(`Successfully decoded entire message as hex, final size: ${keyshareData.length}`);
                debugLog(`First 32 bytes: ${Array.from(keyshareData.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);
                return keyshareData;
            }
        } catch (e) {
            debugLog(`Hex decode of entire message failed: ${e.message}`);
        }
    }

    return keyshareData;
}

function parseProtobufVault(bytes) {
    let offset = 0;
    const vault = {
        name: '',
        localPartyId: 'party_0',
        publicKeyEcdsa: '',
        publicKeyEddsa: '',
        keyshares: [],
        libType: 0,
        resharePrefix: ''
    };

    while (offset < bytes.length - 1) {
        if (offset >= bytes.length) break;
        
        const fieldHeader = bytes[offset];
        const wireType = fieldHeader & 0x07;
        const fieldNumber = fieldHeader >>> 3;

        offset++;

        if (fieldNumber === 1 && wireType === 2) { // name (string)
            const length = readVarint(bytes, offset);
            offset += length.bytesRead;

            if (length.value > 0 && offset + length.value <= bytes.length) {
                const nameBytes = bytes.slice(offset, offset + length.value);
                vault.name = new TextDecoder().decode(nameBytes);
                offset += length.value;
            }
        } else if (fieldNumber === 8 && wireType === 2) { // local_party_id (string)
            const length = readVarint(bytes, offset);
            offset += length.bytesRead;

            if (length.value > 0 && offset + length.value <= bytes.length) {
                const partyIdBytes = bytes.slice(offset, offset + length.value);
                vault.localPartyId = new TextDecoder().decode(partyIdBytes);
                offset += length.value;
            }
        } else if (fieldNumber === 2 && wireType === 2) { // public_key_ecdsa (string)
            const length = readVarint(bytes, offset);
            offset += length.bytesRead;

            if (length.value > 0 && offset + length.value <= bytes.length) {
                const publicKeyEcdsaBytes = bytes.slice(offset, offset + length.value);
                vault.publicKeyEcdsa = new TextDecoder().decode(publicKeyEcdsaBytes);
                offset += length.value;
            }
        } else if (fieldNumber === 3 && wireType === 2) { // public_key_eddsa (string)
            const length = readVarint(bytes, offset);
            offset += length.bytesRead;

            if (length.value > 0 && offset + length.value <= bytes.length) {
                const publicKeyEddsaBytes = bytes.slice(offset, offset + length.value);
                vault.publicKeyEddsa = new TextDecoder().decode(publicKeyEddsaBytes);
                offset += length.value;
            }
        } else if (fieldNumber === 7 && wireType === 2) { // keyshares (repeated)
            const length = readVarint(bytes, offset);
            offset += length.bytesRead;

            if (length.value > 0 && offset + length.value <= bytes.length) {
                const keyshareBytes = bytes.slice(offset, offset + length.value);
                const keyshare = parseProtobufKeyshare(keyshareBytes);
                if (keyshare) {
                    vault.keyshares.push(keyshare);
                }
                offset += length.value;
            }
        } else if (fieldNumber === 10 && wireType === 0) { // lib_type (enum)
            const libType = readVarint(bytes, offset);
            vault.libType = libType.value;
            offset += libType.bytesRead;
        } else if (fieldNumber === 9 && wireType === 2) { // reshare_prefix (string)
            const length = readVarint(bytes, offset);
            offset += length.bytesRead;

            if (length.value > 0 && offset + length.value <= bytes.length) {
                const resharePrefixBytes = bytes.slice(offset, offset + length.value);
                vault.resharePrefix = new TextDecoder().decode(resharePrefixBytes);
                offset += length.value;
            }
        } else if (wireType === 2) {
            const length = readVarint(bytes, offset);
            offset += length.bytesRead + length.value;
        } else if (wireType === 0) {
            const varint = readVarint(bytes, offset);
            offset += varint.bytesRead;
        } else {
            offset++;
        }
    }

    return vault;
}

function parseProtobufKeyshare(bytes) {
    let offset = 0;
    const keyshare = {
        publicKey: '',
        keyshare: ''
    };

    while (offset < bytes.length - 1) {
        if (offset >= bytes.length) break;
        
        const fieldHeader = bytes[offset];
        const wireType = fieldHeader & 0x07;
        const fieldNumber = fieldHeader >>> 3;

        offset++;

        if (fieldNumber === 1 && wireType === 2) { // public_key (string)
            const length = readVarint(bytes, offset);
            offset += length.bytesRead;

            if (length.value > 0 && offset + length.value <= bytes.length) {
                const publicKeyBytes = bytes.slice(offset, offset + length.value);
                keyshare.publicKey = new TextDecoder().decode(publicKeyBytes);
                offset += length.value;
            }
        } else if (fieldNumber === 2 && wireType === 2) { // keyshare (string)
            const length = readVarint(bytes, offset);
            offset += length.bytesRead;

            if (length.value > 0 && offset + length.value <= bytes.length) {
                const keyshareBytes = bytes.slice(offset, offset + length.value);
                keyshare.keyshare = new TextDecoder().decode(keyshareBytes);
                offset += length.value;
            }
        } else if (wireType === 2) {
            const length = readVarint(bytes, offset);
            offset += length.bytesRead + length.value;
        } else if (wireType === 0) {
            const varint = readVarint(bytes, offset);
            offset += varint.bytesRead;
        } else {
            offset++;
        }
    }

    return keyshare.keyshare ? keyshare : null;
}

// Helper function to find a specific protobuf field
function findProtobufField(data, fieldNumber) {
    let offset = 0;

    while (offset < data.length - 10) {
        const fieldHeader = data[offset];
        const wireType = fieldHeader & 0x07;
        const currentFieldNumber = fieldHeader >>> 3;

        offset++;

        if (wireType === 2) { // Length-delimited field
            const lengthInfo = readVarint(data, offset);
            offset += lengthInfo.bytesRead;

            if (currentFieldNumber === fieldNumber && lengthInfo.value > 0 && 
                offset + lengthInfo.value <= data.length) {
                return data.slice(offset, offset + lengthInfo.value);
            }

            offset += lengthInfo.value;
        } else {
            // Skip other wire types
            offset++;
        }
    }

    return null;
}

// Helper function to extract actual keyshare bytes from keyshare protobuf message
function findKeyshareBytes(keyshareMessage) {
    let offset = 0;

    while (offset < keyshareMessage.length - 10) {
        const fieldHeader = keyshareMessage[offset];
        const wireType = fieldHeader & 0x07;
        const fieldNumber = fieldHeader >>> 3;

        offset++;

        if (wireType === 2) { // Length-delimited field
            const lengthInfo = readVarint(keyshareMessage, offset);
            offset += lengthInfo.bytesRead;

            if (lengthInfo.value > 1000 && lengthInfo.value < 50000 && 
                offset + lengthInfo.value <= keyshareMessage.length) {

                const fieldData = keyshareMessage.slice(offset, offset + lengthInfo.value);

                // Check if this looks like actual keyshare bytes (not string data)
                if (isLikelyKeyshareBytes(fieldData)) {
                    debugLog(`Found keyshare bytes at field ${fieldNumber}, length: ${lengthInfo.value}`);
                    return fieldData;
                }
            }

            offset += lengthInfo.value;
        } else {
            offset++;
        }
    }

    return null;
}

// Helper function to read protobuf varint
function readVarint(data, offset) {
    let value = 0;
    let shift = 0;
    let bytesRead = 0;

    while (offset + bytesRead < data.length && bytesRead < 10) { // Allow up to 10 bytes for large varints
        const byte = data[offset + bytesRead];
        bytesRead++;
        value |= (byte & 0x7F) << shift;
        if ((byte & 0x80) === 0) break;
        shift += 7;
    }

    return { value, bytesRead };
}



// Helper function to check if data looks like keyshare bytes
function isLikelyKeyshareBytes(data) {
    if (data.length < 1000) return false;

    // Check entropy - keyshare data should have good entropy
    const uniqueBytes = new Set(data.slice(0, 256));
    if (uniqueBytes.size < 100) return false; // Low entropy

    // Check if it's not obviously text data
    let textLikeCount = 0;
    for (let i = 0; i < Math.min(100, data.length); i++) {
        const byte = data[i];
        if ((byte >= 32 && byte <= 126) || byte === 10 || byte === 13) {
            textLikeCount++;
        }
    }

    // If more than 80% looks like text, it's probably not keyshare bytes
    return textLikeCount / Math.min(100, data.length) < 0.8;
}

// Fallback function to find keyshare data using pattern matching
function findKeyshareDataFallback(vaultData) {
    debugLog("Using fallback keyshare detection");

    let offset = 0;
    let bestCandidate = null;
    let bestScore = 0;

    while (offset < vaultData.length - 10) {
        const fieldHeader = vaultData[offset];
        const wireType = fieldHeader & 0x07;

        if (wireType === 2) { // Length-delimited field
            offset++;

            const lengthInfo = readVarint(vaultData, offset);
            offset += lengthInfo.bytesRead;

            if (lengthInfo.value > 1000 && lengthInfo.value < 100000 && 
                offset + lengthInfo.value <= vaultData.length) {

                const candidate = vaultData.slice(offset, offset + lengthInfo.value);
                const score = scoreKeyshareCandidate(candidate);

                if (score > bestScore) {
                    bestScore = score;
                    bestCandidate = candidate;
                    debugLog(`New best keyshare candidate, score: ${score}, length: ${lengthInfo.value}`);
                }
            }

            offset += lengthInfo.value;
        } else {
            offset++;
        }
    }

    return bestCandidate;
}

// Score a potential keyshare candidate
function scoreKeyshareCandidate(data) {
    let score = 0;

    // Size scoring
    if (data.length > 5000 && data.length < 50000) score += 20;
    if (data.length > 10000 && data.length < 30000) score += 10;

    // Entropy scoring
    const uniqueBytes = new Set(data.slice(0, 1000));
    if (uniqueBytes.size > 200) score += 30;
    if (uniqueBytes.size > 150) score += 10;

    // Not text data
    let textBytes = 0;
    for (let i = 0; i < Math.min(500, data.length); i++) {
        const byte = data[i];
        if ((byte >= 32 && byte <= 126) || byte === 10 || byte === 13) {
            textBytes++;
        }
    }
    const textRatio = textBytes / Math.min(500, data.length);
    if (textRatio < 0.3) score += 20;
    if (textRatio < 0.5) score += 10;

    // Binary patterns that suggest cryptographic data
    let nullBytes = 0;
    for (let i = 0; i < Math.min(100, data.length); i++) {
        if (data[i] === 0) nullBytes++;
    }
    if (nullBytes < 10) score += 10; // Some nulls are okay, too many suggest padding

    return score;
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

        // Process each vault file
        for (let i = 0; i < files.length; i++) {
            debugLog(`Processing file ${i + 1}: ${fileNames[i]}`);
            const password = passwords[i] || "";

            try {
                // Parse and decrypt vault container
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
                const keyId = keyshare.keyId();
                if (!keyId) {
                    throw new Error(`Failed to get key ID for keyshare ${i + 1}`);
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
        debugLog("Creating KeyExportSession...");

        // Create the export session with the first keyshare and all key IDs
        const session = KeyExportSession.new(keyshares[0], keyIds);
        if (!session) {
            throw new Error("Failed to create KeyExportSession");
        }

        debugLog("Getting setup message...");
        const setupMessage = session.setup;
        if (!setupMessage) {
            throw new Error("Failed to get setup message");
        }

        debugLog(`Setup message length: ${setupMessage.length}`);

        // Export shares from all keyshares (starting from the second one)
        debugLog("Exporting shares...");
        for (let i = 1; i < keyshares.length; i++) {
            debugLog(`Exporting share ${i + 1}...`);
            const message = KeyExportSession.exportShare(setupMessage, keyIds[i], keyshares[i]);

            if (!message || !message.body) {
                throw new Error(`Failed to export share ${i + 1}`);
            }

            const messageBody = message.body;
            debugLog(`Share ${i + 1} exported, message length: ${messageBody.length}`);

            // Input the message to the session
            const isComplete = session.inputMessage(messageBody);
            debugLog(`Message ${i + 1} processed, session complete: ${isComplete}`);
        }

        debugLog("Finishing session to extract private key...");
        const privateKeyBytes = session.finish();

        if (!privateKeyBytes) {
            throw new Error("Failed to finish session and extract private key");
        }

        const privateKeyHex = Array.from(privateKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');

        debugLog("Getting public key...");
        const publicKeyBytes = keyshares[0].publicKey();
        const publicKeyHex = Array.from(publicKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');

        // Create results in the expected format
        const results = `
DKLS Key Recovery Results:
=========================

Private Key: ${privateKeyHex}
Public Key: ${publicKeyHex}

Share Details:
${fileNames.map((name, i) => `Share ${i + 1}: ${name} (ID: ${keyIds[i]})`).join('\n')}

Total shares processed: ${keyshares.length}
Recovery successful: Yes
        `.trim();

        debugLog("DKLS processing completed successfully");
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