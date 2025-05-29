
// Vanilla JavaScript protobuf parser for Vultisig vault structures
// No external dependencies - works with static files

// Simple protobuf wire format parser
function readVarint(bytes, offset) {
    let result = 0;
    let shift = 0;
    let byte;
    let bytesRead = 0;
    
    do {
        if (offset + bytesRead >= bytes.length) {
            throw new Error("Unexpected end of buffer while reading varint");
        }
        byte = bytes[offset + bytesRead];
        result |= (byte & 0x7F) << shift;
        shift += 7;
        bytesRead++;
    } while (byte & 0x80);
    
    return { value: result, bytesRead };
}

function readLengthDelimited(bytes, offset) {
    const length = readVarint(bytes, offset);
    const start = offset + length.bytesRead;
    const end = start + length.value;
    
    if (end > bytes.length) {
        throw new Error("Length-delimited field extends beyond buffer");
    }
    
    return {
        data: bytes.slice(start, end),
        bytesRead: length.bytesRead + length.value
    };
}

function readString(bytes, offset) {
    const field = readLengthDelimited(bytes, offset);
    return {
        value: new TextDecoder().decode(field.data),
        bytesRead: field.bytesRead
    };
}

// Parse VaultContainer message
export function parseVaultContainer(bytes) {
    const container = {
        version: 0,
        vault: '',
        isEncrypted: false
    };
    
    let offset = 0;
    
    while (offset < bytes.length) {
        if (offset >= bytes.length) break;
        
        const fieldHeader = bytes[offset];
        const wireType = fieldHeader & 0x07;
        const fieldNumber = fieldHeader >>> 3;
        
        offset++;
        
        try {
            switch (fieldNumber) {
                case 1: // version (uint64)
                    if (wireType === 0) {
                        const version = readVarint(bytes, offset);
                        container.version = version.value;
                        offset += version.bytesRead;
                    } else {
                        offset++;
                    }
                    break;
                    
                case 2: // vault (string)
                    if (wireType === 2) {
                        const vault = readString(bytes, offset);
                        container.vault = vault.value;
                        offset += vault.bytesRead;
                    } else {
                        offset++;
                    }
                    break;
                    
                case 3: // is_encrypted (bool)
                    if (wireType === 0) {
                        const encrypted = readVarint(bytes, offset);
                        container.isEncrypted = encrypted.value !== 0;
                        offset += encrypted.bytesRead;
                    } else {
                        offset++;
                    }
                    break;
                    
                default:
                    // Skip unknown fields
                    if (wireType === 0) {
                        const skip = readVarint(bytes, offset);
                        offset += skip.bytesRead;
                    } else if (wireType === 2) {
                        const skip = readLengthDelimited(bytes, offset);
                        offset += skip.bytesRead;
                    } else {
                        offset++;
                    }
                    break;
            }
        } catch (e) {
            // If we can't parse a field, skip it
            offset++;
        }
    }
    
    return container;
}

// Parse Vault message
export function parseVault(bytes) {
    const vault = {
        name: '',
        publicKeyEcdsa: '',
        publicKeyEddsa: '',
        signers: [],
        createdAt: null,
        hexChainCode: '',
        keyShares: [],
        localPartyId: '',
        resharePrefix: '',
        libType: 0
    };
    
    let offset = 0;
    
    while (offset < bytes.length) {
        if (offset >= bytes.length) break;
        
        const fieldHeader = bytes[offset];
        const wireType = fieldHeader & 0x07;
        const fieldNumber = fieldHeader >>> 3;
        
        offset++;
        
        try {
            switch (fieldNumber) {
                case 1: // name
                    if (wireType === 2) {
                        const name = readString(bytes, offset);
                        vault.name = name.value;
                        offset += name.bytesRead;
                    } else {
                        offset++;
                    }
                    break;
                    
                case 2: // public_key_ecdsa
                    if (wireType === 2) {
                        const pubKey = readString(bytes, offset);
                        vault.publicKeyEcdsa = pubKey.value;
                        offset += pubKey.bytesRead;
                    } else {
                        offset++;
                    }
                    break;
                    
                case 3: // public_key_eddsa
                    if (wireType === 2) {
                        const pubKey = readString(bytes, offset);
                        vault.publicKeyEddsa = pubKey.value;
                        offset += pubKey.bytesRead;
                    } else {
                        offset++;
                    }
                    break;
                    
                case 4: // signers (repeated string)
                    if (wireType === 2) {
                        const signer = readString(bytes, offset);
                        vault.signers.push(signer.value);
                        offset += signer.bytesRead;
                    } else {
                        offset++;
                    }
                    break;
                    
                case 6: // hex_chain_code
                    if (wireType === 2) {
                        const chainCode = readString(bytes, offset);
                        vault.hexChainCode = chainCode.value;
                        offset += chainCode.bytesRead;
                    } else {
                        offset++;
                    }
                    break;
                    
                case 7: // key_shares (repeated KeyShare)
                    if (wireType === 2) {
                        const keyShareData = readLengthDelimited(bytes, offset);
                        const keyShare = parseKeyShare(keyShareData.data);
                        vault.keyShares.push(keyShare);
                        offset += keyShareData.bytesRead;
                    } else {
                        offset++;
                    }
                    break;
                    
                case 8: // local_party_id
                    if (wireType === 2) {
                        const partyId = readString(bytes, offset);
                        vault.localPartyId = partyId.value;
                        offset += partyId.bytesRead;
                    } else {
                        offset++;
                    }
                    break;
                    
                case 9: // reshare_prefix
                    if (wireType === 2) {
                        const prefix = readString(bytes, offset);
                        vault.resharePrefix = prefix.value;
                        offset += prefix.bytesRead;
                    } else {
                        offset++;
                    }
                    break;
                    
                case 10: // lib_type
                    if (wireType === 0) {
                        const libType = readVarint(bytes, offset);
                        vault.libType = libType.value;
                        offset += libType.bytesRead;
                    } else {
                        offset++;
                    }
                    break;
                    
                default:
                    // Skip unknown fields
                    if (wireType === 0) {
                        const skip = readVarint(bytes, offset);
                        offset += skip.bytesRead;
                    } else if (wireType === 2) {
                        const skip = readLengthDelimited(bytes, offset);
                        offset += skip.bytesRead;
                    } else {
                        offset++;
                    }
                    break;
            }
        } catch (e) {
            // If we can't parse a field, skip it
            offset++;
        }
    }
    
    return vault;
}

// Parse KeyShare nested message
function parseKeyShare(bytes) {
    const keyShare = {
        publicKey: '',
        keyshare: ''
    };
    
    let offset = 0;
    
    while (offset < bytes.length) {
        if (offset >= bytes.length) break;
        
        const fieldHeader = bytes[offset];
        const wireType = fieldHeader & 0x07;
        const fieldNumber = fieldHeader >>> 3;
        
        offset++;
        
        try {
            switch (fieldNumber) {
                case 1: // public_key
                    if (wireType === 2) {
                        const pubKey = readString(bytes, offset);
                        keyShare.publicKey = pubKey.value;
                        offset += pubKey.bytesRead;
                    } else {
                        offset++;
                    }
                    break;
                    
                case 2: // keyshare
                    if (wireType === 2) {
                        const share = readString(bytes, offset);
                        keyShare.keyshare = share.value;
                        offset += share.bytesRead;
                    } else {
                        offset++;
                    }
                    break;
                    
                default:
                    // Skip unknown fields
                    if (wireType === 0) {
                        const skip = readVarint(bytes, offset);
                        offset += skip.bytesRead;
                    } else if (wireType === 2) {
                        const skip = readLengthDelimited(bytes, offset);
                        offset += skip.bytesRead;
                    } else {
                        offset++;
                    }
                    break;
            }
        } catch (e) {
            // If we can't parse a field, skip it
            offset++;
        }
    }
    
    return keyShare;
}

// LibType enum values
export const LibType = {
    GG20: 0,
    DKLS: 1,
};
