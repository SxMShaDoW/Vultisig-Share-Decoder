
// AES-GCM decryption implementation
// Based on vultisig-windows reference implementation

/**
 * Decrypts data using AES-GCM
 * @param {string} key - Password string
 * @param {Uint8Array} value - Encrypted data (nonce + ciphertext)
 * @returns {Promise<Uint8Array>} - Decrypted data
 */
export async function decryptWithAesGcm({ key, value }) {
    // Hash the password to create a 256-bit key using SHA-256
    const encoder = new TextEncoder();
    const keyData = encoder.encode(key);
    const hashBuffer = await crypto.subtle.digest('SHA-256', keyData);
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        hashBuffer,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );

    // GCM nonce size is 12 bytes
    const nonceSize = 12;
    if (value.length < nonceSize) {
        throw new Error('Encrypted data too short - missing nonce');
    }

    // Extract nonce and ciphertext
    const nonce = value.slice(0, nonceSize);
    const ciphertext = value.slice(nonceSize);

    try {
        // Decrypt using AES-GCM
        const decryptedBuffer = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: nonce,
            },
            cryptoKey,
            ciphertext
        );

        return new Uint8Array(decryptedBuffer);
    } catch (error) {
        throw new Error(`Decryption failed: ${error.message}`);
    }
}

/**
 * Converts base64 string to Uint8Array
 * @param {string} base64String 
 * @returns {Uint8Array}
 */
export function fromBase64(base64String) {
    const binaryString = atob(base64String);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}
