const crypto = require('crypto');

// AES-256-GCM: authenticated encryption, so tampered data fails to decrypt
const ALGORITHM = 'aes-256-gcm';
// Key length for AES-256 is 32 bytes
// IV length for GCM is 12 bytes; auth tag is 16 bytes
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

/**
 * Encrypt data using AES-256-GCM
 * @param {string} text - The data to encrypt
 * @param {Buffer} key - The 32-byte encryption key
 * @returns {object} - { iv: string (hex), encryptedData: string (hex), authTag: string (hex) }
 */
const encrypt = (text, key) => {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(key), iv, {
        authTagLength: AUTH_TAG_LENGTH,
    });
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted.toString('hex'),
        authTag: cipher.getAuthTag().toString('hex'),
    };
};

/**
 * Decrypt data using AES-256-GCM
 * @param {string} encryptedData - The encrypted data in hex
 * @param {string} iv - The initialization vector in hex
 * @param {Buffer} key - The 32-byte encryption key
 * @param {string} authTag - The GCM authentication tag in hex
 * @returns {string} - The decrypted text
 * @throws {Error} - If the auth tag is missing, or the data, IV or auth tag has been tampered with
 */
const decrypt = (encryptedData, iv, key, authTag) => {
    if (!authTag) {
        throw new Error('Missing AES-GCM auth tag');
    }
    const ivBuffer = Buffer.from(iv, 'hex');
    const encryptedText = Buffer.from(encryptedData, 'hex');

    const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(key), ivBuffer, {
        authTagLength: AUTH_TAG_LENGTH,
    });
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));

    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
};

/**
 * Generate a new random 32-byte key for AES
 * @returns {Buffer}
 */
const generateKey = () => {
    return crypto.randomBytes(32);
};

module.exports = { encrypt, decrypt, generateKey };
