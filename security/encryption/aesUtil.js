const crypto = require('crypto');

const ALGORITHM = 'aes-256-cbc';
// Key length for AES-256 is 32 bytes
// IV length is 16 bytes

/**
 * Encrypt data using AES-256-CBC
 * @param {string} text - The data to encrypt
 * @param {Buffer} key - The 32-byte encryption key
 * @returns {object} - { iv: string (hex), encryptedData: string (hex) }
 */
const encrypt = (text, key) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(key), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
};

/**
 * Decrypt data using AES-256-CBC
 * @param {string} encryptedData - The encrypted data in hex
 * @param {string} iv - The initialization vector in hex
 * @param {Buffer} key - The 32-byte encryption key
 * @returns {string} - The decrypted text
 */
const decrypt = (encryptedData, iv, key) => {
    const ivBuffer = Buffer.from(iv, 'hex');
    const encryptedText = Buffer.from(encryptedData, 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(key), ivBuffer);
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
