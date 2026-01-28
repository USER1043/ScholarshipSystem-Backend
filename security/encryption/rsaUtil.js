const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEYS_DIR = path.join(__dirname, '../../config');
const PUBLIC_KEY_PATH = path.join(KEYS_DIR, 'public.pem');
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, 'private.pem');

// Ensure keys exist, or generate them
const ensureKeys = () => {
    if (!fs.existsSync(PUBLIC_KEY_PATH) || !fs.existsSync(PRIVATE_KEY_PATH)) {
        console.log("Generating new RSA Key Pair...");
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 4096,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem',
            }
        });
        
        fs.writeFileSync(PUBLIC_KEY_PATH, publicKey);
        fs.writeFileSync(PRIVATE_KEY_PATH, privateKey);
        console.log("RSA Key Pair generated and saved to config/.");
    }
};

/**
 * Encrypt data (e.g., AES Key) using Public Key
 * @param {Buffer} data - Data to encrypt
 * @returns {string} - Base64 encoded encrypted data
 */
const encryptWithPublicKey = (data) => {
    ensureKeys();
    const publicKey = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
    const buffer = Buffer.from(data);
    const encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString('base64');
};

/**
 * Decrypt data (e.g., AES Key) using Private Key
 * @param {string} encryptedData - Base64 encoded encrypted data
 * @returns {Buffer} - Decrypted data
 */
const decryptWithPrivateKey = (encryptedData) => {
    ensureKeys();
    const privateKey = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
    const buffer = Buffer.from(encryptedData, 'base64');
    const decrypted = crypto.privateDecrypt(privateKey, buffer);
    return decrypted;
};

module.exports = {
    ensureKeys,
    encryptWithPublicKey,
    decryptWithPrivateKey
};
