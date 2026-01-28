const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const rsaUtil = require('../encryption/rsaUtil');

const KEYS_DIR = path.join(__dirname, '../../config');
const PUBLIC_KEY_PATH = path.join(KEYS_DIR, 'public.pem');
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, 'private.pem');

const canonicalize = (obj) => {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
        return obj;
    }
    const sortedKeys = Object.keys(obj).sort();
    const result = {};
    sortedKeys.forEach(key => {
        result[key] = canonicalize(obj[key]);
    });
    return JSON.stringify(result);
};

/**
 * Sign data using RSA Private Key (SHA-256)
 * @param {object|string} data - Data to sign
 * @returns {string} - Base64 encoded signature
 */
const signData = (data) => {
    rsaUtil.ensureKeys();
    const privateKey = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
    const sign = crypto.createSign('SHA256');
    
    // Create canonical JSON string for objects to ensure consistent ordering
    const dataString = typeof data === 'string' ? data : canonicalize(data);
    
    sign.update(dataString);
    sign.end();
    
    const signature = sign.sign(privateKey, 'base64');
    return signature;
};

/**
 * Verify a digital signature using RSA Public Key
 * @param {object|string} data - Original data that was signed
 * @param {string} signature - Base64 encoded signature to verify
 * @returns {boolean} - True if valid, false otherwise
 */
const verifySignature = (data, signature) => {
    rsaUtil.ensureKeys();
    const publicKey = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
    const verify = crypto.createVerify('SHA256');
    
    const dataString = typeof data === 'string' ? data : canonicalize(data);
    
    verify.update(dataString);
    verify.end();
    
    return verify.verify(publicKey, signature, 'base64');
};

/**
 * Generate SHA-256 hash of data
 * @param {object|string} data
 * @returns {string} - Hex encoded hash
 */
const hashData = (data) => {
    const hash = crypto.createHash('sha256');
    const dataString = typeof data === 'string' ? data : canonicalize(data);
    hash.update(dataString);
    return hash.digest('hex');
};

module.exports = { signData, verifySignature, hashData };
