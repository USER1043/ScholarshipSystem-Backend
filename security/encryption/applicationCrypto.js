const aesUtil = require('./aesUtil');
const rsaUtil = require('./rsaUtil');

// Maps plaintext field name -> encrypted field on the Application model
const ENCRYPTED_FIELDS = {
    bankDetails: 'encryptedBankDetails',
    idNumber: 'encryptedIdNumber',
    incomeDetails: 'encryptedIncomeDetails',
    academicDetails: 'encryptedAcademicDetails',
};

/**
 * Decrypt selected sensitive fields of an application on the server.
 * The AES key is unwrapped with the server's RSA private key and never leaves
 * the server; callers request only the fields their role needs (least privilege).
 * @param {object} app - Application document
 * @param {string[]} fields - Keys of ENCRYPTED_FIELDS to decrypt
 * @returns {object} - { [field]: plaintext } (academicDetails is parsed JSON)
 */
const decryptApplicationFields = (app, fields) => {
    const aesKey = rsaUtil.decryptWithPrivateKey(app.encryptedAesKey);
    const result = {};

    fields.forEach((field) => {
        const encrypted = app[ENCRYPTED_FIELDS[field]];
        if (!encrypted || !encrypted.content) {
            result[field] = null;
            return;
        }
        const plaintext = aesUtil.decrypt(
            encrypted.content,
            encrypted.iv,
            aesKey,
            encrypted.authTag,
        );
        result[field] = field === 'academicDetails' ? JSON.parse(plaintext) : plaintext;
    });

    return result;
};

module.exports = { decryptApplicationFields };
