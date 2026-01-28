const QRCode = require('qrcode');

/**
 * Generate QR Code Data URL
 * @param {string} data - Data to encode
 * @returns {Promise<string>} - Data URL of QR Code
 */
const generateQRCode = async (data) => {
    try {
        return await QRCode.toDataURL(data);
    } catch (err) {
        console.error(err);
        return null;
    }
};

module.exports = { generateQRCode };
