const crypto = require('crypto');

/**
 * Generate a 6-digit numeric OTP
 * @returns {string}
 */
const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

/**
 * Generate expiration time (e.g. 5 minutes from now)
 * @param {number} minutes 
 * @returns {Date}
 */
const generateExpiry = (minutes = 5) => {
    return new Date(Date.now() + minutes * 60 * 1000);
};

module.exports = { generateOTP, generateExpiry };
