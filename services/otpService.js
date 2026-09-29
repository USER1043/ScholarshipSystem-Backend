const crypto = require('crypto');

/**
 * Generate a 6-digit numeric OTP using a cryptographically secure RNG
 * @returns {string}
 */
const generateOTP = () => {
    // randomInt's upper bound is exclusive: yields 100000–999999
    return crypto.randomInt(100000, 1000000).toString();
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
