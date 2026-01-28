const speakeasy = require("speakeasy");
const qrcode = require("qrcode");
// Generate TOTP Secret (for new setup)
const generateSecret = async (username) => {
  const secret = speakeasy.generateSecret({
    length: 20,
    name: `SecureScholarship (${username})`,
    issuer: "SecureScholarship",
  });

  // Generate QR Code URL
  const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

  return {
    secret: secret.base32,
    qrCode: qrCodeUrl,
  };
};

// Verify TOTP Token
const verifyToken = (token, secretBase32) => {
  return speakeasy.totp.verify({
    secret: secretBase32,
    encoding: "base32",
    token: token,
    window: 1, // Allow 30sec drift
  });
};

module.exports = {
  generateSecret,
  verifyToken,
};
