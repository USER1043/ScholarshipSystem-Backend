const mongoose = require("mongoose");
const User = require("../models/User");
const hashUtil = require("../security/hashing/hashUtil");
const aesUtil = require("../security/encryption/aesUtil");
const rsaUtil = require("../security/encryption/rsaUtil");
const totpService = require("../services/totpService");
const dotenv = require("dotenv");
const QRCode = require("qrcode");
const path = require("path");

// Load env vars
dotenv.config({ path: path.join(__dirname, "../.env") });

const fs = require("fs");

const seedAdmin = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("MongoDB Connected");

    const adminEmail = process.env.SUPER_ADMIN_EMAIL;
    const adminPassword = process.env.SUPER_ADMIN_PASSWORD;

    const userExists = await User.findOne({ email: adminEmail });
    if (userExists) {
      console.log("Admin already exists (Run resetAdmin.js to recreate)");
      process.exit();
    }

    console.log(`Creating Admin: ${adminEmail}`);

    const hashedPassword = await hashUtil.hashPassword(adminPassword);

    // Generate TOTP Secret
    // We use 'Admin' as username for the TOTP label
    const { secret, qrCode } = await totpService.generateSecret("SuperAdmin");

    // Encrypt Secret (Hybrid)
    const tempAesKey = aesUtil.generateKey();
    const encryptedSecret = aesUtil.encrypt(secret, tempAesKey);
    const encryptedAesKey = rsaUtil.encryptWithPublicKey(tempAesKey);

    const mfaSecretJSON = JSON.stringify({
      secret: encryptedSecret,
      key: encryptedAesKey,
    });

    const admin = await User.create({
      username: "SuperAdmin",
      email: adminEmail,
      password: hashedPassword,
      role: "admin",
      accountStatus: "active",
      mfaEnabled: true,
      mfaType: "totp_app",
      mfaSecret: mfaSecretJSON,
      deviceTrustEnabled: false, // Force TOTP every time for Root Admin? Or follow standard logic.
    });

    console.log("Super Admin created successfully:", admin._id);

    // Generate HTML File for QR
    const htmlContent = `
    <html>
      <body style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; font-family: sans-serif;">
        <h1>Super Admin Created</h1>
        <p>Scan this QR Code with your Authenticator App immediately.</p>
        <img src="${qrCode}" alt="QR Code" style="border: 1px solid #ccc; padding: 10px; border-radius: 8px;"/>
        <p><strong>Secret Key:</strong> ${secret}</p>
        <p style="color: red; margin-top: 20px;">For security, delete this file after scanning!</p>
      </body>
    </html>
    `;

    const qrFilePath = path.join(__dirname, "admin_qr.html");
    fs.writeFileSync(qrFilePath, htmlContent);

    console.log("------------------------------------------------");
    console.log("QR CODE EXPORTED TO FILE:");
    console.log(qrFilePath);
    console.log(
      "Use 'open server/scripts/admin_qr.html' or open in browser to scan.",
    );
    console.log("------------------------------------------------");
    process.exit();
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
};

seedAdmin();
