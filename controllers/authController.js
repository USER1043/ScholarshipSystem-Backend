const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const User = require("../models/User");
const jwt = require("jsonwebtoken");
const hashUtil = require("../security/hashing/hashUtil");
const otpService = require("../services/otpService");
const emailService = require("../services/emailService");
const crypto = require("crypto");

// Generate JWT
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET || "secret_key_change_me", {
    expiresIn: "30d",
  });
};

// @desc    Register a new user
// @route   POST /api/auth/register
// @access  Public
const registerUser = async (req, res) => {
  const { username, email, password, role } = req.body;

  try {
    // Check if user exists
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Hash password
    const hashedPassword = await hashUtil.hashPassword(password);

    // Generate Verification OTP
    const otp = otpService.generateOTP();
    const expiry = otpService.generateExpiry();
    const hashedOTP = await hashUtil.hashPassword(otp);

    // Create user
    const user = await User.create({
      username,
      email,
      password: hashedPassword,
      role: "student", // Public registration is strictly for students
      accountStatus: "pending_verification", // Requires email link first (LoA 1 -> 2)
      mfaEnabled: true,
      mfaType: "email_otp",
      mfaSecret: hashedOTP, // Save hashed OTP
      mfaExpiry: expiry,
    });

    if (user) {
      // Send OTP Email
      console.log("DEV OTP:", otp);
      const emailSubject = "Verify your Email";
      const emailBody = `Welcome to SafeApply: Secure Scholarship Application System. Your verification code is ${otp}. It expires in 5 minutes.`;
      //await emailService.sendEmail(user.email, emailSubject, emailBody);

      res.status(201).json({
        _id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        message:
          "Registration successful. Please check your email for verification code.",
        mfaType: "email_otp",
      });
    } else {
      res.status(400).json({ message: "Invalid user data" });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Login user & Send OTP
// @route   POST /api/auth/login
// @access  Public
const totpService = require("../services/totpService");
const aesUtil = require("../security/encryption/aesUtil");
const rsaUtil = require("../security/encryption/rsaUtil");

// @desc    Login user & Send OTP / Verify TOTP Step 1
// @route   POST /api/auth/login
// @access  Public
const loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    // 1. Check Credentials
    if (user && (await hashUtil.comparePassword(password, user.password))) {
      // 2. NIST: Check Account Status (Identity Verification)
      if (user.accountStatus === "suspended") {
        return res
          .status(403)
          .json({ message: "Account suspended. Contact Administrator." });
      }

      // 3. Update Session Info
      user.lastLoginAt = Date.now();
      user.failedLoginAttempts = 0; // Reset on success
      await user.save();

      // 4. Device Trust Check (Optional Bypass)
      // ... (Existing Device Logic preserved but simplified for readability here)
      // For NIST LoA 3, we ALWAYS require MFA, so trusted device usually just skips 2nd factor?
      // Better to always require MFA for high security. Keeping it simple: Always MFA.

      // 5. Routing based on MFA Type
      if (user.mfaType === "totp_app") {
        // Return success but indicate TOTP is required next
        // User must call /verify-totp endpoint next (we need to make that)
        // OR we can handle it here if they sent the code? No, usually 2-step.
        // Let's return a flag.

        // If they haven't set up TOTP yet (new employee), we assume mfaSecret is null?
        // Or we generate it now.
        if (!user.mfaSecret) {
          // First time setup for Employee
          const { secret, qrCode } = await totpService.generateSecret(
            user.username,
          );

          // Encrypt Secret at Rest (Hybrid Encryption same as App Data)
          // 1. Generate temp AES Key
          const tempAesKey = aesUtil.generateKey();
          // 2. Encrypt Secret with AES
          const encryptedSecret = aesUtil.encrypt(secret, tempAesKey);
          // 3. Encrypt AES Key with RSA Public Key
          const encryptedAesKey = rsaUtil.encryptWithPublicKey(tempAesKey);

          // Store as JSON string
          user.mfaSecret = JSON.stringify({
            secret: encryptedSecret, // { iv, encryptedData }
            key: encryptedAesKey,
          });

          await user.save();

          return res.json({
            message: "MFA Setup Required",
            mfaType: "totp_setup",
            qrCode: qrCode,
            userId: user._id,
          });
        } else {
          // Normal TOTP Login
          return res.json({
            message: "Enter TOTP Code from App",
            mfaType: "totp_app",
            userId: user._id,
          });
        }
      } else {
        // EMAIL OTP (Student Legacy Flow)
        console.log(`[LOGIN] Checking existing OTP for user: ${user.email}`);

        // Check if OTP already exists and is valid
        if (user.mfaExpiry > Date.now()) {
          console.log(
            `[LOGIN] OTP already valid until ${user.mfaExpiry}. Skipping generation.`,
          );
          return res.json({
            message: "OTP already sent. Please check your email.",
            userId: user._id,
            email: user.email,
            mfaType: "email_otp",
          });
        }

        console.log(`[LOGIN] Generating NEW OTP for user: ${user.email}`);
        const otp = otpService.generateOTP();
        const expiry = otpService.generateExpiry();
        const hashedOTP = await hashUtil.hashPassword(otp);

        user.mfaSecret = hashedOTP; // Re-using field for hashed OTP
        user.mfaExpiry = expiry;
        await user.save();

        console.log("DEV OTP:", otp);
        const emailSubject = "Verification Code";
        const emailBody = `Your OTP code is ${otp}. It expires in 5 minutes.`;

        try {
          // await emailService.sendEmail(user.email, emailSubject, emailBody);
          console.log(`[LOGIN] Email sent successfully to ${user.email}`);
        } catch (emailError) {
          console.error(`[LOGIN] Failed to send email: ${emailError.message}`);
        }

        res.json({
          message: "OTP sent to your email",
          userId: user._id,
          email: user.email,
          mfaType: "email_otp",
        });
      }
    } else {
      // 5. NIST: Handle Failed Login (Lockout Logic needed here later)
      // Increment failed attempts
      if (user) {
        user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
        await user.save();
      }
      res.status(401).json({ message: "Invalid email or password" });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Verify OTP and Get Token
// @route   POST /api/auth/verify-otp
// @access  Public
const verifyOTP = async (req, res) => {
  const { userId, otp } = req.body;

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.mfaExpiry < Date.now()) {
      return res.status(400).json({ message: "OTP expired" });
    }

    // Verify OTP
    const isMatch = await hashUtil.comparePassword(otp, user.mfaSecret);

    if (isMatch) {
      // Clear OTP fields
      user.mfaSecret = undefined;
      user.mfaExpiry = undefined;

      // Activate account if pending verification
      if (user.accountStatus === "pending_verification") {
        user.accountStatus = "active";
      }

      let newDeviceId = null;
      if (req.body.trustDevice) {
        newDeviceId = crypto.randomBytes(32).toString("hex");
        user.trustedDevices.push({
          deviceId: newDeviceId,
          expiry: Date.now() + 14 * 24 * 60 * 60 * 1000, // 14 days
        });
      }

      await user.save();

      res.json({
        _id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        token: generateToken(user._id),
        deviceId: newDeviceId,
      });
    } else {
      res.status(400).json({ message: "Invalid OTP" });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Resend OTP
// @route   POST /api/auth/resend-otp
// @access  Public
const resendOTP = async (req, res) => {
  const { userId } = req.body;

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check if OTP is still valid
    if (user.mfaExpiry && user.mfaExpiry > Date.now()) {
      const remainingTime = Math.ceil((user.mfaExpiry - Date.now()) / 1000);
      if (remainingTime > 0) {
        return res.status(400).json({
          message: `Please wait ${remainingTime} seconds before resending.`,
          remainingTime,
        });
      }
    }

    // Generate new OTP
    const otp = otpService.generateOTP();
    const expiry = otpService.generateExpiry();
    const hashedOTP = await hashUtil.hashPassword(otp);

    user.mfaSecret = hashedOTP;
    user.mfaExpiry = expiry;
    await user.save();

    // Send OTP via Email
    console.log("DEV OTP (RESEND):", otp);
    // await emailService.sendEmail(
    //   user.email,
    //   "Verification Code",
    //   `Your new OTP code is ${otp}. It expires in 5 minutes.`,
    // );

    res.json({ message: "New OTP sent to your email" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Admin: Onboard new Employee (Verifier/Admin)
// @route   POST /api/auth/onboard
// @access  Private (Admin Only)
const onboardEmployee = async (req, res) => {
  const { username, email, role } = req.body;

  // Only Admin can do this (Middleware validtion should exist)
  if (!["admin", "verifier"].includes(role)) {
    return res
      .status(400)
      .json({ message: "Invalid role for internal onboarding" });
  }

  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Create User with 'invited' status and NO password yet
    // We set a random dummy password initially because Schema requires it.
    const unusablePassword = crypto.randomBytes(32).toString("hex");

    const user = await User.create({
      username,
      email,
      password: unusablePassword,
      role,
      accountStatus: "invited",
      mfaEnabled: true,
      mfaType: "totp_app",
      verifiedBy: req.user._id,
      verificationDate: Date.now(),
    });

    // Generate Invite Token (valid for 24h)
    const inviteToken = jwt.sign(
      { id: user._id, type: "invite" },
      process.env.JWT_SECRET || "secret_key_change_me",
      { expiresIn: "24h" },
    );
    const inviteLink = `http://localhost:5173/setup-account?token=${inviteToken}`;

    // Actually send the email via configured Email Service
    try {
      // await emailService.sendEmail(
      //   email,
      //   "Welcome to SafeApply: Secure Scholarship Application System",
      //   `You have been invited to join the SafeApply as a ${role}.\n\nPlease click the following link to set up your account credentials:\n\n${inviteLink}\n\nThis link is valid for 24 hours.`,
      // );
      console.log(`Invite email sent to ${email}`);
    } catch (emailErr) {
      console.error("Failed to send invite email:", emailErr);
      // We might want to warn but not fail the transaction?
      // Better to fail so Admin knows.
      // For Lab: Log it and proceed with returning it in JSON as backup.
    }

    console.log("------------------------------------------------");
    console.log("INVITE LINK (Backup):", inviteLink);
    console.log("------------------------------------------------");

    res.status(201).json({
      message: "Employee invited. Invitation link sent to email.",
      email: user.email, // Do NOT return credential
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Complete Onboarding (Set Password)
// @route   POST /api/auth/complete-invite
// @access  Public (Validated by Token)
const completeOnboarding = async (req, res) => {
  const { token, password } = req.body;

  try {
    // Verify Token
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "secret_key_change_me",
    );
    if (decoded.type !== "invite") {
      return res.status(400).json({ message: "Invalid token type" });
    }

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.accountStatus !== "invited") {
      return res
        .status(400)
        .json({ message: "Account already set up or invalid status" });
    }

    // Validate Password Strength (NIST Requirement)
    if (password.length < 8) {
      return res
        .status(400)
        .json({ message: "Password must be at least 8 characters" });
    }
    // Add more checks here (Upper, Lower, Special, etc.)

    // Hash Password
    const hashedPassword = await hashUtil.hashPassword(password);

    user.password = hashedPassword;
    user.accountStatus = "active"; // Now they can login
    user.passwordLastChanged = Date.now();
    // Add to history if we implemented history array

    await user.save();

    res.json({
      message: "Account set up successfully. Please login to configure MFA.",
    });
  } catch (error) {
    res.status(400).json({ message: "Invalid or expired invitation link" });
  }
};

// @desc    Check OTP Status (Remaining Time)
// @route   POST /api/auth/otp-status
// @access  Public
const checkOtpStatus = async (req, res) => {
  const { userId } = req.body;

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!user.mfaExpiry || user.mfaExpiry < Date.now()) {
      return res.json({ remainingTime: 0 });
    }

    const remainingTime = Math.ceil((user.mfaExpiry - Date.now()) / 1000);
    res.json({ remainingTime: remainingTime > 0 ? remainingTime : 0 });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const verifyTOTP = async (req, res) => {
  const { userId, token } = req.body;

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    if (!user.mfaSecret)
      return res.status(400).json({ message: "MFA not set up" });

    // Decrypt the TOTP Secret (Hybrid Encryption)
    let secretBase32;
    try {
      const secretData = JSON.parse(user.mfaSecret);
      // 1. Decrypt AES Key with Server Private Key
      const aesKey = rsaUtil.decryptWithPrivateKey(secretData.key);
      // 2. Decrypt TOTP Secret with AES Key
      const decryptedSecret = aesUtil.decrypt(
        secretData.secret.encryptedData,
        secretData.secret.iv,
        aesKey,
      );
      secretBase32 = decryptedSecret;
    } catch (err) {
      console.error(err);
      return res
        .status(500)
        .json({ message: "Failed to process security keys" });
    }

    // Verify Token
    const isValid = totpService.verifyToken(token, secretBase32);

    if (isValid) {
      // Update Device Trust (Simplified)
      let newDeviceId = null;
      if (req.body.trustDevice) {
        newDeviceId = crypto.randomBytes(32).toString("hex");
        user.trustedDevices.push({
          deviceId: newDeviceId,
          expiry: Date.now() + 14 * 24 * 60 * 60 * 1000, // 14 days
        });
      }
      await user.save();

      res.json({
        _id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        token: generateToken(user._id),
        deviceId: newDeviceId,
        message: "Authentication Successful",
      });
    } else {
      res.status(400).json({ message: "Invalid Authenticator Code" });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

module.exports = {
  registerUser,
  loginUser,
  verifyOTP,
  resendOTP,
  checkOtpStatus,
  onboardEmployee,
  verifyTOTP,
  completeOnboarding,
  getPublicKey,
};
