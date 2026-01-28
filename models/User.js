const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String, // Stores the hashed password
        required: true
    },
    role: {
        type: String,
        enum: ['student', 'verifier', 'admin'],
        default: 'student'
    },
    mfaType: {
        type: String,
        enum: ['email_otp', 'totp_app'],
        default: 'email_otp' // Students default to email, employees/admins must upgrade
    },
    mfaSecret: {
        type: String // Stores the hashed OTP for email_otp
    },
    mfaExpiry: {
        type: Date
    },
    // NIST: Encrypted TOTP Secret for App Authenticator
    totpSecret: {
        iv: String,
        content: String
    },
    // NIST: Identity Lifecycle
    accountStatus: {
        type: String,
        enum: ['pending_verification', 'active', 'suspended', 'locked', 'invited'],
        default: 'pending_verification'
    },
    verifiedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User' // Who performed identity proofing (for employees)
    },
    verificationDate: {
        type: Date
    },
    // NIST: Password Policy
    passwordLastChanged: {
        type: Date,
        default: Date.now
    },
    passwordHistory: [{
        type: String // Store hashed passwords
    }],
    lastLoginAt: {
        type: Date
    },
    failedLoginAttempts: {
        type: Number,
        default: 0
    },
    lockoutUntil: {
        type: Date
    },
    trustedDevices: [{
        deviceId: {
            type: String,
            required: true
        },
        lastUsed: {
            type: Date,
            default: Date.now
        },
        expiry: {
            type: Date,
            required: true
        }
    }]
}, {
    timestamps: true
});

module.exports = mongoose.model('User', userSchema);
