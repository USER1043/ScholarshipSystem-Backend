const mongoose = require("mongoose");

const applicationSchema = new mongoose.Schema(
  {
    studentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    // Non-sensitive data can be stored plainly
    fullName: {
      type: String,
      required: true,
    },
    // Sensitive fields are stored as encrypted strings
    // We store them as a JSON string of { iv, encryptedData } or just the encrypted hex?
    // Let's store structured encrypted data for easier decryption
    encryptedBankDetails: {
      iv: String,
      content: String,
    },
    encryptedIdNumber: {
      iv: String,
      content: String,
    },
    encryptedIncomeDetails: {
      iv: String,
      content: String,
    },
    // New Academic Details
    instituteName: {
      type: String,
      required: true,
    },
    examType: {
      type: String,
      enum: ["JEE", "NEET", "GATE"],
      required: true,
    },
    // Contains encrypted { currentGPA, examScore }
    encryptedAcademicDetails: {
      iv: String,
      content: String,
    },
    // File Upload Paths (Reference to distinct Document model)
    documents: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Document",
    },
    // Hybrid Encryption: Store the AES key encrypted with Server's RSA Public Key
    // This allows the server to decrypt the AES key, then decrypt the data.
    encryptedAesKey: {
      type: String, // Base64 encoded RSA-encrypted AES key
      required: true,
    },
    status: {
      type: String,
      enum: ["Submitted", "Verified", "Approved", "Rejected"],
      default: "Submitted",
    },
    verifierComments: {
      type: String,
    },
    // Admin Rejection Details
    rejectedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    rejectedAt: {
      type: Date,
    },
    rejectionReason: {
      type: String,
    },
    // Digital Signature Fields
    digitalSignature: {
      type: String,
    },
    dataHash: {
      type: String,
    },
    signedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    signedAt: {
      type: Date,
    },
  },
  {
    timestamps: true,
  },
);

module.exports = mongoose.model("Application", applicationSchema);
