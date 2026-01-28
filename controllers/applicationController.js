const Application = require("../models/Application");
const Document = require("../models/Document");
const aesUtil = require("../security/encryption/aesUtil");
const rsaUtil = require("../security/encryption/rsaUtil");
const digitalSignature = require("../security/signature/digitalSignature");
const qrUtil = require("../security/encoding/qrUtil");

// @desc    Submit a new scholarship application
// @route   POST /api/applications
// @access  Private (Student)
const submitApplication = async (req, res) => {
  try {
    const {
      bankDetails,
      idNumber,
      incomeDetails,
      instituteName,
      currentGPA,
      examType,
      examScore,
    } = req.body;
    const fullName = req.user.username; // Use registered username as full name

    // 1. Generate a new random AES key for this application
    const aesKey = aesUtil.generateKey();

    // 2. Encrypt sensitive data using the AES key
    const encryptedBankDetails = aesUtil.encrypt(bankDetails, aesKey);
    const encryptedIdNumber = aesUtil.encrypt(idNumber, aesKey);
    const encryptedIncomeDetails = aesUtil.encrypt(incomeDetails, aesKey);

    // Encrypt Academic Scores
    const academicData = JSON.stringify({ currentGPA, examScore });
    const encryptedAcademicDetails = aesUtil.encrypt(academicData, aesKey);

    // 3. Encrypt the AES key using the Server's RSA Public Key
    // This ensures that even if the database is compromised, the AES key cannot be recovered
    // without the server's Private Key (which should be stored securely/in memory/HSM).
    const encryptedAesKey = rsaUtil.encryptWithPublicKey(aesKey);

    const application = new Application({
      studentId: req.user._id,
      fullName,
      instituteName,
      examType,
      encryptedBankDetails: {
        iv: encryptedBankDetails.iv,
        content: encryptedBankDetails.encryptedData,
      },
      encryptedIdNumber: {
        iv: encryptedIdNumber.iv,
        content: encryptedIdNumber.encryptedData,
      },
      encryptedIncomeDetails: {
        iv: encryptedIncomeDetails.iv,
        content: encryptedIncomeDetails.encryptedData,
      },
      encryptedAcademicDetails: {
        iv: encryptedAcademicDetails.iv,
        content: encryptedAcademicDetails.encryptedData,
      },
      encryptedAesKey,
    });

    // Save application first to get ID
    await application.save();

    // Create and save Document entry linked to application
    const files = req.files || {};
    // Only create if files exist (or create empty one?)
    if (files.incomeProof || files.marksheet || files.studentCertificate) {
      const doc = await Document.create({
        applicationId: application._id,
        studentId: req.user._id,
        incomeProof: files.incomeProof ? files.incomeProof[0].filename : null,
        marksheet: files.marksheet ? files.marksheet[0].filename : null,
        studentCertificate: files.studentCertificate
          ? files.studentCertificate[0].filename
          : null,
      });

      // Update application with reference
      application.documents = doc._id;
      await application.save();
    }

    res.status(201).json({
      message: "Application submitted successfully",
      applicationId: application._id,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server Error" });
  }
};

// @desc    Get my applications
// @route   GET /api/applications/my
// @access  Private (Student)
// @desc    get my apps
// ...
const getMyApplications = async (req, res) => {
  try {
    const applications = await Application.find({
      studentId: req.user._id,
    }).populate("documents");

    const decryptedApplications = await Promise.all(
      applications.map(async (app) => {
        try {
          // 1. Decrypt AES Key using Server Private Key
          const aesKey = rsaUtil.decryptWithPrivateKey(app.encryptedAesKey);

          let qrCode = null;
          if (app.status === "approved") {
            // Generate QR Code encoding the Public Verify URL
            // Using hardcoded localhost for demo environment
            const verifyUrl = `http://localhost:5000/api/applications/verify-qr/${app._id}`;
            qrCode = await qrUtil.generateQRCode(verifyUrl);
          }

          // 2. Decrypt fields
          let academicDetails = {};
          if (
            app.encryptedAcademicDetails &&
            app.encryptedAcademicDetails.content
          ) {
            const decryptedAcademicJson = aesUtil.decrypt(
              app.encryptedAcademicDetails.content,
              app.encryptedAcademicDetails.iv,
              aesKey,
            );
            academicDetails = JSON.parse(decryptedAcademicJson);
          }

          return {
            _id: app._id,
            fullName: app.fullName,
            status: app.status,
            // Derive verification status for UI consistency
            verificationStatus:
              app.status === "Submitted"
                ? "Pending"
                : app.status === "Verified" || app.status === "Approved"
                  ? "Verified"
                  : "Rejected",
            verifierComments: app.verifierComments,
            rejectionReason: app.rejectionReason, // Add rejection reason
            rejectedAt: app.rejectedAt,
            instituteName: app.instituteName || "N/A",
            examType: app.examType || "N/A",
            currentGPA: academicDetails.currentGPA || "N/A",
            examScore: academicDetails.examScore || "N/A",
            bankDetails: aesUtil.decrypt(
              app.encryptedBankDetails.content,
              app.encryptedBankDetails.iv,
              aesKey,
            ),
            idNumber: aesUtil.decrypt(
              app.encryptedIdNumber.content,
              app.encryptedIdNumber.iv,
              aesKey,
            ),
            incomeDetails: aesUtil.decrypt(
              app.encryptedIncomeDetails.content,
              app.encryptedIncomeDetails.iv,
              aesKey,
            ),
            createdAt: app.createdAt,
            digitalSignature: app.digitalSignature, // Include signature
            dataHash: app.dataHash, // Include hash if needed
            signedAt: app.signedAt,
            documents: app.documents,
            qrCode: qrCode,
          };
        } catch (err) {
          console.error("Error decrypting application " + app._id, err);
          return {
            _id: app._id,
            fullName: app.fullName,
            status: app.status,
            error: "Failed to decrypt sensitive data",
          };
        }
      }),
    );

    res.json(decryptedApplications);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server Error" });
  }
};

// @desc    Verify Application Digital Signature
// @route   GET /api/applications/verify-signature/:id
// @access  Private (Student/Admin/Verifier)
const verifySignature = async (req, res) => {
  try {
    const application = await Application.findById(req.params.id);

    if (!application) {
      return res.status(404).json({ message: "Application not found" });
    }

    if (!application.digitalSignature) {
      return res.status(400).json({ message: "Application is not signed yet" });
    }

    // Reconstruct data to verify
    const dataToVerify = {
      applicationId: application._id.toString(),
      studentId: application.studentId.toString(),
      status: "approved", // Signature is only for approved state
      bankDetails: application.encryptedBankDetails,
      idNumber: application.encryptedIdNumber,
      incomeDetails: application.encryptedIncomeDetails,
      instituteName: application.instituteName,
      examType: application.examType,
      academicDetails: application.encryptedAcademicDetails,
      aesKey: application.encryptedAesKey,
    };

    // 1. Verify Hash Integrity
    const computedHash = digitalSignature.hashData(dataToVerify);
    const hashMatch = computedHash === application.dataHash;

    // 2. Verify Digital Signature
    const signatureValid = digitalSignature.verifySignature(
      dataToVerify,
      application.digitalSignature,
    );

    if (hashMatch && signatureValid) {
      res.json({
        status: "valid",
        message: "Integrity Check Passed — Data has not been altered.",
        signatureId: application.digitalSignature.substring(0, 10) + "...",
        signedAt: application.signedAt,
      });
    } else {
      res.json({
        status: "tampered",
        message: "Warning: Data integrity compromised!",
        details: {
          hashMatch,
          signatureValid,
        },
      });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Public Verify Application (QR Code)
// @route   GET /api/applications/verify-qr/:id
// @access  Public
const verifyByQR = async (req, res) => {
  try {
    const application = await Application.findById(req.params.id).populate(
      "studentId",
      "username email",
    );

    if (!application) {
      return res.status(404).json({ message: "Application not found" });
    }

    // Return only public-safe partial data
    // Encoding demo: The QR code pointed here, revealing this info.
    res.json({
      applicationId: application._id,
      applicantName: application.result_fullName, // We don't have decrypted name easily if not stored.
      // Better to show status and validity.
      // If we have fullName stored in plain text (we do), use it.
      applicantName: application.fullName,
      status: application.status,
      verificationStatus: application.verificationStatus,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const path = require("path");

// ... existing code ...

// @desc    Serve Uploaded Document
// @route   GET /api/applications/documents/:filename
const serveDocument = async (req, res) => {
  try {
    const filename = req.params.filename;

    // Find metadata for security check
    const doc = await Document.findOne({
      $or: [
        { incomeProof: filename },
        { marksheet: filename },
        { studentCertificate: filename },
      ],
    });

    if (!doc) {
      return res.status(404).json({ message: "Document not found" });
    }

    // Check Permissions
    const isOwner = doc.studentId.toString() === req.user._id.toString();
    const isStaff = req.user.role === "verifier" || req.user.role === "admin";

    if (!isOwner && !isStaff) {
      return res.status(403).json({ message: "Not authorized" });
    }

    const filePath = path.join(__dirname, "../uploads", filename);
    res.download(filePath, (err) => {
      if (err) {
        // console.error("File download error:", err); // Suppress generic log
        if (!res.headersSent)
          res.status(500).json({ message: "Could not download file" });
      }
    });
  } catch (error) {
    res.status(500).json({ message: "Server Error" });
  }
};

module.exports = {
  submitApplication,
  getMyApplications,
  verifySignature,
  verifyByQR,
  serveDocument,
};
