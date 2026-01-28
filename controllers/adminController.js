const Application = require("../models/Application");
const digitalSignature = require("../security/signature/digitalSignature");
const aesUtil = require("../security/encryption/aesUtil");
const rsaUtil = require("../security/encryption/rsaUtil");
const qrUtil = require("../security/encoding/qrUtil");

// @desc    Get all verified applications
// @route   GET /api/admin/applications
// @access  Private (Admin)
const getVerifiedApplications = async (req, res) => {
  try {
    // Admin might want to see all, but mostly focuses on 'verified' ones ready for approval
    const applications = await Application.find()
      .populate("studentId", "email username")
      .populate("documents");

    // Return summary or decrypted?
    // Admin needs to see details to approve.
    const decryptedApplications = applications.map((app) => {
      try {
        const aesKey = rsaUtil.decryptWithPrivateKey(app.encryptedAesKey);
        return {
          _id: app._id,
          student: app.studentId,
          fullName: app.fullName,
          status: app.status,
          verificationStatus: app.verificationStatus,
          verifierComments: app.verifierComments,
          incomeDetails: aesUtil.decrypt(
            app.encryptedIncomeDetails.content,
            app.encryptedIncomeDetails.iv,
            aesKey,
          ),

          // Decrypt Academic Info
          instituteName: app.instituteName || "N/A",
          examType: app.examType || "N/A",
          academicDetails: app.encryptedAcademicDetails
            ? JSON.parse(
                aesUtil.decrypt(
                  app.encryptedAcademicDetails.content,
                  app.encryptedAcademicDetails.iv,
                  aesKey,
                ),
              )
            : null,

          createdAt: app.createdAt,
          documents: app.documents,
        };
      } catch (err) {
        return { _id: app._id, error: "Decryption failed" };
      }
    });

    res.json(decryptedApplications);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Approve Scholarship & Sign
// @route   POST /api/admin/approve/:id
// @access  Private (Admin)
const approveScholarship = async (req, res) => {
  try {
    const application = await Application.findById(req.params.id);

    if (!application) {
      return res.status(404).json({ message: "Application not found" });
    }

    if (application.status !== "Verified") {
      return res.status(400).json({
        message: "Application must be Verified by staff before Approval",
      });
    }

    // 1. Update status
    application.status = "Approved";
    await application.save();

    // 2. Create Digital Signature
    // We sign a hash of critical data: StudentID + ApplicationID + Status + Sensitive Encrypted Data
    const dataToSign = {
      applicationId: application._id.toString(),
      studentId: application.studentId.toString(),
      status: "Approved",
      bankDetails: application.encryptedBankDetails,
      idNumber: application.encryptedIdNumber,
      incomeDetails: application.encryptedIncomeDetails,
      instituteName: application.instituteName,
      examType: application.examType,
      academicDetails: application.encryptedAcademicDetails,
      aesKey: application.encryptedAesKey,
    };

    const signatureBase64 = digitalSignature.signData(dataToSign);
    const dataHash = digitalSignature.hashData(dataToSign);

    application.digitalSignature = signatureBase64;
    application.dataHash = dataHash;
    application.signedBy = req.user._id;
    application.signedAt = Date.now();

    // 3. Generate QR Code for the Application ID
    const qrCode = await qrUtil.generateQRCode(application._id.toString());

    res.json({
      message: "Scholarship Approved and Digitally Signed",
      signature: signatureBase64,
      qrCode,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Reject Scholarship Application
// @route   POST /api/admin/reject/:id
// @access  Private (Admin)
const rejectApplication = async (req, res) => {
  const { reason } = req.body;

  try {
    const application = await Application.findById(req.params.id);

    if (!application) {
      return res.status(404).json({ message: "Application not found" });
    }

    // Allow rejection from Submitted or Verified state?
    // Requirement says "Verified" or "Submitted".
    // Let's allow anytime before Approval.
    if (application.status === "Approved") {
      return res
        .status(400)
        .json({ message: "Cannot reject an already Approved application." });
    }

    application.status = "Rejected";
    application.rejectedBy = req.user._id;
    application.rejectedAt = Date.now();
    application.rejectionReason = reason || "No reason provided";

    await application.save();

    res.json({ message: "Application Rejected", application });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

module.exports = {
  getVerifiedApplications,
  approveScholarship,
  rejectApplication,
};
