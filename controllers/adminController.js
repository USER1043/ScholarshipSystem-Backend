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
    const applications = await Application.find().populate(
      "studentId",
      "email username",
    );

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

    if (application.verificationStatus !== "verified") {
      return res
        .status(400)
        .json({ message: "Application not verified by staff yet" });
    }

    // 1. Update status
    application.status = "approved";
    await application.save();

    // 2. Create Digital Signature
    // We sign a hash of critical data: StudentID + ApplicationID + Status + Sensitive Encrypted Data
    // Ideally we sign the DECRYPTED data (what the admin saw/verified) or the ENCRYPTED data (integrity of storage).
    // Let's sign the ENCRYPTED content to verify DB integrity, OR decrypted to verify logical data.
    // Requirement says "Hash the complete application data".
    // Better to sign the immutable decrypted values (e.g. Identity/Bank) + Status.
    // However, we only have encrypted components here.
    // Let's sign the `encryptedAesKey` + `status` + `studentId` as a proxy for the whole record,
    // OR sign the specific encrypted fields if we want to ensure *those* bits haven't flipped.
    // Let's sign the canonical object of important fields.

    const dataToSign = {
      applicationId: application._id.toString(),
      studentId: application.studentId.toString(),
      status: "approved",
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

    await application.save();

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

module.exports = { getVerifiedApplications, approveScholarship };
