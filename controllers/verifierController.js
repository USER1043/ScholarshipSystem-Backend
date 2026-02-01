const Application = require("../models/Application");
const aesUtil = require("../security/encryption/aesUtil");
const rsaUtil = require("../security/encryption/rsaUtil");

// @desc    Get all applications (for Verifier)
// @route   GET /api/verifier/applications
// @access  Private (Verifier)
const getAllApplications = async (req, res) => {
  try {
    const applications = await Application.find()
      .populate("studentId", "username email")
      .populate("documents");

    // Decrypt data for verification
    // Decrypt AES Key for Client-Side Decryption
    const decryptedApplications = applications.map((app) => {
      try {
        const aesKeyBuffer = rsaUtil.decryptWithPrivateKey(app.encryptedAesKey);
        const aesKey = aesKeyBuffer.toString("hex");

        return {
          _id: app._id,
          student: app.studentId,
          fullName: app.fullName,
          status: app.status,
          verificationStatus: app.verificationStatus,
          verifierComments: app.verifierComments,

          // Pass Encrypted Data + Key
          encryptedBankDetails: app.encryptedBankDetails,
          encryptedIdNumber: app.encryptedIdNumber,
          encryptedIncomeDetails: app.encryptedIncomeDetails,
          encryptedAcademicDetails: app.encryptedAcademicDetails,

          decryptedAesKey: aesKey,

          // Legacy / Plain text fallback
          instituteName: app.instituteName || "N/A",
          examType: app.examType || "N/A",

          createdAt: app.createdAt,
          documents: app.documents,
        };
      } catch (err) {
        return {
          _id: app._id,
          student: app.studentId,
          fullName: app.fullName,
          status: app.status,
          error: "Failed to process security keys",
        };
      }
    });

    res.json(decryptedApplications);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Update verification status
// @route   PUT /api/verifier/applications/:id
// @access  Private (Verifier)
const verifyApplication = async (req, res) => {
  const { status, comments } = req.body;

  try {
    const application = await Application.findById(req.params.id);

    if (!application) {
      return res.status(404).json({ message: "Application not found" });
    }

    // Role-Based Restriction: Verifiers can ONLY set status to 'Verified'
    if (status !== "Verified") {
      return res
        .status(403)
        .json({ message: "Verifiers can only mark applications as Verified." });
    }

    application.status = "Verified";
    application.verifierComments = comments;

    await application.save();
    res.json({ message: "Application marked as Verified", application });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

module.exports = { getAllApplications, verifyApplication };
