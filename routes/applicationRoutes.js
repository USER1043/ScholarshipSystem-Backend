const express = require("express");
const router = express.Router();
const upload = require("../middleware/uploadMiddleware");
const {
  submitApplication,
  getMyApplications,
  verifySignature,
  verifyByQR,
  serveDocument,
} = require("../controllers/applicationController");
const { protect } = require("../middleware/authMiddleware");
const { authorize } = require("../middleware/roleMiddleware");
const { validate } = require("../middleware/validateInput");
const { check } = require("express-validator");

router.post(
  "/",
  protect,
  authorize("student"),
  upload.fields([
    { name: "incomeProof", maxCount: 1 },
    { name: "marksheet", maxCount: 1 },
    { name: "studentCertificate", maxCount: 1 },
  ]),
  [
    check("encryptedBankDetails", "Bank Details are required").not().isEmpty(),
    check("encryptedIdNumber", "Aadhar ID is required").not().isEmpty(),
    check("encryptedIncomeDetails", "Income Details are required").not().isEmpty(),
    check("encryptedAcademicDetails", "Academic Details are required").not().isEmpty(),
    check("encryptedAesKey", "Encryption key is required").not().isEmpty(),
    // Non-encrypted fields
    check("instituteName", "Institute Name is required").not().isEmpty(),
    check("examType", "Exam Type must be JEE, NEET, or GATE").isIn([
      "JEE",
      "NEET",
      "GATE",
    ]),
    validate,
  ],
  submitApplication,
);

router.get("/documents/:filename", protect, serveDocument);
router.get("/my", protect, authorize("student"), getMyApplications);
router.get("/verify-signature/:id", protect, verifySignature);
router.get("/verify-qr/:id", verifyByQR);

module.exports = router;
