const express = require("express");
const router = express.Router();
const {
  submitApplication,
  getMyApplications,
  verifySignature,
  verifyByQR,
} = require("../controllers/applicationController");
const { protect } = require("../middleware/authMiddleware");
const { authorize } = require("../middleware/roleMiddleware");
const { validate } = require("../middleware/validateInput");
const { check } = require("express-validator");

router.post(
  "/",
  protect,
  authorize("student"),
  [
    check("bankDetails", "Bank Details are required").not().isEmpty(),
    check("idNumber", "Aadhar ID is required").not().isEmpty(),
    check("incomeDetails", "Income Details are required").not().isEmpty(),
    // New Academic Validations
    check("instituteName", "Institute Name is required").not().isEmpty(),
    check("currentGPA", "GPA must be between 0 and 10").isFloat({
      min: 0,
      max: 10,
    }),
    check("examType", "Exam Type must be JEE, NEET, or GATE").isIn([
      "JEE",
      "NEET",
      "GATE",
    ]),
    check("examScore", "Exam Score is required").isNumeric(),
    validate,
  ],
  submitApplication,
);

router.get("/my", protect, authorize("student"), getMyApplications);
router.get("/verify-signature/:id", protect, verifySignature);
router.get("/verify-qr/:id", verifyByQR);

module.exports = router;
