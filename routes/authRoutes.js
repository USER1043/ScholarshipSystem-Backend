const express = require("express");
const router = express.Router();
const {
  registerUser,
  loginUser,
  verifyOTP,
  resendOTP,
  onboardEmployee,
  verifyTOTP,
  completeOnboarding,
  checkOtpStatus,
} = require("../controllers/authController");
const { loginLimiter } = require("../middleware/rateLimiter");
const { protect } = require("../middleware/authMiddleware");
const { authorize } = require("../middleware/roleMiddleware");
const { check } = require("express-validator");
const { validate } = require("../middleware/validateInput");

router.post(
  "/register",
  [
    check("username", "Official Name is required").not().isEmpty().escape(),
    check("email", "Please include a valid email").isEmail().normalizeEmail(),
    check("password", "Password must be 6 or more characters").isLength({
      min: 6,
    }),
    validate,
  ],
  registerUser,
);

router.post(
  "/login",
  loginLimiter,
  [
    check("email", "Please include a valid email").isEmail().normalizeEmail(),
    check("password", "Password is required").exists(),
    validate,
  ],
  loginUser,
);

router.post(
  "/verify-otp",
  [
    check("userId", "User ID is required").not().isEmpty(),
    check("otp", "OTP is required").not().isEmpty(),
    validate,
  ],
  verifyOTP,
);

router.post(
  "/verify-totp",
  [
    check("userId", "User ID is required").not().isEmpty(),
    check("token", "Authenticator code is required").not().isEmpty(),
    validate,
  ],
  verifyTOTP,
);

router.post(
  "/resend-otp",
  [check("userId", "User ID is required").not().isEmpty(), validate],
  resendOTP,
);

// Protected Admin Route for Employee Onboarding
router.post(
  "/otp-status",
  [check("userId", "User ID is required").not().isEmpty(), validate],
  checkOtpStatus,
);

// Protected Admin Route for Employee Onboarding
router.post(
  "/onboard",
  protect,
  authorize("admin"),
  [
    check("username", "Username is required").not().isEmpty().escape(),
    check("email", "Valid email is required").isEmail().normalizeEmail(),
    check("role", "Role is required").isIn(["verifier", "admin"]),
    validate,
  ],
  onboardEmployee,
);

router.post(
  "/complete-invite",
  [
    check("token", "Token is required").not().isEmpty(),
    check(
      "password",
      "Password must be 8+ characters with special chars",
    ).isStrongPassword({
      minLength: 8,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1,
    }),
    validate,
  ],
  completeOnboarding,
);

module.exports = router;
