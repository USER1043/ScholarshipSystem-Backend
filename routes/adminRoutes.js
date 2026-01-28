const express = require("express");
const router = express.Router();
const {
  getVerifiedApplications,
  approveScholarship,
  rejectApplication,
  getAllUsers,
  removeStaff,
} = require("../controllers/adminController");

const { protect } = require("../middleware/authMiddleware");
const { authorize } = require("../middleware/roleMiddleware");

router.get(
  "/applications",
  protect,
  authorize("admin"),
  getVerifiedApplications,
);
router.post("/approve/:id", protect, authorize("admin"), approveScholarship);
router.post("/reject/:id", protect, authorize("admin"), rejectApplication);
router.get("/users", protect, authorize("admin"), getAllUsers);
router.delete("/staff/:id", protect, authorize("admin"), removeStaff);

module.exports = router;
