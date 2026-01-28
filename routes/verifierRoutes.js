const express = require('express');
const router = express.Router();
const { getAllApplications, verifyApplication } = require('../controllers/verifierController');
const { protect } = require('../middleware/authMiddleware');
const { authorize } = require('../middleware/roleMiddleware');

router.get('/applications', protect, authorize('verifier'), getAllApplications);
router.put('/applications/:id', protect, authorize('verifier'), verifyApplication);

module.exports = router;
