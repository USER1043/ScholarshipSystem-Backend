const { validationResult } = require('express-validator');

// Generic error handler for validation results
const validate = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
};

// We can add specific sanitize functions here if needed, 
// usually done in the route definition using check().escape()

module.exports = { validate };
