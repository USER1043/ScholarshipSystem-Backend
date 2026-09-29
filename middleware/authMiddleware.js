const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { getJwtSecret, JWT_ALGORITHMS } = require('../config/jwt');

const protect = async (req, res, next) => {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            
            const decoded = jwt.verify(token, getJwtSecret(), { algorithms: JWT_ALGORITHMS });

            // Only session tokens may authenticate API calls (rejects e.g. invite tokens)
            if (decoded.type !== 'access') {
                return res.status(401).json({ message: 'Not authorized, invalid token type' });
            }
            
            // Check if user still exists
            req.user = await User.findById(decoded.id).select('-password');
            if (!req.user) {
                return res.status(401).json({ message: 'Not authorized, user not found' });
            }

            // Optional: Check if MFA was required and verified in the token payload
            // For this implementation, we will assume if they have a valid JWT, they passed MFA if enabled.
            
            next();
        } catch (error) {
            console.error(error);
            res.status(401).json({ message: 'Not authorized, token failed' });
        }
    } else {
        res.status(401).json({ message: 'Not authorized, no token' });
    }
};

module.exports = { protect };
