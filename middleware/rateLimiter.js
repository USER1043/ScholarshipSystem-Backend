const rateLimit = require("express-rate-limit");

// General limiter
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again after 15 minutes",
  standardHeaders: true,
  legacyHeaders: false,
});

// Stricter limiter for login (brute force protection)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 5 login requests per windowMs
  message: "Too many login attempts, please try again after 15 minutes",
});

module.exports = { apiLimiter, loginLimiter };
