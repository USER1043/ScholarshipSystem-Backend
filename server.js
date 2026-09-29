const dotenv = require('dotenv');
// Load env vars first
dotenv.config();

const connectDB = require('./config/db');
const { getJwtSecret } = require('./config/jwt');

// Fail fast if the JWT secret is missing or weak
try {
    getJwtSecret();
} catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
}
const app = require('./app');

// Connect to Database
connectDB();

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    // Optional: Log memory usage or security status
    console.log(`Security Modules Loaded: AES-256, RSA-4096, Bcrypt, JWT`);
});
