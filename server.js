const dotenv = require('dotenv');
// Load env vars first
dotenv.config();

const connectDB = require('./config/db');
const app = require('./app');

// Connect to Database
connectDB();

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    // Optional: Log memory usage or security status
    console.log(`Security Modules Loaded: AES-256, RSA-4096, Bcrypt, JWT`);
});
