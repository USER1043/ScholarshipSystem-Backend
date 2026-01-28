const mongoose = require("mongoose");
const User = require("../models/User");
const dotenv = require("dotenv");
const path = require("path");

dotenv.config({ path: path.join(__dirname, "../.env") });

const resetAdmin = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    const res = await User.deleteOne({ email: process.env.SUPER_ADMIN_EMAIL });
    console.log("Deleted Admin Count:", res.deletedCount);
    process.exit();
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
};

resetAdmin();
