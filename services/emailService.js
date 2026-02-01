const nodemailer = require("nodemailer");

const sendEmail = async (to, subject, text) => {
  // Create a transporter using environment variables.
  // For this lab, we will log if credentials are missing.
  let transporter;
  {
    transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });
  }

  const mailOptions = {
    from:
      process.env.EMAIL_USER ||
      '"SafeApply: Secure Scholarship Application System" <system@example.com>',
    to,
    subject,
    text,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log(`Email sent to ${to}`);
  } catch (error) {
    console.error("Error sending email:", error);
    throw new Error("Email could not be sent");
  }
};

module.exports = { sendEmail };
