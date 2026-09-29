// Transactional email via the Brevo HTTP API
// https://developers.brevo.com/reference/sendtransacemail
const BREVO_API_URL = "https://api.brevo.com/v3/smtp/email";
const REQUEST_TIMEOUT_MS = 10000;

const sendEmail = async (to, subject, text) => {
  const apiKey = process.env.BREVO_API_KEY;
  const senderEmail = process.env.BREVO_SENDER_EMAIL; // Must be a verified sender in Brevo
  const senderName = process.env.BREVO_SENDER_NAME || "SafeApply";

  if (!apiKey || !senderEmail) {
    console.error("Error sending email: BREVO_API_KEY and BREVO_SENDER_EMAIL must be set");
    throw new Error("Email could not be sent");
  }

  try {
    const response = await fetch(BREVO_API_URL, {
      method: "POST",
      headers: {
        "api-key": apiKey,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({
        sender: { name: senderName, email: senderEmail },
        to: [{ email: to }],
        subject,
        textContent: text,
      }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!response.ok) {
      const details = await response.text();
      throw new Error(`Brevo API responded ${response.status}: ${details}`);
    }

    console.log(`Email sent to ${to}`);
  } catch (error) {
    console.error("Error sending email:", error.message);
    throw new Error("Email could not be sent");
  }
};

module.exports = { sendEmail };
