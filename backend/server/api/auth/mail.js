const nodemailer = require("nodemailer");

// Utility function to send OTP via email
async function sendEmail(email, subject, text) {
  // Create transporter using Gmail's SMTP service
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER, // Your Gmail address from the .env file
      pass: process.env.EMAIL_PASS, // Your App Password from the .env file
    },
  });

  // Send the email
  await transporter.sendMail({
    from: process.env.EMAIL_USER, // Sender's email
    to: email, // Recipient's email
    subject: subject, // Subject of the email
    text: text, // Body content of the email (OTP in this case)
  });
}

module.exports = sendEmail;
