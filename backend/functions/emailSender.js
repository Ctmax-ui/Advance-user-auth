const nodemailer = require("nodemailer");
require("dotenv").config();

// Create a reusable transporter object
const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.APP_EMAIL,
    pass: process.env.APP_PASSWORD,
  },
});

/**
 * Send an email with the given options
 * @param {string} to - The recipient's email address
 * @param {string} subject - The subject of the email
 * @param {string} html - The HTML content of the email
 * @returns {Promise} - A promise that resolves when the email is sent
 */
const sendEmail = async (to, subject, html) => {
  try {
    const mailOptions = {
      from: process.env.APP_EMAIL,
      to,
      subject,
      html,
    };

    await transporter.sendMail(mailOptions);
    console.log(`Email sent to ${to}`);
  } catch (err) {
    console.error(`Error sending email to ${to}:`, err);
    throw new Error("Email sending failed.");
  }
};

module.exports = sendEmail;
