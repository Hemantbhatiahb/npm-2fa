const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");

let emailConfig = {};
const configureEmail = (config) => {
  emailConfig = config;
};

let jwtSecret = "";

const setJwtSecret = (secret) => {
  jwtSecret = secret;
}

// Generate JWT Token
const generateToken = (payload, expiresIn = "1d") => {
  if (!jwtSecret) {
    throw new Error("JWT_SECRETKEY is missing! Please provide it in initAuth.");
  }

  return jwt.sign(payload, jwtSecret, { expiresIn });
};

const verifyToken = (token) => {
  return jwt.verify(token, jwtSecret);
}

// Send Email
const sendEmail = async (to, subject, html) => {
  if (!emailConfig.transportOptions) {
    throw new Error(
      "Email transport not configured. Call `configureEmail()` first."
    );
  }

  const transporter = nodemailer.createTransport(emailConfig.transportOptions);

  const mailOptions = {
    from: emailConfig.fromEmail || process.env.EMAIL_USER,
    to,
    subject,
    html,
  };

  return await transporter.sendMail(mailOptions);
};

module.exports = { configureEmail, generateToken, sendEmail, setJwtSecret, verifyToken};
