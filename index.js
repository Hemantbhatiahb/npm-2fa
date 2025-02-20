const express = require("express");
const mongoose = require("mongoose");
const authRoutes = require("./routes/authRoutes");
const { configureEmail, setJwtSecret } = require("./utils/emailService");

let mongoURI = "";
let jwtSecret = "";

// Function to initialize authentication package
const initAuth = ({ mongoUrl, jwtSecretKey, emailConfig }) => {
  if (!mongoUrl || !jwtSecretKey) {
    throw new Error("MongoDB URL and JWT secret are required.");
  }

  mongoURI = mongoUrl;
  jwtSecret = jwtSecretKey;

  // Configure email service
  configureEmail(emailConfig || {});
  setJwtSecret(jwtSecret);

  // Connect to MongoDB
  mongoose
    .connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Connected to MongoDB"))
    .catch((err) => console.error("MongoDB connection error:", err));

  // Create an Express Router for authentication
  const router = express.Router();
  router.use(express.json());
  router.use("/auth", authRoutes);

  return router;
};

module.exports = { initAuth };
