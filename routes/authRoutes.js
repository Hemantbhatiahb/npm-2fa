const express = require("express");
const {
  registerUser,
  loginUser,
  verifyEmail,
  enable2FA,
  verify2FA,
  disable2FA,
  resendVerificationEmail,
  getCurrentUser,
  updateUser,
  logoutUser,
  forgotPassword,
  resetPassword,
  changePassword,
} = require("../controllers/authController");
const auth = require("../middlewares/authMiddleware");

const router = express.Router();

router.post("/register", registerUser);
router.post("/resend-verification", resendVerificationEmail);
router.post(
  "/login",
  rateLimiter(10 * 60 * 1000, 5, "Too many login attempts. Try again later."),
  loginUser
);
router.get("/verify-email", verifyEmail);

router.post("/enable-2fa", auth, enable2FA);
router.post("/disable-2fa", auth, disable2FA);
router.post("/verify-2fa", auth, verify2FA);

router.get("/current-user", auth, getCurrentUser);
router.put("/update-user/:userId", updateUser);
router.post("/logout", logoutUser);

router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);
router.put("/change-password", auth, changePassword);

module.exports = router;
