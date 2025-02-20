const express = require("express");
const {
  registerUser,
  loginUser,
  verifyEmail,
  enable2FA,
  verify2FA,
  disable2FA,
  resendVerificationEmail,
} = require("../controllers/authController");
const auth = require("../middlewares/authMiddleware");

const router = express.Router();


router.post("/register", registerUser);
router.post("/resend-verification", resendVerificationEmail);
router.post("/login", loginUser);
router.get("/verify-email", verifyEmail);

router.post("/enable-2fa", auth, enable2FA);
router.post("/disable-2fa",auth, disable2FA);
router.post("/verify-2fa", auth, verify2FA);

module.exports = router;
