const express = require("express");
const {
  register,
  registerOAuth,
  listOAuth,
  authorize,
  login,
  token,
  logout,
  logoutAll,
  sessionInfo,
  userInfo,
} = require("../controllers/authController");
const { verifySession, requireAdmin } = require("../midlleware/auth");
const { loginLimiter, tokenLimiter } = require("../midlleware/rateLimit");

const router = express.Router();

router.post("/register", register);
router.post("/register-oauth-client", requireAdmin, registerOAuth);
router.get("/oauth-client", requireAdmin, listOAuth);
router.get("/authorize", authorize);
router.post("/login", loginLimiter, login);
router.post("/token", tokenLimiter, token);
router.post("/logout", verifySession, logout);
router.post("/logout-all", verifySession, logoutAll);
router.get("/session-info", verifySession, sessionInfo);
router.get("/userinfo", verifySession, userInfo);

module.exports = router;
