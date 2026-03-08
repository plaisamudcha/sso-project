const { rateLimit } = require("express-rate-limit");

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: {
    message: "Too many login attempts. Try again later",
  },
});

const tokenLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: {
    message: "Too many token requests",
  },
});

module.exports = { loginLimiter, tokenLimiter, refreshLimiter };
