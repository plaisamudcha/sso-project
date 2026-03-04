const { envConfig } = require("../config/config");
const jwt = require("jsonwebtoken");

function generateToken(user) {
  return jwt.sign({ userId: user.id }, envConfig.ACCESS_SECRET, {
    expiresIn: "15m",
  });
}

function generateRefreshToken(sessionId) {
  return jwt.sign({ sessionId }, envConfig.REFRESH_SECRET, { expiresIn: "7d" });
}

module.exports = { generateRefreshToken, generateToken };
