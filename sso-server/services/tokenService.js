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

function verifyToken(token) {
  return jwt.verify(token, envConfig.ACCESS_SECRET);
}

module.exports = { generateRefreshToken, generateToken, verifyToken };
