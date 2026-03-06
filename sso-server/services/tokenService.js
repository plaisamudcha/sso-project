const { envConfig } = require("../config/config");
const jwt = require("jsonwebtoken");

function generateToken(payload) {
  return jwt.sign(payload, envConfig.ACCESS_SECRET, { expiresIn: "15m" });
}

function generateRefreshToken(sessionId) {
  return jwt.sign({ sessionId }, envConfig.REFRESH_SECRET, { expiresIn: "7d" });
}

function generateIdToken(payload) {
  return jwt.sign(payload, envConfig.ID_TOKEN_SECRET, { expiresIn: "15m" });
}

function verifyToken(token) {
  return jwt.verify(token, envConfig.ACCESS_SECRET);
}

function verifyRefreshToken(token) {
  return jwt.verify(token, envConfig.REFRESH_SECRET);
}

module.exports = {
  generateRefreshToken,
  generateToken,
  generateIdToken,
  verifyToken,
  verifyRefreshToken,
};
