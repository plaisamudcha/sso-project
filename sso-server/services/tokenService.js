const { envConfig } = require("../config/config");
const jwt = require("jsonwebtoken");
const { kid, privateKeyPem } = require("../config/oidcKeys");

function generateToken(payload) {
  return jwt.sign(payload, envConfig.ACCESS_SECRET, { expiresIn: "15m" });
}

function generateRefreshToken(sessionId) {
  return jwt.sign({ sessionId }, envConfig.REFRESH_SECRET, { expiresIn: "7d" });
}

function generateIdToken(payload) {
  return jwt.sign(payload, privateKeyPem, {
    algorithm: "RS256",
    expiresIn: "15m",
    keyid: kid,
  });
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
