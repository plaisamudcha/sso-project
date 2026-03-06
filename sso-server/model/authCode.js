const mongoose = require("mongoose");

const authCodeSchema = new mongoose.Schema({
  code: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  clientId: String,
  redirectUri: String,
  expiresAt: Date,

  // OIDC fields
  scope: {
    type: String,
    default: "",
  },
  nonce: {
    type: String,
    default: null,
  },
  authTime: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model("AuthCode", authCodeSchema);
