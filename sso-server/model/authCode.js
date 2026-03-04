const mongoose = require("mongoose");

const authCodeSchema = new mongoose.Schema({
  code: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  clientId: String,
  redirectUri: String,
  expiresAt: Date,
});

module.exports = mongoose.model("AuthCode", authCodeSchema);
