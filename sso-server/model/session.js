const mongoose = require("mongoose");

const sessionSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    deviceId: String,
    deviceType: { type: String, enum: ["mobile", "browser"] },
    refreshToken: String,
    isActive: { type: Boolean, default: true },
  },
  {
    timestamps: true,
  },
);

module.exports = mongoose.model("Session", sessionSchema);
