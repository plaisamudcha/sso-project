const mongoose = require("mongoose");
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  sub: {
    type: String,
    unique: true,
    default: crypto.randomUUID(),
  },

  email: {
    type: String,
    unique: true,
    required: true,
    lowercase: true,
    index: true,
  },

  emailVerified: {
    type: Boolean,
    default: false,
  },

  password: {
    type: String,
    required: true,
  },

  name: String,
  givenName: String,
  familyName: String,
  picture: String,

  isActive: {
    type: Boolean,
    default: true,
  },

  loginAttempts: {
    type: Number,
    default: 0
  },

  lockUntil: Date,

  lastLoginAt: Date,

  passwordChangedAt: Date,
}, {
  timestamps: true,
});

module.exports = mongoose.model("User", userSchema);
