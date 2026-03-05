const mongoose = require("mongoose");

const OAuthClientSchema = new mongoose.Schema({
  clientId: {
    type: String,
    unique: true,
    required: true,
  },
  clientSecret: {
    type: String,
    required: true,
  },
  name: String,

  redirectUris: [String],

  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model("OAuthClient", OAuthClientSchema);
