const mongoose = require("mongoose");

const OAuthClientSchema = new mongoose.Schema({
  clientId: {
    type: String,
    unique: true,
    required: true,
  },
  clientSecret: {
    type: String,
    default: null,
  },
  name: String,
  redirectUris: [String],

  // OIDC/OAuth metadata
  allowedScopes: {
    type: [String],
    default: ["openid", "profile", "email"],
  },
  grantTypes: {
    type: [String],
    default: ["authorization_code", "refresh_token"],
  },

  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model("OAuthClient", OAuthClientSchema);
