const { envConfig } = require("../config/config");
const { jwks } = require("../config/oidcKeys");

function openIdConfiguration(_req, res) {
  const issuer = envConfig.ISSUER;

  return res.json({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["public"],
    code_challenge_methods_supported: ["S256"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: ["openid", "profile", "email"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
    claims_supported: [
      "sub",
      "email",
      "email_verified",
      "name",
      "given_name",
      "family_name",
      "picture",
      "auth_time",
      "iss",
      "aud",
      "nonce",
    ],
  });
}

function jwksEndpoint(_req, res) {
  return res.json(jwks);
}

module.exports = {
  openIdConfiguration,
  jwksEndpoint,
};
