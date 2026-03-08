const fs = require("fs");
const crypto = require("crypto");
const { envConfig } = require("./config");

const privateKeyPem = fs.readFileSync(envConfig.OIDC_PRIVATE_KEY_PATH, "utf8");
const publicKeyPem = fs.readFileSync(envConfig.OIDC_PUBLIC_KEY_PATH, "utf8");

const publicJwk = crypto
  .createPublicKey(publicKeyPem)
  .export({ format: "jwk" });

const jwks = {
  keys: [
    {
      ...publicJwk,
      use: "sig",
      kid: envConfig.OIDC_KID,
      alg: "RS256",
    },
  ],
};

module.exports = {
  privateKeyPem,
  jwks,
  kid: envConfig.OIDC_KID,
};
