const crypto = require("crypto");

function base64url(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function isValidCodeVerifier(verifier) {
  return (
    typeof verifier === "string" && /^[A-Za-z0-9._~-]{43,128}$/.test(verifier)
  );
}

function createS256CodeChallenge(verifier) {
  return base64url(crypto.createHash("sha256").update(verifier).digest());
}

function buildIdTokenClaims(user, scopes, baseClaims) {
  const claims = { ...baseClaims };

  if (scopes.has("email")) {
    claims.email = user.email;
    claims.email_verified = Boolean(user.emailVerified);
  }

  if (scopes.has("profile")) {
    if (user.name) claims.name = user.name;
    if (user.givenName) claims.given_name = user.givenName;
    if (user.familyName) claims.family_name = user.familyName;
    if (user.picture) claims.picture = user.picture;
  }

  return claims;
}

function buildUserInfoClaims(user, scopes) {
  const claims = { sub: user.sub };

  if (scopes.has("email")) {
    claims.email = user.email;
    claims.email_verified = Boolean(user.emailVerified);
  }

  if (scopes.has("profile")) {
    if (user.name) claims.name = user.name;
    if (user.givenName) claims.given_name = user.givenName;
    if (user.familyName) claims.family_name = user.familyName;
    if (user.picture) claims.picture = user.picture;
  }

  return claims;
}

module.exports = {
  isValidCodeVerifier,
  createS256CodeChallenge,
  buildIdTokenClaims,
  buildUserInfoClaims,
};
