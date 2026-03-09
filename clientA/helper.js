const crypto = require("crypto");
const axios = require("axios");
const jwt = require("jsonwebtoken");

const jwksCache = new Map();

async function getJwks(issuer) {
  const cacheKey = `${issuer}/.well-known/jwks.json`;
  const cached = jwksCache.get(cacheKey);

  if (cached && cached.expiresAt > Date.now()) {
    return cached.value;
  }

  const response = await axios.get(cacheKey, { timeout: 5000 });
  const keys = response.data?.keys;

  if (!Array.isArray(keys) || keys.length === 0) {
    throw new Error("JWKS response has no signing keys");
  }

  jwksCache.set(cacheKey, {
    value: keys,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });

  return keys;
}

function selectSigningJwk(jwks, kid) {
  if (!kid) {
    throw new Error("ID token header is missing kid");
  }

  const key = jwks.find((k) => k.kid === kid && k.kty === "RSA");
  if (!key) {
    throw new Error(`No matching JWK found for kid=${kid}`);
  }

  return key;
}

async function verifyIdToken(idToken, { issuer, audience, nonce }) {
  const decoded = jwt.decode(idToken, { complete: true });
  if (!decoded || !decoded.header) {
    throw new Error("Invalid ID token format");
  }

  const jwks = await getJwks(issuer);
  const jwk = selectSigningJwk(jwks, decoded.header.kid);
  const publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });

  const claims = jwt.verify(idToken, publicKey, {
    algorithms: ["RS256"],
    issuer,
    audience,
  });

  if (nonce && claims.nonce !== nonce) {
    throw new Error("ID token nonce mismatch");
  }

  return claims;
}

function base64url(buffer) {
  return buffer
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function createPkcePair() {
  const verifier = base64url(crypto.randomBytes(64));
  const challenge = base64url(
    crypto.createHash("sha256").update(verifier).digest(),
  );
  return { verifier, challenge };
}

function parseJwt(token) {
  return JSON.parse(Buffer.from(token.split(".")[1], "base64").toString());
}

module.exports = { parseJwt, createPkcePair, base64url, verifyIdToken };
