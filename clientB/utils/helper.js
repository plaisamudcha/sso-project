const { createApiClient } = require("../apis/apiClient");
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

function destroyLocalSession(req, res, redirectPath = "/") {
  req.logout(() => {
    req.session.destroy(() => {
      res.redirect(redirectPath);
    });
  });
}

async function ensureUpstreamSession(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return next();
  }

  const api = createApiClient(req);

  try {
    await api.get("/session-info");
    return next();
  } catch {
    return destroyLocalSession(req, res);
  }
}

function base64Url(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function createPkcePair() {
  const verifier = base64Url(crypto.randomBytes(64));
  const challenge = base64Url(
    crypto.createHash("sha256").update(verifier).digest(),
  );
  return { verifier, challenge };
}

function preparePkce(req, _res, next) {
  const { verifier, challenge } = createPkcePair();
  req.session.pkceVerifier = verifier;
  req.session.pkceChallenge = challenge;
  next();
}

module.exports = {
  destroyLocalSession,
  ensureUpstreamSession,
  base64Url,
  createPkcePair,
  preparePkce,
  verifyIdToken,
};
