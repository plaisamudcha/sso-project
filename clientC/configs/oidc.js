const envConfig = require('./config');
const crypto = require('crypto');
const axios = require('axios');
const jwt = require('jsonwebtoken');

let openIdClientLib;
let oidcConfigPromise;
const jwksCache = new Map();

async function getOpenIdClientLib() {
  if (!openIdClientLib) {
    openIdClientLib = await import('openid-client');
  }
  return openIdClientLib;
}

async function getOidcConfig() {
  if (!oidcConfigPromise) {
    oidcConfigPromise = (async () => {
      const client = await getOpenIdClientLib();
      const discoveryOptions =
        envConfig.NODE_ENV === "production"
          ? undefined
          : { execute: [client.allowInsecureRequests] };

      const config = await client.discovery(
        new URL(envConfig.SSO_SERVER),
        envConfig.CLIENT_ID,
        envConfig.CLIENT_SECRET,
        undefined,
        discoveryOptions,
      );

      // Keep HTTP disabled in production. Allow local http:// issuer only in dev.
      if (envConfig.NODE_ENV !== "production") {
        client.allowInsecureRequests(config);
      }

      return config;
    })();
  }

  return oidcConfigPromise;
}

async function buildAuthorizationUrl({
  scope,
  state,
  nonce,
  codeVerifier,
}) {
  const client = await getOpenIdClientLib();
  const config = await getOidcConfig();

  const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);

  const params = {
    redirect_uri: envConfig.REDIRECT_URI,
    response_type: "code",
    scope,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  };

  if (nonce) {
    params.nonce = nonce;
  }

  return client.buildAuthorizationUrl(config, params).href;
}

async function validateIdToken(idToken, nonce) {
  const decoded = jwt.decode(idToken, { complete: true });
  if (!decoded?.header?.kid) {
    throw new Error('Invalid ID token header');
  }

  const jwksUri = `${envConfig.SSO_SERVER.replace(/\/+$/, '')}/.well-known/jwks.json`;
  const cached = jwksCache.get(jwksUri);
  let jwks = cached?.expiresAt > Date.now() ? cached.value : null;

  if (!jwks) {
    const response = await axios.get(jwksUri, { timeout: 5000 });
    jwks = response.data?.keys;
    if (!Array.isArray(jwks) || jwks.length === 0) {
      throw new Error('JWKS response has no signing keys');
    }

    jwksCache.set(jwksUri, {
      value: jwks,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });
  }

  const jwk = jwks.find((k) => k.kid === decoded.header.kid && k.kty === 'RSA');
  if (!jwk) {
    throw new Error(`No matching JWK found for kid=${decoded.header.kid}`);
  }

  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const claims = jwt.verify(idToken, publicKey, {
    algorithms: ['RS256'],
    issuer: envConfig.SSO_SERVER,
    audience: envConfig.CLIENT_ID,
  });

  if (nonce && claims.nonce !== nonce) {
    throw new Error('ID token nonce mismatch');
  }

  return claims;
}

function parseJwt(token) {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
}

module.exports = {
  buildAuthorizationUrl,
  parseJwt,
  getOidcConfig,
  validateIdToken
}