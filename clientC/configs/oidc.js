const envConfig = require('./config');

let openIdClientLib;
let oidcConfigPromise;

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
      return client.discovery(
        new URL(envConfig.SSO_SERVER),
        envConfig.CLIENT_ID,
        envConfig.CLIENT_SECRET,
      );
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
  const client = await getOpenIdClientLib();
  const config = await getOidcConfig();

  const claims = await client.getValidatedIdTokenClaims(config, idToken, nonce ? { expectedNonce: nonce } : undefined);
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