// Libraries
const express = require("express");
const session = require("express-session");
const { RedisStore } = require("connect-redis");
const { v4: uuidv4 } = require("uuid");
const crypto = require('crypto');
const axios = require('axios');

// Utilities
const envConfig = require("./configs/config");
const { createApiClient } = require("./apis/apiClient");
const {
  destroyLocalSession,
  ensureUpstreamSession,
} = require("./utils/helper");
const redisClient = require('./configs/redis')
const { buildAuthorizationUrl, parseJwt, validateIdToken } = require('./configs/oidc')

// Configurations
require("./configs/redis");

const app = express();

const isProd = envConfig.NODE_ENV === "production";
app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(
  session({
    name: "clientC.sid",
    store: new RedisStore({ client: redisClient }),
    secret: envConfig.APP_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: isProd,
      sameSite: isProd ? "none" : "lax",
      httpOnly: true,
    },
  }),
);

app.use((req, _res, next) => {
  if (!req.session.browserId) {
    req.session.browserId = uuidv4();
  }
  next();
})

app.use((req, _res, next) => {
  req.user = req.session.user || null;
  next();
});

app.get("/", ensureUpstreamSession, (req, res) => {
  if (!req.session.user) {
    return res.send(`
      <h1>ClientC</h1>
      <a href='/login'>Login with SSO</a>
      <p>or</p>
      <a href='/login-oidc'>Login with OIDC</a>
      `);
  }

  console.log('req.user', req.user)

  return res.send(`
    <h1>ClientC</h1>
    <p>User ID: ${req.session.user?.sub || req.session.user?.idTokenClaims?.sub}</p>
    <p>Session ID: ${req.user.sessionId}</p>
    <a href='/me'>View Profile</a>
    <a href='/user-info'>View User Info</a>
    <a href='/logout'>Logout this device</a>
    <a href='/logout-all'>Logout all devices</a>
    `);
});

app.get("/login", async (req, res) => {
  const state = crypto.randomUUID();
  const codeVerifier = crypto.randomBytes(64).toString('base64url');

  req.session.oauthState = state;
  req.session.pkceVerifier = codeVerifier;

  const redirectUrl = await buildAuthorizationUrl({
    scope: "",
    state,
    codeVerifier,
  });

  req.session.save(() => res.redirect(redirectUrl));
});

app.get("/login-oidc", async (req, res) => {
  const state = crypto.randomUUID();
  const nonce = crypto.randomUUID();
  const codeVerifier = crypto.randomBytes(64).toString('base64url');

  req.session.oauthState = state;
  req.session.oidcNonce = nonce;
  req.session.pkceVerifier = codeVerifier;

  const redirectUrl = await buildAuthorizationUrl({
    scope: "openid email profile",
    state,
    nonce,
    codeVerifier,
  });

  req.session.save(() => res.redirect(redirectUrl));
});

app.get('/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!code || !state) {
    return res.status(400).send("Missing code or state");
  }

  if (!req.session.oauthState || state !== req.session.oauthState) {
    return res.status(400).send("Invalid state");
  }

  try {
    const tokenResponse = await axios.post(`${envConfig.SSO_SERVER}/token`, {
      grant_type: "authorization_code",
      code,
      client_id: envConfig.CLIENT_ID,
      client_secret: envConfig.CLIENT_SECRET,
      redirect_uri: envConfig.REDIRECT_URI,
      deviceId: req.session.browserId,
      deviceType: 'browser',
      code_verifier: req.session.pkceVerifier,
    });

    const tokenPayload = parseJwt(tokenResponse.data.access_token);
    const nonce = req.session.oidcNonce || null;
    const isOidcFlow = Boolean(nonce);

    if (isOidcFlow && !tokenResponse.data.id_token) {
      return res.status(400).send("Missing ID token");
    }

    let idTokenClaims = null;
    if (tokenResponse.data.id_token) {
      idTokenClaims = await validateIdToken(tokenResponse.data.id_token, nonce);
    }

    req.session.user = {
      sub: tokenPayload.sub,
      sessionId: tokenPayload.sessionId,
      scope: tokenPayload.scope || '',
      accessToken: tokenResponse.data.access_token,
      refreshToken: tokenResponse.data.refresh_token,
      idToken: tokenResponse.data.id_token || null,
      idTokenClaims,
    };

    delete req.session.oauthState;
    delete req.session.oidcNonce;
    delete req.session.pkceVerifier;

    return res.redirect('/');
  } catch (err) {
    console.error('clientB callback error:', err.response?.data || err.message);
    return res.status(500).send("Authentication failed");
  }
})

app.get("/me", ensureUpstreamSession, (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  return res.json(req.user);
});

app.get("/protected-check", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const api = createApiClient(req);

  try {
    const result = await api.post("/logout");

    return res.json({ message: "Protected call success", result: result.data });
  } catch (err) {
    return res.status(500).json({
      message: "Protected call failed",
      error: err.response?.data || err.message,
    });
  }
});

app.get("/user-info", ensureUpstreamSession, async (req, res) => {
  const api = createApiClient(req);

  try {
    const response = await api.get("/userinfo");
    return res.send(`
      <p>User Info:</p>
      <p>User ID: ${response.data?.sub}</p>
      <p>Email: ${response.data?.email}</p>
      <p>Name: ${response.data?.name}</p>
      <p>given_name: ${response.data?.given_name}</p>
      <p>family_name: ${response.data?.family_name}</p>
      <p>Picture: <img src="${response.data?.picture}" alt="User Picture" width="100"/></p>
      `)
  } catch (err) {
    const upstream = err.response?.data || err.message;
    console.error("Error fetching user info:", upstream);
    return res
      .status(err.response?.status || 500)
      .json({ message: "Failed to fetch user info", error: upstream });
  }
});

app.get("/logout", async (req, res) => {
  if (!req.session.user) {
    return destroyLocalSession(req, res);
  }

  const api = createApiClient(req);

  try {
    await api.post("/logout");
  } catch (err) {
    console.error("SSO logout error:", err.message);
  }

  return destroyLocalSession(req, res);
});

app.get("/logout-all", async (req, res) => {
  if (!req.session.user) {
    return destroyLocalSession(req, res);
  }

  const api = createApiClient(req);

  try {
    await api.post("/logout-all");
  } catch (err) {
    console.error("SSO global logout error:", err.message);
  }

  return destroyLocalSession(req, res);
});

app.listen(envConfig.PORT, () => {
  console.log(`Client B running on port ${envConfig.PORT}`);
});