// Libraries
const express = require("express");
const axios = require("axios");
const session = require("express-session");
const { RedisStore } = require("connect-redis");
const { createClient } = require("redis");
const { v4: uuidv4 } = require("uuid");

// Utilities
const { createApiClient } = require("./services/apiClient");
const { envConfig } = require("./config");
const { createPkcePair, parseJwt, verifyIdToken } = require("./helper");

async function ensureUpstreamSession(req, res, next) {
  if (!req.session.user?.accessToken) {
    return next();
  }

  const api = createApiClient(req);

  try {
    await api.get("/session-info");
    return next();
  } catch {
    delete req.session.user;
    return next();
  }
}

const app = express();
const redisClient = createClient({
  url: envConfig.REDIS_URL,
});

redisClient.connect().catch(console.error);

const isProd = envConfig.NODE_ENV === "production";
app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(
  session({
    name: "clientA.sid",
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
app.use((req, res, next) => {
  if (!req.session.browserId) {
    req.session.browserId = uuidv4();
  }
  next();
});

app.set("view engine", "ejs");

app.get("/", ensureUpstreamSession, (req, res) => {
  if (!req.session.user) {
    return res.send(`
      <h1>ClientA</h1>
      <a href='/login'>Login with SSO</a>
      <p>or</p>
      <a href='/login-oidc'>Login with OIDC</a>
      `);
  }

  return res.send(`
    <h1>ClientA</h1>
    <p>User ID: ${req.session.user.sub}</p>
    <p>Session ID: ${req.session.user.sessionId}</p>
    <p>Scope: ${req.session.user.scope || "(none)"}</p>
    <p>Login Type: ${req.session.user.idTokenClaims ? "OIDC" : "OAuth"}</p>
    <a href='/profile'>View Profile</a>
    <a href='/user-info'>View User Info</a>
    <a href='/logout'>Logout this device</a>
    <a href='/logout-all'>Logout all devices</a>
    `);
});

app.get("/login", (req, res) => {
  const state = uuidv4();
  const { challenge, verifier } = createPkcePair();
  req.session.oauthState = state;
  req.session.pkceVerifier = verifier;

  const params = new URLSearchParams({
    client_id: envConfig.CLIENT_ID,
    redirect_uri: envConfig.REDIRECT_URI,
    response_type: "code",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  const url = `${envConfig.SSO_SERVER}/authorize?${params.toString()}`;
  req.session.save(() => {
    res.redirect(url);
  });
});

app.get("/login-oidc", (req, res) => {
  const state = uuidv4();
  const nonce = uuidv4();
  const { challenge, verifier } = createPkcePair();
  req.session.oauthState = state;
  req.session.oauthNonce = nonce;
  req.session.pkceVerifier = verifier;
  const params = new URLSearchParams({
    client_id: envConfig.CLIENT_ID,
    redirect_uri: envConfig.REDIRECT_URI,
    response_type: "code",
    scope: "openid email",
    nonce,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  const url = `${envConfig.SSO_SERVER}/authorize?${params.toString()}`;
  req.session.save(() => {
    res.redirect(url);
  });
});

app.get("/callback", async (req, res) => {
  const { code, state } = req.query;
  const expectedNonce = req.session.oauthNonce || null;
  const expectsOidc = Boolean(expectedNonce);

  if (!code || !state) {
    return res.status(400).send("Invalid callback parameters");
  }

  if (!req.session.oauthState || req.session.oauthState !== state) {
    return res.status(400).send("Invalid OAuth state");
  }

  delete req.session.oauthState;

  try {
    let idTokenClaims = null;
    const tokenResponse = await axios.post(`${envConfig.SSO_SERVER}/token`, {
      grant_type: "authorization_code",
      code,
      client_id: envConfig.CLIENT_ID,
      client_secret: envConfig.CLIENT_SECRET,
      redirect_uri: envConfig.REDIRECT_URI,
      deviceId: req.session.browserId,
      deviceType: "browser",
      code_verifier: req.session.pkceVerifier,
    });

    console.log("Token response:", tokenResponse.data);

    if (expectsOidc && !tokenResponse.data.id_token) {
      throw new Error("Missing id_token for OIDC login");
    }

    if (tokenResponse.data.id_token) {
      idTokenClaims = await verifyIdToken(tokenResponse.data.id_token, {
        issuer: envConfig.SSO_SERVER,
        audience: envConfig.CLIENT_ID,
        nonce: expectedNonce,
      });
      console.log("verified id_token claims:", idTokenClaims);
    }

    const { access_token, refresh_token, token_type, expires_in } =
      tokenResponse.data;
    const tokenPayload = parseJwt(access_token);

    req.session.user = {
      accessToken: access_token,
      refreshToken: refresh_token,
      tokenType: token_type,
      expiresIn: expires_in,
      sub: tokenPayload.sub,
      sessionId: tokenPayload.sessionId,
      scope: tokenPayload.scope || "",
      idTokenClaims,
    };

    // PKCE/nonce are one-time values per auth attempt.
    delete req.session.pkceVerifier;
    delete req.session.oauthNonce;

    res.redirect("/");
  } catch (err) {
    console.error(
      "clientA token exchange failed:",
      err.response?.data || err.message,
    );
    res.status(401).send("login failed");
  }
});

app.get("/profile", ensureUpstreamSession, async (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
  }

  const { sub, sessionId, scope, tokenType, expiresIn, idTokenClaims } =
    req.session.user;

  return res.send(`
    <h2>ClientA Profile</h2>
    <p>sub: ${sub}</p>
    <p>sessionId: ${sessionId}</p>
    <p>scope: ${scope || "(none)"}</p>
    <p>tokenType: ${tokenType}</p>
    <p>expiresIn: ${expiresIn} seconds</p>
    <p>oidc: ${idTokenClaims ? "enabled" : "disabled"}</p>
    <a href='/'>Back</a>
  `);
});

app.get("/user-info", ensureUpstreamSession, async (req, res) => {
  const api = createApiClient(req);

  try {
    const response = await api.get("/userinfo");
    return res.send(`
      <p>User Info:</p>
      <p>User ID: ${response.data?.sub}</p>
      <p>Email: ${response.data?.email}</p>
      <p>Name: ${response.data?.name || 'not in scope'}</p>
      <p>given_name: ${response.data?.given_name || 'not in scope'}</p>
      <p>family_name: ${response.data?.family_name || 'not in scope'}</p>
      <p>Picture: ${response.data?.picture ? `<img src="${response.data.picture}" alt="User Picture" width="100"/>` : 'not in scope'}</p>
      `)
  } catch (err) {
    const upstream = err.response?.data || err.message;
    console.error("Error fetching user info:", upstream);
    return res.redirect("/");
  }
});

app.get("/logout", async (req, res) => {
  const api = createApiClient(req);

  try {
    await api.post("/logout");
  } catch (err) {
    // SSO server อาจ return 401 ถ้า token หมดอายุแล้ว
    // ไม่ต้อง block การ logout ฝั่ง client
    console.error("SSO logout error:", err.message);
  }

  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.get("/logout-all", async (req, res) => {
  const api = createApiClient(req);

  try {
    await api.post("/logout-all");
  } catch (err) {
    // SSO server อาจ return 401 ถ้า token หมดอายุแล้ว
    // ไม่ต้อง block การ logout ฝั่ง client
    console.error("SSO global logout error:", err.message);
  }

  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.listen(envConfig.PORT, () => {
  console.log(`ClientA is running on port http://localhost:${envConfig.PORT}`);
});
