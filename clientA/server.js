// Libraries
const express = require("express");
const axios = require("axios");
const session = require("express-session");
const { RedisStore } = require("connect-redis");
const { createClient } = require("redis");
const { v4: uuidv4 } = require("uuid");

// Utilities
const { createApiClient } = require("./services/apiClient");
const { parseJwt } = require("./helper");
const { envConfig } = require("./config");

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

app.use(
  session({
    name: "clientA.sid",
    store: new RedisStore({ client: redisClient }),
    secret: envConfig.APP_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false,
      sameSite: "lax",
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
      `);
  }

  return res.send(`
    <h1>ClientA</h1>
    <p>User ID: ${req.session.user.userId}</p>
    <p>Session ID: ${req.session.user.sessionId}</p>
    <a href='/profile'>View Profile</a>
    <a href='/logout'>Logout this device</a>
    <a href='/logout-all'>Logout all devices</a>
    `);
});

app.get("/login", (req, res) => {
  const state = uuidv4();
  req.session.oauthState = state;

  const url = `${envConfig.SSO_SERVER}/authorize?client_id=${envConfig.CLIENT_ID}&redirect_uri=${envConfig.REDIRECT_URI}&state=${state}`;
  req.session.save(() => {
    res.redirect(url);
  });
});

app.get("/callback", async (req, res) => {
  const { code, state } = req.query;

  if (!code || !state) {
    return res.status(400).send("Invalid callback parameters");
  }

  if (!req.session.oauthState || req.session.oauthState !== state) {
    return res.status(400).send("Invalid OAuth state");
  }

  delete req.session.oauthState;

  try {
    const tokenResponse = await axios.post(`${envConfig.SSO_SERVER}/token`, {
      code,
      client_id: envConfig.CLIENT_ID,
      client_secret: envConfig.CLIENT_SECRET,
      redirect_uri: envConfig.REDIRECT_URI,
      deviceId: req.session.browserId,
      deviceType: "browser",
    });

    const { access_token, refresh_token, token_type, expires_in } =
      tokenResponse.data;
    const tokenPayload = parseJwt(access_token);

    req.session.user = {
      accessToken: access_token,
      refreshToken: refresh_token,
      tokenType: token_type,
      expiresIn: expires_in,
      userId: tokenPayload.userId,
      sessionId: tokenPayload.sessionId,
    };

    console.log("user logged in", req.session.user);

    res.redirect("/");
  } catch (err) {
    res.send("login failed");
  }
});

app.get("/profile", ensureUpstreamSession, async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  return res.json(req.session.user);
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
