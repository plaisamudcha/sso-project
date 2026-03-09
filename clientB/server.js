// Libraries
const express = require("express");
const session = require("express-session");
const { RedisStore } = require("connect-redis");
const passport = require("passport");
const { v4: uuidv4 } = require("uuid");

// Utilities
const envConfig = require("./configs/config");
const { createApiClient } = require("./apis/apiClient");
const {
  preparePkce,
  destroyLocalSession,
  ensureUpstreamSession,
} = require("./utils/helper");
const redisClient = require('./configs/redis')

// Configurations
require("./configs/passport");
require("./configs/redis");

const app = express();

const isProd = envConfig.NODE_ENV === "production";
app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(
  session({
    name: "clientB.sid",
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

app.use(passport.initialize());
app.use(passport.session());

app.get("/", ensureUpstreamSession, (req, res) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.send(`
      <h1>ClientB</h1>
      <a href='/login'>Login with SSO</a>
      <p>or</p>
      <a href='/login-oidc'>Login with OIDC</a>
      `);
  }

  console.log('req.user', req.user)

  return res.send(`
    <h1>ClientB</h1>
    <p>User ID: ${req.user.idTokenClaims?.sub}</p>
    <p>Session ID: ${req.user.sessionId}</p>
    <a href='/me'>View Profile</a>
    <a href='/user-info'>View User Info</a>
    <a href='/logout'>Logout this device</a>
    <a href='/logout-all'>Logout all devices</a>
    `);
});

app.get("/login", preparePkce, passport.authenticate("sso"));

app.get(
  "/login-oidc",
  preparePkce,
  (req, res, next) => {
    req.session.oidcNonce = uuidv4();
    next();
  },
  passport.authenticate("sso", { scope: "openid email profile" }),
);

app.get(
  "/callback",
  passport.authenticate("sso", {
    failureRedirect: "/",
  }),
  (req, res) => {
    res.redirect("/");
  },
);

app.get("/me", ensureUpstreamSession, (req, res) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  return res.json(req.user);
});

app.get("/protected-check", async (req, res) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
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
  if (!req.isAuthenticated || !req.isAuthenticated()) {
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
  if (!req.isAuthenticated || !req.isAuthenticated()) {
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
