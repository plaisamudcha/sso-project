// Libraries
const express = require("express");
const session = require("express-session");
const { RedisStore } = require("connect-redis");
const { createClient } = require("redis");
const passport = require("passport");
const OAuth2Strategy = require("passport-oauth2");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

// Utilities
const envConfig = require("./config");
const { createApiClient } = require("./services/apiClient");
const {
  base64Url,
  createPkcePair,
  preparePkce,
  destroyLocalSession,
  ensureUpstreamSession,
} = require("./helper");

class DeviceAwareOAuth2Strategy extends OAuth2Strategy {
  authenticate(req, options = {}) {
    options.deviceId = req.session.browserId;
    options.deviceType = "browser";

    // PKCE from session
    options.codeVerifier = req.session.pkceVerifier;
    options.codeChallenge = req.session.pkceChallenge;
    options.codeChallengeMethod = "S256";

    // if OIDC login, add scope and nonce
    if (String(options.scope || "").includes("openid")) {
      options.nonce = req.session.oidcNonce;
    }

    return super.authenticate(req, options);
  }

  authorizationParams(options) {
    const params = {};
    if (options.nonce) {
      params.nonce = options.nonce;
    }

    if (options.codeChallenge) {
      params.code_challenge = options.codeChallenge;
      params.code_challenge_method = options.codeChallengeMethod || "S256";
    }

    return params;
  }

  tokenParams(options) {
    return {
      grant_type: "authorization_code",
      code_verifier: options.codeVerifier,
      deviceId: options.deviceId,
      deviceType: options.deviceType,
      client_id: envConfig.CLIENT_ID,
      redirect_uri: envConfig.REDIRECT_URI,
    };
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

passport.use(
  "sso",
  new DeviceAwareOAuth2Strategy(
    {
      authorizationURL: `${envConfig.SSO_SERVER}/authorize`,
      tokenURL: `${envConfig.SSO_SERVER}/token`,
      clientID: envConfig.CLIENT_ID,
      clientSecret: envConfig.CLIENT_SECRET,
      callbackURL: envConfig.REDIRECT_URI,
      state: true,
    },
    (accessToken, refreshToken, params, _profile, done) => {
      console.log("token params:", params);

      if (params.id_token) {
        console.log("Decoded ID Token:", jwt.decode(params.id_token));
      } else {
        console.warn("No ID Token received in token response");
      }

      const payload = jwt.decode(accessToken) || {};
      return done(null, {
        userId: payload.userId,
        sessionId: payload.sessionId,
        accessToken,
        refreshToken,
        idToken: params.id_token,
      });
    },
  ),
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

app.get("/", ensureUpstreamSession, (req, res) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.send(`
      <h1>ClientB</h1>
      <a href='/login'>Login with SSO</a>
      <p>or</p>
      <a href='/login-oidc'>Login with OIDC</a>
      `);
  }

  return res.send(`
    <h1>ClientB</h1>
    <p>User ID: ${req.user.userId}</p>
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
  passport.authenticate("sso", { scope: "openid email" }),
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
    return res.json(response.data);
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
