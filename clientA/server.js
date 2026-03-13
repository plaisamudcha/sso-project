// Libraries
const express = require("express");
const session = require("express-session");
const { RedisStore } = require("connect-redis");
const { createClient } = require("redis");
const { v4: uuidv4 } = require("uuid");

// Utilities
const { createApiClient } = require("./services/apiClient");
const { envConfig } = require("./config");
const { createPkcePair } = require("./helper");
const passport = require("./configs/passport");

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

app.use(passport.initialize());
app.use(passport.session());

app.set("view engine", "ejs");

app.get("/", (req, res) => {
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

app.get("/login", (req, res, next) => {
  const { challenge, verifier } = createPkcePair();
  req.session.pkceVerifier = verifier;
  req.session.pkceChallenge = challenge;
  delete req.session.oauthNonce;

  req.session.save(() => {
    passport.authenticate("sso")(req, res, next);
  });
});

app.get("/login-oidc", (req, res, next) => {
  const nonce = uuidv4();
  const { challenge, verifier } = createPkcePair();
  req.session.oauthNonce = nonce;
  req.session.pkceVerifier = verifier;
  req.session.pkceChallenge = challenge;

  req.session.save(() => {
    passport.authenticate("sso", { scope: "openid email" })(req, res, next);
  });
});

app.get(
  "/callback",
  passport.authenticate("sso", {
    failureRedirect: "/",
  }),
  (req, res) => {
    req.session.user = req.user;

    req.session.save((saveErr) => {
      if (saveErr) {
        console.error("clientA session save failed:", saveErr.message);
        return res.status(500).send("login failed");
      }

      return res.redirect("/");
    });
  },
);

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
