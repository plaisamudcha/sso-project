// Libraries
const express = require("express");
const bcrypt = require("bcryptjs");
const { envConfig } = require("./config/config.js");
const { connectDB } = require("./config/db.js");
const { v4: uuidv4 } = require("uuid");
const session = require("express-session");
const cors = require("cors");
const crypto = require("crypto");

// Models
const User = require("./model/user.js");
const AuthCode = require("./model/authCode.js");
const OAuthClient = require("./model/oAuthClient.js");

// Utilities
const {
  generateRefreshToken,
  generateToken,
  generateIdToken,
  verifyRefreshToken,
} = require("./services/tokenService.js");
const { verifySession } = require("./midlleware/auth.js");
const redis = require("./config/redis.js");
const { RedisStore } = require("connect-redis");
const redisClient = require("./config/redis.js");
const {
  loginLimiter,
  tokenLimiter,
  refreshLimiter,
} = require("./midlleware/rateLimit.js");

const app = express();
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
const SUPPORTED_DEVICE_TYPES = new Set(["mobile", "browser"]);

function getDeviceSessionKey(deviceType, deviceId) {
  return `deviceSession:${deviceType}:${deviceId}`;
}

async function removeSessionById(sessionId) {
  const sessionRaw = await redis.get(`session:${sessionId}`);
  let session;

  if (sessionRaw) {
    try {
      session = JSON.parse(sessionRaw);
    } catch {
      session = null;
    }
  }

  await redis.del(`session:${sessionId}`);

  if (session?.userId) {
    await redis.sRem(`userSessions:${session.userId}`, sessionId);
  }

  if (session?.deviceType && session?.deviceId) {
    await redis.del(getDeviceSessionKey(session.deviceType, session.deviceId));
  }
}

app.use(express.json());
app.use(
  cors({
    origin: ["http://localhost:5000", "http://localhost:5002"],
    methods: ["GET", "POST"],
    credentials: true,
  }),
);

app.use(
  session({
    name: "sso.sid",
    store: new RedisStore({ client: redisClient }),
    secret: envConfig.SSO_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false,
      httpOnly: true,
    },
  }),
);
app.use(express.urlencoded({ extended: true }));

app.set("view engine", "ejs");
connectDB();

app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  const existing = await User.findOne({ email });
  if (existing) {
    return res.status(400).json({ message: "Email already exists" });
  }

  const hashed = await bcrypt.hash(password, envConfig.SALT_ROUNDS);

  await User.create({
    email,
    password: hashed,
  });

  res.json({ message: "Register successfully" });
});

app.post("/register-oauth-client", async (req, res) => {
  const { name, redirectUris } = req.body;

  if (!name || !redirectUris) {
    return res.status(400).json({ message: "Invalid request" });
  }

  if (!Array.isArray(redirectUris)) {
    return res.status(400).json({ message: "redirectUris must be array" });
  }

  const clientId = crypto.randomUUID();
  const clientSecret = crypto.randomBytes(32).toString("hex");

  const client = await OAuthClient.create({
    name,
    clientId,
    clientSecret,
    redirectUris,
  });

  res.json({
    client_id: client.clientId,
    client_secret: client.clientSecret,
  });
});

app.get("/oauth-client", async (req, res) => {
  const data = await OAuthClient.find();

  return res.status(200).json(data);
});

app.get("/authorize", async (req, res) => {
  const {
    client_id,
    redirect_uri,
    state,
    response_type = "code",
    scope = "",
    nonce,
  } = req.query;

  if (!client_id || !redirect_uri) {
    return res.status(400).send("Invalid request");
  }

  if (response_type !== "code") {
    return res.status(400).send("Unsupported response_type");
  }

  const client = await OAuthClient.findOne({ clientId: client_id });
  if (!client) {
    return res.status(400).send("Invalid client");
  }
  if (!client.redirectUris.includes(redirect_uri)) {
    return res.status(400).send("Invalid redirect_uri");
  }

  const requestedScopes = String(scope).trim()
    ? String(scope).split(/\s+/)
    : [];
  const invalidScopes = requestedScopes.find(
    (s) => !client.allowedScopes.includes(s),
  );
  if (invalidScopes) {
    return res.status(400).send(`Invalid scope: ${invalidScopes}`);
  }
  const isOidcRequest = requestedScopes.includes("openid");
  if (isOidcRequest && !nonce) {
    return res.status(400).send("Missing nonce for openid scope");
  }

  req.session.oauth = {
    client_id,
    redirect_uri,
    state,
    scope: requestedScopes.join(" "),
    nonce: nonce || null,
  };

  console.log("save session to redis", req.session.oauth);

  req.session.save(() => {
    res.render("login");
  });
});

app.post("/login", loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!req.session.oauth) {
    return res.status(400).send("Unauthorized flow");
  }

  const { client_id, redirect_uri, state, scope, nonce } = req.session.oauth;

  const client = await OAuthClient.findOne({ clientId: client_id });

  if (!client || !client.redirectUris.includes(redirect_uri)) {
    return res.status(401).send("Invalid OAuth client");
  }

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: "Invalid credentials" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ message: "Invalid credentials" });

  const code = uuidv4();

  const authCode = await AuthCode.create({
    code,
    userId: user._id,
    clientId: client_id,
    redirectUri: redirect_uri,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000),

    // OIDC context
    scope: scope || "",
    nonce: nonce || null,
    authTime: new Date(),
  });

  console.log("create auth code", authCode);

  delete req.session.oauth;

  console.log("delete session from redis", req.session.oauth);

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set("code", code);

  if (state) {
    redirectUrl.searchParams.set("state", state);
  }

  res.redirect(redirectUrl.toString());
});

app.post("/token", tokenLimiter, async (req, res) => {
  const { code, deviceId, deviceType, client_id, client_secret, redirect_uri } =
    req.body;

  if (
    !code ||
    !client_id ||
    !client_secret ||
    !redirect_uri ||
    !deviceId ||
    !deviceType
  ) {
    return res.status(400).json({ message: "Missing parameters" });
  }

  if (!SUPPORTED_DEVICE_TYPES.has(deviceType)) {
    return res.status(400).json({ message: "Invalid device type" });
  }

  const authCode = await AuthCode.findOne({ code });
  if (!authCode) {
    return res.status(400).json({ message: "Invalid code" });
  }
  if (
    authCode.clientId !== client_id ||
    authCode.redirectUri !== redirect_uri
  ) {
    return res.status(401).json({ message: "Invalid authorization code" });
  }
  if (authCode.expiresAt < new Date()) {
    return res.status(400).json({ message: "Code expired" });
  }

  const grantedScopes = (authCode.scope || "").split(/\s+/).filter(Boolean);
  const isOidc = grantedScopes.includes("openid");

  let idToken;
  if (isOidc) {
    idToken = generateIdToken({
      iss: envConfig.ISSUER,
      sub: authCode.userId.toString(),
      aud: client_id,
      nonce: authCode.nonce || undefined,
      auth_time: Math.floor(
        new Date(authCode.authTime || Date.now()).getTime() / 1000,
      ),
    });
  }

  const client = await OAuthClient.findOne({ clientId: client_id });
  if (!client || !client.redirectUris.includes(redirect_uri)) {
    return res.status(401).json({ message: "Invalid Client" });
  }

  if (!client.grantTypes?.includes("authorization_code")) {
    return res
      .status(401)
      .json({ message: "Client not allowed for authorization_code grant" });
  }

  if (client.tokenEndpointAuthMethod === "client_secret_post") {
    if (!client_secret) {
      return res.status(401).json({ message: "Missing client_secret" });
    }

    if (client_secret !== client.clientSecret) {
      return res.status(401).json({ message: "Invalid client credentials" });
    }
  }

  const existingSessionId = await redis.get(
    getDeviceSessionKey(deviceType, deviceId),
  );

  console.log(
    "existingSessionId for device",
    deviceType,
    deviceId,
    existingSessionId,
  );

  // One account per device/browser: replacing any existing login on this device.
  if (existingSessionId) {
    await removeSessionById(existingSessionId);
  }

  const sessionId = uuidv4();

  const refreshToken = generateRefreshToken(sessionId);

  const sessionData = {
    userId: authCode.userId.toString(),
    deviceId,
    deviceType,
    refreshToken,
    isActive: true,
  };

  // เก็บ session พร้อม TTL 7 วัน
  await redis.set(`session:${sessionId}`, JSON.stringify(sessionData), {
    EX: SESSION_TTL_SECONDS,
  });

  console.log("create session in redis", sessionData, `session:${sessionId}`);

  // เพิ่ม session เข้า userSessions
  await redis.sAdd(`userSessions:${authCode.userId}`, sessionId);

  console.log(
    "add session to userSessions set",
    `userSessions:${authCode.userId}`,
    sessionId,
  );

  console.log(
    "userSession",
    await redis.sMembers(`userSessions:${authCode.userId}`),
  );

  await redis.set(getDeviceSessionKey(deviceType, deviceId), sessionId, {
    EX: SESSION_TTL_SECONDS,
  });

  console.log(
    "set device session key",
    getDeviceSessionKey(deviceType, deviceId),
    sessionId,
  );

  const accessToken = generateToken({
    userId: authCode.userId,
    sessionId,
  });

  const responsePayload = {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 15 * 60,
    refresh_token: refreshToken,
  };

  if (isOidc) {
    responsePayload.id_token = idToken;
    responsePayload.scope = authCode.scope || "openid";
  }

  await AuthCode.deleteOne({ code });

  res.json(responsePayload);
});

app.post("/refresh", refreshLimiter, async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const payload = verifyRefreshToken(refreshToken);

    const sessionRaw = await redis.get(`session:${payload.sessionId}`);
    if (!sessionRaw) {
      return res.status(401).json({ message: "Invalid session" });
    }

    const session = JSON.parse(sessionRaw);

    if (session.refreshToken !== refreshToken) {
      return res.status(401).json({ message: "Token mismatch" });
    }

    // rotate refresh token
    const newRefreshToken = generateRefreshToken(payload.sessionId);

    // สร้าง access token ใหม่
    const newAccessToken = generateToken({
      userId: session.userId,
      sessionId: payload.sessionId,
    });

    session.refreshToken = newRefreshToken;

    await redis.set(`session:${payload.sessionId}`, JSON.stringify(session), {
      EX: SESSION_TTL_SECONDS,
    });

    if (session.deviceType && session.deviceId) {
      await redis.set(
        getDeviceSessionKey(session.deviceType, session.deviceId),
        payload.sessionId,
        { EX: SESSION_TTL_SECONDS },
      );
    }

    res.json({
      access_token: newAccessToken,
      token_type: "Bearer",
      expires_in: 15 * 60,
      refresh_token: newRefreshToken,
    });
  } catch (err) {
    return res.status(401).json({ message: "Invalid refresh token" });
  }
});

app.post("/logout", verifySession, async (req, res) => {
  await removeSessionById(req.user.sessionId);

  res.json({ message: "logout success" });
});

app.post("/logout-all", verifySession, async (req, res) => {
  const sessionIds = await redis.sMembers(`userSessions:${req.user.userId}`);

  for (const id of sessionIds) {
    await removeSessionById(id);
  }

  await redis.del(`userSessions:${req.user.userId}`);

  res.json({ message: "global logout success" });
});

app.get("/session-info", verifySession, async (req, res) => {
  res.json({
    userId: req.user.userId,
    sessionId: req.user.sessionId,
    active: true,
  });
});

app.get("/user-info", verifySession, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).lean();

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    return res.json({
      sub: req.user.userId,
      email: user.email,
    });
  } catch (err) {
    return res.status(500).json({ message: "Server error" });
  }
});

app.listen(envConfig.PORT, () => {
  console.log(`Server is running on port http://localhost:${envConfig.PORT}`);
});
