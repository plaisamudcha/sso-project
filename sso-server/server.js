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
const { verifySession, requireAdmin } = require("./midlleware/auth.js");
const redis = require("./config/redis.js");
const { RedisStore } = require("connect-redis");
const redisClient = require("./config/redis.js");
const { loginLimiter, tokenLimiter } = require("./midlleware/rateLimit.js");
const {
  getDeviceSessionKey,
  removeSessionById,
  oauthError,
  validateTokenClient,
  createS256CodeChallenge,
  isValidCodeVerifier,
  buildIdTokenClaims,
  buildUserInfoClaims,
} = require("./helper.js");
const { jwks } = require("./config/oidcKeys.js");

const app = express();
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
const SUPPORTED_DEVICE_TYPES = new Set(["mobile", "browser"]);

app.use(express.json());
app.use(
  cors({
    origin: ["http://localhost:5000", "http://localhost:5002"],
    methods: ["GET", "POST"],
    credentials: true,
  }),
);

const isProd = envConfig.NODE_ENV === "production";
app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(
  session({
    name: "sso.sid",
    store: new RedisStore({ client: redisClient }),
    secret: envConfig.SSO_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: isProd,
      sameSite: isProd ? "none" : "lax",
      httpOnly: true,
    },
  }),
);
app.use(express.urlencoded({ extended: true }));

app.set("view engine", "ejs");
connectDB();

app.post("/register", async (req, res) => {
  const { email, password, name, givenName, familyName, picture } = req.body;

  const existing = await User.findOne({ email });
  if (existing) {
    return res.status(400).json({ message: "Email already exists" });
  }

  const hashed = await bcrypt.hash(password, envConfig.SALT_ROUNDS);

  await User.create({
    email,
    password: hashed,
    name,
    givenName,
    familyName,
    picture
  });

  res.json({ message: "Register successfully" });
});

app.post("/register-oauth-client", requireAdmin, async (req, res) => {
  const {
    name,
    redirectUris,
    tokenEndpointAuthMethod = "client_secret_post",
    allowedScopes,
    grantTypes,
  } = req.body;

  const supportedAuthMethods = new Set(["client_secret_post", "none"]);
  const supportedScopes = new Set(["openid", "profile", "email"]);
  const supportedGrantTypes = new Set(["authorization_code", "refresh_token"]);

  if (!name || !Array.isArray(redirectUris) || redirectUris.length === 0) {
    return res.status(400).json({ message: "Invalid request" });
  }

  if (!supportedAuthMethods.has(tokenEndpointAuthMethod)) {
    return res.status(400).json({
      message: `Unsupported tokenEndpointAuthMethod: ${tokenEndpointAuthMethod}`,
    });
  }

  const normalizedRedirectUris = [
    ...new Set(redirectUris.map((u) => String(u).trim()).filter(Boolean)),
  ];

  const invalidUri = normalizedRedirectUris.find(
    (u) => !/^https?:\/\/.+/i.test(u),
  );
  if (invalidUri) {
    return res
      .status(400)
      .json({ message: `Invalid redirect URI: ${invalidUri}` });
  }

  const normalizedScopes = Array.isArray(allowedScopes) && allowedScopes.length > 0
    ? [...new Set(allowedScopes.map((s) => String(s).trim()).filter(Boolean))]
    : ["openid", "profile", "email"];
  const invalidScope = normalizedScopes.find((s) => !supportedScopes.has(s));
  if (invalidScope) {
    return res.status(400).json({ message: `Unsupported scope: ${invalidScope}` });
  }

  const normalizedGrantTypes = Array.isArray(grantTypes) && grantTypes.length > 0
    ? [...new Set(grantTypes.map((g) => String(g).trim()).filter(Boolean))]
    : ["authorization_code", "refresh_token"];
  const invalidGrantType = normalizedGrantTypes.find(
    (g) => !supportedGrantTypes.has(g),
  );
  if (invalidGrantType) {
    return res
      .status(400)
      .json({ message: `Unsupported grant type: ${invalidGrantType}` });
  }

  if (!normalizedGrantTypes.includes("authorization_code")) {
    return res
      .status(400)
      .json({ message: "authorization_code grant is required" });
  }

  if (
    tokenEndpointAuthMethod === "none" &&
    normalizedGrantTypes.includes("refresh_token")
  ) {
    return res.status(400).json({
      message:
        "refresh_token grant is not allowed for public clients (tokenEndpointAuthMethod=none)",
    });
  }

  const clientId = crypto.randomUUID();
  let rawClientSecret = null;
  let hashedClientSecret = null;

  if (tokenEndpointAuthMethod === "client_secret_post") {
    rawClientSecret = crypto.randomBytes(32).toString("hex");
    hashedClientSecret = await bcrypt.hash(rawClientSecret, envConfig.SALT_ROUNDS);
  }

  const client = await OAuthClient.create({
    name,
    clientId,
    clientSecret: hashedClientSecret,
    redirectUris: normalizedRedirectUris,
    tokenEndpointAuthMethod,
    allowedScopes: normalizedScopes,
    grantTypes: normalizedGrantTypes,
  });

  const responsePayload = {
    client_id: client.clientId,
    token_endpoint_auth_method: client.tokenEndpointAuthMethod,
    redirect_uris: client.redirectUris,
    allowed_scopes: client.allowedScopes,
    grant_types: client.grantTypes,
  };

  if (rawClientSecret) {
    // Expose client secret exactly once for confidential clients.
    responsePayload.client_secret = rawClientSecret;
  }

  return res.json(responsePayload);
});

app.get("/oauth-client", requireAdmin, async (_req, res) => {
  const data = await OAuthClient.find({}, { clientSecret: 0, __v: 0 }).lean();
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
    code_challenge,
    code_challenge_method,
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
  const requirePkce = client.tokenEndpointAuthMethod === "none";
  if (requirePkce) {
    if (!code_challenge) {
      return res.status(400).send("Missing code_challenge");
    }
    if (code_challenge_method !== "S256") {
      return res.status(400).send("Unsupported code_challenge_method");
    }
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
    code_challenge: code_challenge || null,
    code_challenge_method: code_challenge_method || null,
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

  const {
    client_id,
    redirect_uri,
    state,
    scope,
    nonce,
    code_challenge,
    code_challenge_method,
  } = req.session.oauth;

  const client = await OAuthClient.findOne({ clientId: client_id });

  if (!client || !client.redirectUris.includes(redirect_uri)) {
    return res.status(401).send("Invalid OAuth client");
  }

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: "Invalid credentials" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ message: "Invalid credentials" });

  const code = crypto.randomBytes(32).toString('hex');

  const authCode = await AuthCode.create({
    code,
    userId: user._id,
    clientId: client_id,
    redirectUri: redirect_uri,
    codeChallenge: code_challenge || null,
    codeChallengeMethod: code_challenge_method || null,
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
  try {
    const {
      code,
      deviceId,
      deviceType,
      client_id,
      client_secret,
      redirect_uri,
      grant_type,
      refresh_token,
      code_verifier,
    } = req.body;

    if (!grant_type) {
      return oauthError(res, 400, "invalid_request", "Missing grant_type");
    }

    const { client, error } = await validateTokenClient(
      client_id,
      client_secret,
    );
    if (error) {
      return oauthError(res, error.status, error.code, error.description);
    }

    if (grant_type === "authorization_code") {
      if (!code || !redirect_uri || !deviceId || !deviceType) {
        return oauthError(res, 400, "invalid_request", "Missing parameters");
      }

      if (!SUPPORTED_DEVICE_TYPES.has(deviceType)) {
        return oauthError(res, 400, "invalid_request", "Invalid device type");
      }

      if (!client.grantTypes?.includes("authorization_code")) {
        return oauthError(
          res,
          400,
          "unauthorized_client",
          "Client not allowed for this grant type",
        );
      }

      const now = new Date();
      const authCode = await AuthCode.findOneAndUpdate(
        {
          code,
          clientId: client_id,
          redirectUri: redirect_uri,
          expiresAt: { $gte: now },
          consumedAt: null,
        },
        {
          $set: { consumedAt: now },
        },
        {
          new: true,
        },
      );

      if (!authCode) {
        return oauthError(
          res,
          400,
          "invalid_grant",
          "Invalid, expired, or already used authorization code",
        );
      }

      if (authCode.codeChallenge) {
        if (!isValidCodeVerifier(code_verifier)) {
          return oauthError(
            res,
            400,
            "invalid_request",
            "Missing/invalid code_verifier",
          );
        }

        if (authCode.codeChallengeMethod !== "S256") {
          return oauthError(
            res,
            400,
            "invalid_grant",
            "Unsupported code challenge method",
          );
        }

        const computedChallenge = createS256CodeChallenge(code_verifier);
        if (computedChallenge !== authCode.codeChallenge) {
          return oauthError(res, 400, "invalid_grant", "Invalid code_verifier");
        }
      }

      const grantedScopes = (authCode.scope || "").split(/\s+/).filter(Boolean);
      const isOidc = grantedScopes.includes("openid");

      const user = await User.findById(authCode.userId).lean();
      if (!user) {
        return oauthError(res, 400, "invalid_grant", "User not found");
      }

      const existingSessionId = await redis.get(
        getDeviceSessionKey(deviceType, deviceId),
      );

      if (existingSessionId) {
        await removeSessionById(existingSessionId);
      }

      const sessionId = uuidv4();
      const refreshToken = generateRefreshToken(sessionId);

      const sessionData = {
        sub: user.sub,
        userId: authCode.userId.toString(),
        clientId: authCode.clientId,
        scope: authCode.scope || "",
        nonce: authCode.nonce || null,
        authTime: new Date(authCode.authTime || Date.now()).toISOString(),
        deviceId,
        deviceType,
        refreshToken,
        isActive: true,
      };

      await redis.set(`session:${sessionId}`, JSON.stringify(sessionData), {
        EX: SESSION_TTL_SECONDS,
      });

      await redis.sAdd(`userSessions:${authCode.userId}`, sessionId);

      await redis.set(getDeviceSessionKey(deviceType, deviceId), sessionId, {
        EX: SESSION_TTL_SECONDS,
      });

      const accessToken = generateToken({
        iss: envConfig.ISSUER,
        sub: user.sub,
        sessionId,
        scope: authCode.scope,
      });

      const responsePayload = {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 15 * 60,
        refresh_token: refreshToken,
        scope: sessionData.scope,
      };

      if (isOidc) {

        const scopes = new Set(grantedScopes);

        const idTokenClaims = buildIdTokenClaims(
          user,
          scopes,
          {
            iss: envConfig.ISSUER,
            sub: user.sub,
            aud: client_id,
            auth_time: Math.floor(new Date(authCode.authTime).getTime() / 1000),
            ...(authCode.nonce ? { nonce: authCode.nonce } : {}),
          }
        )

        responsePayload.id_token = generateIdToken(idTokenClaims);
      }

      await AuthCode.deleteOne({ _id: authCode._id });

      res.set("Cache-Control", "no-store");
      res.set("Pragma", "no-cache");
      return res.json(responsePayload);
    }

    if (grant_type === "refresh_token") {
      if (client.tokenEndpointAuthMethod === "none") {
        return oauthError(
          res,
          400,
          "unauthorized_client",
          "refresh_token grant is not allowed for public clients",
        );
      }

      if (!client.grantTypes?.includes("refresh_token")) {
        return oauthError(
          res,
          400,
          "unauthorized_client",
          "Client not allowed for refresh_token grant",
        );
      }

      if (!refresh_token) {
        return oauthError(res, 400, "invalid_request", "Missing refresh_token");
      }

      let payload;
      try {
        payload = verifyRefreshToken(refresh_token);
      } catch {
        return oauthError(res, 400, "invalid_grant", "Invalid refresh token");
      }

      const sessionRaw = await redis.get(`session:${payload.sessionId}`);
      if (!sessionRaw) {
        return oauthError(res, 400, "invalid_grant", "Session not found");
      }

      const session = JSON.parse(sessionRaw);

      if (session.refreshToken !== refresh_token) {
        return oauthError(res, 400, "invalid_grant", "Refresh token mismatch");
      }

      if (session.clientId !== client_id) {
        return oauthError(
          res,
          400,
          "invalid_grant",
          "Refresh token client mismatch",
        );
      }

      const newRefreshToken = generateRefreshToken(payload.sessionId);
      const newAccessToken = generateToken({
        iss: envConfig.ISSUER,
        sub: session.sub,
        sessionId: payload.sessionId,
        scope: session.scope,
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

      const responsePayload = {
        access_token: newAccessToken,
        token_type: "Bearer",
        expires_in: 15 * 60,
        refresh_token: newRefreshToken,
        scope: session.scope || "",
      };

      res.set("Cache-Control", "no-store");
      res.set("Pragma", "no-cache");
      return res.json(responsePayload);
    }

    return oauthError(
      res,
      400,
      "unsupported_grant_type",
      "Supported grant_type: authorization_code, refresh_token",
    );
  } catch (err) {
    console.error("/token error", err);
    return oauthError(res, 500, "server_error", "Internal Server Error");
  }
});

app.post("/logout", verifySession, async (req, res) => {
  await removeSessionById(req.user.sessionId);

  res.json({ message: "logout success" });
});

app.post("/logout-all", verifySession, async (req, res) => {
  const sessionUserId = req.user.userId || req.user.sessionUserId;
  const sessionIds = await redis.sMembers(`userSessions:${sessionUserId}`);

  for (const id of sessionIds) {
    await removeSessionById(id);
  }

  await redis.del(`userSessions:${sessionUserId}`);

  res.json({ message: "global logout success" });
});

app.get("/session-info", verifySession, async (req, res) => {
  res.json({
    userId: req.user.userId || req.user.sessionUserId || null,
    sub: req.user.sub,
    sessionId: req.user.sessionId,
    active: true,
  });
});

app.get("/userinfo", verifySession, async (req, res) => {
  const sessionUserId = req.user.userId || req.user.sessionUserId;
  const [user, sessionRaw] = await Promise.all([
    User.findById(sessionUserId).lean(),
    redis.get(`session:${req.user.sessionId}`),
  ]);

  if (!user || !sessionRaw) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const session = JSON.parse(sessionRaw);
  const scopes = new Set(
    String(session.scope || "")
      .split(/\s+/)
      .filter(Boolean),
  );

  if (!scopes.has("openid")) {
    return res.status(403).json({
      error: "insufficient_scope",
      error_description: "openid scope is required",
    });
  }

  const claims = buildUserInfoClaims(user, scopes);

  return res.json(claims);
});

// backward compatibility
app.get("/user-info", verifySession, (req, res, next) => {
  req.url = "/userinfo";
  next();
});

app.get("/.well-known/openid-configuration", (_req, res) => {
  const issuer = envConfig.ISSUER;

  return res.json({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["public"],
    code_challenge_methods_supported: ["S256"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: ["openid", "profile", "email"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
    claims_supported: [
      "sub",
      "email",
      "email_verified",
      "name",
      "given_name",
      "family_name",
      "picture",
      "auth_time",
      "iss",
      "aud",
      "nonce",
    ],
  });
});

app.get("/.well-known/jwks.json", (_req, res) => {
  res.json(jwks);
});

app.listen(envConfig.PORT, () => {
  console.log(`Server is running on port http://localhost:${envConfig.PORT}`);
});
