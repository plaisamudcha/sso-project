const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const { envConfig } = require("../config/config");
const {
  generateRefreshToken,
  generateToken,
  generateIdToken,
  verifyRefreshToken,
} = require("./tokenService");
const {
  findByEmail,
  findByIdLean,
  createUser,
} = require("../repositories/userRepository");
const {
  findByClientId,
  createClient,
  findAllWithoutSecrets,
} = require("../repositories/oauthClientRepository");
const {
  saveAuthCode,
  consumeAuthCode,
} = require("../repositories/authCodeRepository");
const {
  getSessionById,
  saveSession,
  addUserSession,
  getUserSessionIds,
  deleteUserSessionsSet,
  bindDeviceSession,
  getSessionIdByDevice,
  removeSessionById,
} = require("../repositories/sessionRepository");
const { validateTokenClient } = require("./clientValidationService");
const {
  isValidCodeVerifier,
  createS256CodeChallenge,
  buildIdTokenClaims,
  buildUserInfoClaims,
} = require("./oidcService");
const { AppError, OAuthError } = require("./errors");

const SUPPORTED_DEVICE_TYPES = new Set(["mobile", "browser"]);
const SUPPORTED_AUTH_METHODS = new Set(["client_secret_post", "none"]);
const SUPPORTED_SCOPES = new Set(["openid", "profile", "email"]);
const SUPPORTED_GRANT_TYPES = new Set(["authorization_code", "refresh_token"]);

async function registerUser(payload) {
  const { email, password, name, givenName, familyName, picture } = payload;

  if (!email || !password) {
    throw new AppError(400, "Email and password are required");
  }

  if (!name || !givenName || !familyName) {
    throw new AppError(400, "Name, givenName and familyName are required");
  }

  if (picture && typeof picture !== "string") {
    throw new AppError(400, "Picture must be a string URL");
  }

  const existing = await findByEmail(email);
  if (existing) {
    throw new AppError(400, "Email already exists");
  }

  const hashed = await bcrypt.hash(password, envConfig.SALT_ROUNDS);

  try {
    await createUser({
      sub: crypto.randomUUID(),
      email,
      password: hashed,
      name,
      givenName,
      familyName,
      picture,
    });

    return { message: "Register successfully" };
  } catch (err) {
    if (err?.code === 11000 && err?.keyPattern?.email) {
      throw new AppError(400, "Email already exists");
    }

    if (err?.code === 11000 && err?.keyPattern?.sub) {
      throw new AppError(500, "Failed to generate unique user subject (sub)");
    }

    throw new AppError(500, "Register failed");
  }
}

async function registerOAuthClient(payload) {
  const {
    name,
    redirectUris,
    tokenEndpointAuthMethod = "client_secret_post",
    allowedScopes,
    grantTypes,
  } = payload;

  if (!name || !Array.isArray(redirectUris) || redirectUris.length === 0) {
    throw new AppError(400, "Invalid request");
  }

  if (!SUPPORTED_AUTH_METHODS.has(tokenEndpointAuthMethod)) {
    throw new AppError(
      400,
      `Unsupported tokenEndpointAuthMethod: ${tokenEndpointAuthMethod}`,
    );
  }

  const normalizedRedirectUris = [
    ...new Set(redirectUris.map((u) => String(u).trim()).filter(Boolean)),
  ];

  const invalidUri = normalizedRedirectUris.find((u) => !/^https?:\/\/.+/i.test(u));
  if (invalidUri) {
    throw new AppError(400, `Invalid redirect URI: ${invalidUri}`);
  }

  const normalizedScopes =
    Array.isArray(allowedScopes) && allowedScopes.length > 0
      ? [...new Set(allowedScopes.map((s) => String(s).trim()).filter(Boolean))]
      : ["openid", "profile", "email"];

  const invalidScope = normalizedScopes.find((s) => !SUPPORTED_SCOPES.has(s));
  if (invalidScope) {
    throw new AppError(400, `Unsupported scope: ${invalidScope}`);
  }

  const normalizedGrantTypes =
    Array.isArray(grantTypes) && grantTypes.length > 0
      ? [...new Set(grantTypes.map((g) => String(g).trim()).filter(Boolean))]
      : ["authorization_code", "refresh_token"];

  const invalidGrantType = normalizedGrantTypes.find(
    (g) => !SUPPORTED_GRANT_TYPES.has(g),
  );
  if (invalidGrantType) {
    throw new AppError(400, `Unsupported grant type: ${invalidGrantType}`);
  }

  if (!normalizedGrantTypes.includes("authorization_code")) {
    throw new AppError(400, "authorization_code grant is required");
  }

  if (
    tokenEndpointAuthMethod === "none" &&
    normalizedGrantTypes.includes("refresh_token")
  ) {
    throw new AppError(
      400,
      "refresh_token grant is not allowed for public clients (tokenEndpointAuthMethod=none)",
    );
  }

  const clientId = crypto.randomUUID();
  let rawClientSecret = null;
  let hashedClientSecret = null;

  if (tokenEndpointAuthMethod === "client_secret_post") {
    rawClientSecret = crypto.randomBytes(32).toString("hex");
    hashedClientSecret = await bcrypt.hash(rawClientSecret, envConfig.SALT_ROUNDS);
  }

  const client = await createClient({
    name,
    clientId,
    clientSecret: hashedClientSecret,
    redirectUris: normalizedRedirectUris,
    allowedScopes: normalizedScopes,
    grantTypes: normalizedGrantTypes,
  });

  const responsePayload = {
    client_id: client.clientId,
    token_endpoint_auth_method: rawClientSecret ? "client_secret_post" : "none",
    redirect_uris: client.redirectUris,
    allowed_scopes: client.allowedScopes,
    grant_types: client.grantTypes,
  };

  if (rawClientSecret) {
    responsePayload.client_secret = rawClientSecret;
  }

  return responsePayload;
}

async function listOAuthClients() {
  return findAllWithoutSecrets();
}

async function validateAuthorizeRequest(query) {
  const {
    client_id,
    redirect_uri,
    state,
    response_type = "code",
    scope = "",
    nonce,
    code_challenge,
    code_challenge_method,
  } = query;

  if (!client_id || !redirect_uri) {
    throw new AppError(400, "Invalid request");
  }

  if (response_type !== "code") {
    throw new AppError(400, "Unsupported response_type");
  }

  const client = await findByClientId(client_id);
  if (!client) {
    throw new AppError(400, "Invalid client");
  }

  if (!client.redirectUris.includes(redirect_uri)) {
    throw new AppError(400, "Invalid redirect_uri");
  }

  if (!code_challenge) {
    throw new AppError(400, "Missing code_challenge");
  }

  if (code_challenge_method !== "S256") {
    throw new AppError(400, "Unsupported code_challenge_method");
  }

  const requestedScopes = String(scope).trim() ? String(scope).split(/\s+/) : [];
  const invalidScopes = requestedScopes.find((s) => !client.allowedScopes.includes(s));
  if (invalidScopes) {
    throw new AppError(400, `Invalid scope: ${invalidScopes}`);
  }

  const isOidcRequest = requestedScopes.includes("openid");
  if (isOidcRequest && !nonce) {
    throw new AppError(400, "Missing nonce for openid scope");
  }

  return {
    sessionOauth: {
      client_id,
      redirect_uri,
      state,
      scope: requestedScopes.join(" "),
      nonce: nonce || null,
      code_challenge: code_challenge || null,
      code_challenge_method: code_challenge_method || null,
    },
  };
}

async function loginAndCreateAuthCode(body, sessionOauth) {
  const { email, password } = body;

  if (!sessionOauth) {
    throw new AppError(400, "Unauthorized flow");
  }

  const {
    client_id,
    redirect_uri,
    state,
    scope,
    nonce,
    code_challenge,
    code_challenge_method,
  } = sessionOauth;

  const client = await findByClientId(client_id);
  if (!client || !client.redirectUris.includes(redirect_uri)) {
    throw new AppError(401, "Invalid OAuth client");
  }

  const user = await findByEmail(email);
  if (!user) {
    throw new AppError(400, "Invalid credentials");
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    throw new AppError(400, "Invalid credentials");
  }

  const code = crypto.randomBytes(32).toString("hex");

  const authCodeData = {
    code,
    userId: user._id.toString(),
    clientId: client_id,
    redirectUri: redirect_uri,
    codeChallenge: code_challenge || null,
    codeChallengeMethod: code_challenge_method || null,
    scope: scope || "",
    nonce: nonce || null,
    authTime: new Date().toISOString(),
  };

  await saveAuthCode(client_id, redirect_uri, code, authCodeData);

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set("code", code);

  if (state) {
    redirectUrl.searchParams.set("state", state);
  }

  return { redirectUrl: redirectUrl.toString() };
}

async function exchangeAuthorizationCode(body) {
  const {
    code,
    deviceId,
    deviceType,
    client_id,
    client_secret,
    redirect_uri,
    code_verifier,
  } = body;

  if (!code || !redirect_uri || !deviceId || !deviceType) {
    throw new OAuthError(400, "invalid_request", "Missing parameters");
  }

  if (!SUPPORTED_DEVICE_TYPES.has(deviceType)) {
    throw new OAuthError(400, "invalid_request", "Invalid device type");
  }

  const client = await validateTokenClient(client_id, client_secret);

  if (!client.grantTypes?.includes("authorization_code")) {
    throw new OAuthError(
      400,
      "unauthorized_client",
      "Client not allowed for this grant type",
    );
  }

  const authCode = await consumeAuthCode(client_id, redirect_uri, code);
  if (!authCode) {
    throw new OAuthError(
      400,
      "invalid_grant",
      "Invalid, expired, or already used authorization code",
    );
  }

  if (authCode.codeChallenge) {
    if (!isValidCodeVerifier(code_verifier)) {
      throw new OAuthError(400, "invalid_request", "Missing/invalid code_verifier");
    }

    if (authCode.codeChallengeMethod !== "S256") {
      throw new OAuthError(400, "invalid_grant", "Unsupported code challenge method");
    }

    const computedChallenge = createS256CodeChallenge(code_verifier);
    if (computedChallenge !== authCode.codeChallenge) {
      throw new OAuthError(400, "invalid_grant", "Invalid code_verifier");
    }
  }

  const grantedScopes = (authCode.scope || "").split(/\s+/).filter(Boolean);
  const isOidc = grantedScopes.includes("openid");

  const user = await findByIdLean(authCode.userId);
  if (!user) {
    throw new OAuthError(400, "invalid_grant", "User not found");
  }

  const existingSessionId = await getSessionIdByDevice(deviceType, deviceId);
  if (existingSessionId) {
    await removeSessionById(existingSessionId);
  }

  const sessionId = uuidv4();
  const refreshToken = generateRefreshToken(sessionId);

  const sessionData = {
    sub: user.sub,
    userId: authCode.userId,
    clientId: authCode.clientId,
    scope: authCode.scope || "",
    nonce: authCode.nonce || null,
    authTime: new Date(authCode.authTime || Date.now()).toISOString(),
    deviceId,
    deviceType,
    refreshToken,
    isActive: true,
  };

  await saveSession(sessionId, sessionData);
  await addUserSession(authCode.userId, sessionId);
  await bindDeviceSession(deviceType, deviceId, sessionId);

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
    const idTokenClaims = buildIdTokenClaims(user, scopes, {
      iss: envConfig.ISSUER,
      sub: user.sub,
      aud: client_id,
      auth_time: Math.floor(new Date(authCode.authTime).getTime() / 1000),
      ...(authCode.nonce ? { nonce: authCode.nonce } : {}),
    });

    responsePayload.id_token = generateIdToken(idTokenClaims);
  }

  return responsePayload;
}

async function exchangeRefreshToken(body) {
  const { client_id, client_secret, refresh_token } = body;
  const client = await validateTokenClient(client_id, client_secret);

  const isPublicClient = !(typeof client.clientSecret === "string" && client.clientSecret.length > 0);
  if (isPublicClient) {
    throw new OAuthError(
      400,
      "unauthorized_client",
      "refresh_token grant is not allowed for public clients",
    );
  }

  if (!client.grantTypes?.includes("refresh_token")) {
    throw new OAuthError(
      400,
      "unauthorized_client",
      "Client not allowed for refresh_token grant",
    );
  }

  if (!refresh_token) {
    throw new OAuthError(400, "invalid_request", "Missing refresh_token");
  }

  let payload;
  try {
    payload = verifyRefreshToken(refresh_token);
  } catch {
    throw new OAuthError(400, "invalid_grant", "Invalid refresh token");
  }

  const session = await getSessionById(payload.sessionId);
  if (!session) {
    throw new OAuthError(400, "invalid_grant", "Session not found");
  }

  if (session.refreshToken !== refresh_token) {
    throw new OAuthError(400, "invalid_grant", "Refresh token mismatch");
  }

  if (session.clientId !== client_id) {
    throw new OAuthError(400, "invalid_grant", "Refresh token client mismatch");
  }

  const newRefreshToken = generateRefreshToken(payload.sessionId);
  const newAccessToken = generateToken({
    iss: envConfig.ISSUER,
    sub: session.sub,
    sessionId: payload.sessionId,
    scope: session.scope,
  });

  session.refreshToken = newRefreshToken;
  await saveSession(payload.sessionId, session);

  if (session.deviceType && session.deviceId) {
    await bindDeviceSession(session.deviceType, session.deviceId, payload.sessionId);
  }

  return {
    access_token: newAccessToken,
    token_type: "Bearer",
    expires_in: 15 * 60,
    refresh_token: newRefreshToken,
    scope: session.scope || "",
  };
}

async function logoutBySessionId(sessionId) {
  await removeSessionById(sessionId);
  return { message: "logout success" };
}

async function logoutAllByUserId(sessionUserId) {
  const sessionIds = await getUserSessionIds(sessionUserId);
  for (const id of sessionIds) {
    await removeSessionById(id);
  }
  await deleteUserSessionsSet(sessionUserId);
  return { message: "global logout success" };
}

async function getUserInfoBySession(sessionId, userId) {
  const [user, session] = await Promise.all([
    findByIdLean(userId),
    getSessionById(sessionId),
  ]);

  if (!user || !session) {
    throw new AppError(401, "Unauthorized");
  }

  const scopes = new Set(String(session.scope || "").split(/\s+/).filter(Boolean));
  if (!scopes.has("openid")) {
    throw new OAuthError(403, "insufficient_scope", "openid scope is required");
  }

  return buildUserInfoClaims(user, scopes);
}

module.exports = {
  registerUser,
  registerOAuthClient,
  listOAuthClients,
  validateAuthorizeRequest,
  loginAndCreateAuthCode,
  exchangeAuthorizationCode,
  exchangeRefreshToken,
  logoutBySessionId,
  logoutAllByUserId,
  getUserInfoBySession,
};
