const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT_DIR = __dirname;
const DEFAULT_PASSWORD = "SmokeTest#2026";
const MAX_LOGIN_ATTEMPTS = 3;

function base64url(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function createPkcePair() {
  const verifier = base64url(crypto.randomBytes(64));
  const challenge = base64url(
    crypto.createHash("sha256").update(verifier).digest(),
  );
  return { verifier, challenge };
}

function parseEnvFile(filePath) {
  const content = fs.readFileSync(filePath, "utf8");
  const lines = content.split(/\r?\n/);
  const result = {};

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const eqIndex = trimmed.indexOf("=");
    if (eqIndex === -1) continue;

    const key = trimmed.slice(0, eqIndex).trim();
    let value = trimmed.slice(eqIndex + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    result[key] = value;
  }

  return result;
}

function loadClientConfig(clientDirName) {
  const envPath = path.join(ROOT_DIR, clientDirName, ".env");
  if (!fs.existsSync(envPath)) {
    throw new Error(`Missing env file: ${envPath}`);
  }

  const env = parseEnvFile(envPath);
  const requiredKeys = [
    "CLIENT_ID",
    "CLIENT_SECRET",
    "REDIRECT_URI",
    "SSO_SERVER",
  ];

  for (const key of requiredKeys) {
    if (!env[key]) {
      throw new Error(`${clientDirName}/.env is missing ${key}`);
    }
  }

  return {
    name: clientDirName,
    clientId: env.CLIENT_ID,
    clientSecret: env.CLIENT_SECRET,
    redirectUri: env.REDIRECT_URI,
    ssoServer: env.SSO_SERVER.replace(/\/+$/, ""),
  };
}

function loadSsoServerEnv() {
  const envPath = path.join(ROOT_DIR, "sso-server", ".env");
  if (!fs.existsSync(envPath)) {
    return {};
  }
  return parseEnvFile(envPath);
}

class CookieJar {
  constructor() {
    this.cookies = {};
  }

  headerValue() {
    return Object.entries(this.cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
  }

  attach(headers) {
    const cookieHeader = this.headerValue();
    if (cookieHeader) {
      headers.Cookie = cookieHeader;
    }
  }

  updateFromResponse(res) {
    let setCookies = [];

    if (typeof res.headers.getSetCookie === "function") {
      setCookies = res.headers.getSetCookie();
    } else {
      const raw = res.headers.get("set-cookie");
      if (raw) setCookies = [raw];
    }

    for (const cookie of setCookies) {
      const firstPart = String(cookie).split(";")[0];
      const idx = firstPart.indexOf("=");
      if (idx <= 0) continue;
      const name = firstPart.slice(0, idx).trim();
      const value = firstPart.slice(idx + 1).trim();
      this.cookies[name] = value;
    }
  }
}

async function httpRequest(url, options = {}) {
  const {
    method = "GET",
    json,
    headers = {},
    jar,
    redirect = "follow",
  } = options;

  const requestHeaders = { ...headers };
  let body;

  if (json !== undefined) {
    requestHeaders["Content-Type"] = "application/json";
    body = JSON.stringify(json);
  }

  if (jar) {
    jar.attach(requestHeaders);
  }

  const res = await fetch(url, {
    method,
    headers: requestHeaders,
    body,
    redirect,
  });

  if (jar) {
    jar.updateFromResponse(res);
  }

  const text = await res.text();
  let data = null;
  try {
    data = JSON.parse(text);
  } catch {
    data = null;
  }

  return {
    status: res.status,
    headers: res.headers,
    text,
    data,
  };
}

function ensureStatus(actual, expected, message, payload) {
  if (actual !== expected) {
    const detail = payload ? ` | payload: ${payload}` : "";
    throw new Error(
      `${message} (expected ${expected}, got ${actual})${detail}`,
    );
  }
}

function randomEmail(prefix) {
  return `${prefix}.${Date.now()}.${crypto.randomBytes(3).toString("hex")}@example.com`;
}

function randomTestIp() {
  // TEST-NET-2 range for documentation/examples.
  return `198.51.100.${Math.floor(Math.random() * 200) + 20}`;
}

async function loginWithRetry({
  ssoServer,
  jar,
  email,
  password,
  baseHeaders,
}) {
  let attempt = 0;
  let currentIp = baseHeaders["X-Forwarded-For"] || randomTestIp();

  while (attempt < MAX_LOGIN_ATTEMPTS) {
    attempt += 1;

    const headers = {
      ...baseHeaders,
      "X-Forwarded-For": currentIp,
    };

    const loginRes = await httpRequest(`${ssoServer}/login`, {
      method: "POST",
      jar,
      redirect: "manual",
      headers,
      json: {
        email,
        password,
      },
    });

    if (loginRes.status !== 429) {
      return loginRes;
    }

    if (attempt >= MAX_LOGIN_ATTEMPTS) {
      return loginRes;
    }

    // Rotate source IP for local smoke tests when login limiter is hot.
    currentIp = randomTestIp();
  }

  throw new Error("Unexpected retry loop exit");
}

async function registerUser(ssoServer, email, password) {
  const baseName = email.split("@")[0];
  const response = await httpRequest(`${ssoServer}/register`, {
    method: "POST",
    json: {
      email,
      password,
      name: `${baseName} TestUser`,
      givenName: "Test",
      familyName: "User",
      picture: "https://example.com/avatar.png",
    },
  });

  if (response.status === 200) return;
  if (
    response.status === 400 &&
    response.data?.message === "Email already exists"
  )
    return;

  const rawPayload = JSON.stringify(response.data || response.text);
  if (
    response.status === 500 &&
    /sub_1 dup key: \{ sub: null \}|duplicate key error.*sub_1/i.test(
      rawPayload,
    )
  ) {
    throw new Error(
      "register failed due to duplicate `sub:null` on server DB/index. Restart sso-server with latest User schema and run `node sso-server/scripts/backfill-user-fields.js`, then rerun smoke_test.",
    );
  }

  throw new Error(
    `register failed (status ${response.status}) ${rawPayload}`,
  );
}

async function runFlow(config) {
  const {
    label,
    ssoServer,
    clientId,
    clientSecret,
    redirectUri,
    oidc,
    tokenEndpointAuthMethod,
    grantTypes,
  } = config;

  const jar = new CookieJar();
  const flowSourceIp = randomTestIp();
  const state = crypto.randomUUID();
  const nonce = oidc ? crypto.randomUUID() : null;
  const { verifier, challenge } = createPkcePair();

  const authorizeParams = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });

  if (oidc) {
    authorizeParams.set("scope", "openid email");
    authorizeParams.set("nonce", nonce);
  }

  const authorizeRes = await httpRequest(
    `${ssoServer}/authorize?${authorizeParams.toString()}`,
    {
      headers: {
        "X-Forwarded-For": flowSourceIp,
      },
      jar,
      redirect: "manual",
    },
  );
  ensureStatus(
    authorizeRes.status,
    200,
    `${label}: /authorize should render login page`,
  );

  const email = randomEmail(label.toLowerCase().replace(/\s+/g, "-"));
  await registerUser(ssoServer, email, DEFAULT_PASSWORD);

  const loginRes = await loginWithRetry({
    ssoServer,
    jar,
    email,
    password: DEFAULT_PASSWORD,
    baseHeaders: {
      "X-Forwarded-For": flowSourceIp,
    },
  });

  if (loginRes.status !== 302 && loginRes.status !== 303) {
    throw new Error(
      `${label}: /login should redirect (got ${loginRes.status}) ${JSON.stringify(loginRes.data || loginRes.text)}`,
    );
  }

  const location = loginRes.headers.get("location");
  if (!location) {
    throw new Error(`${label}: missing redirect location from /login`);
  }

  const callbackUrl = new URL(location);
  const code = callbackUrl.searchParams.get("code");
  const returnedState = callbackUrl.searchParams.get("state");

  if (!code) {
    throw new Error(`${label}: callback is missing code`);
  }
  if (returnedState !== state) {
    throw new Error(`${label}: callback state mismatch`);
  }

  const tokenRes = await httpRequest(`${ssoServer}/token`, {
    method: "POST",
    json: {
      grant_type: "authorization_code",
      code,
      client_id: clientId,
      ...(tokenEndpointAuthMethod === "client_secret_post"
        ? { client_secret: clientSecret }
        : {}),
      redirect_uri: redirectUri,
      deviceId: `smoke-${crypto.randomUUID()}`,
      deviceType: "browser",
      code_verifier: verifier,
    },
  });

  ensureStatus(
    tokenRes.status,
    200,
    `${label}: token exchange failed`,
    JSON.stringify(tokenRes.data || tokenRes.text),
  );

  const accessToken = tokenRes.data?.access_token;
  const refreshToken = tokenRes.data?.refresh_token;
  if (!accessToken || !refreshToken) {
    throw new Error(
      `${label}: token response missing access_token or refresh_token`,
    );
  }

  if (oidc && !tokenRes.data?.id_token) {
    throw new Error(`${label}: oidc flow should return id_token`);
  }

  const userInfoRes = await httpRequest(`${ssoServer}/userinfo`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (oidc) {
    ensureStatus(
      userInfoRes.status,
      200,
      `${label}: /userinfo should succeed for oidc flow`,
      JSON.stringify(userInfoRes.data || userInfoRes.text),
    );

    if (!userInfoRes.data?.sub) {
      throw new Error(`${label}: /userinfo missing sub claim`);
    }
    if (!userInfoRes.data?.email) {
      throw new Error(`${label}: /userinfo missing email claim`);
    }
  } else {
    ensureStatus(
      userInfoRes.status,
      403,
      `${label}: /userinfo should fail for oauth-only flow`,
      JSON.stringify(userInfoRes.data || userInfoRes.text),
    );

    if (userInfoRes.data?.error !== "insufficient_scope") {
      throw new Error(
        `${label}: expected insufficient_scope, got ${JSON.stringify(userInfoRes.data || userInfoRes.text)}`,
      );
    }
  }

  let refreshedAccessToken = accessToken;
  const shouldExpectRefreshSuccess =
    grantTypes.includes("refresh_token") &&
    tokenEndpointAuthMethod === "client_secret_post";

  const refreshRes = await httpRequest(`${ssoServer}/token`, {
    method: "POST",
    json: {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: clientId,
      ...(tokenEndpointAuthMethod === "client_secret_post"
        ? { client_secret: clientSecret }
        : {}),
    },
  });

  if (shouldExpectRefreshSuccess) {
    ensureStatus(
      refreshRes.status,
      200,
      `${label}: refresh token exchange failed`,
      JSON.stringify(refreshRes.data || refreshRes.text),
    );

    refreshedAccessToken = refreshRes.data?.access_token;
    if (!refreshedAccessToken) {
      throw new Error(`${label}: refresh response missing access_token`);
    }
  } else {
    if (refreshRes.status !== 400) {
      throw new Error(
        `${label}: expected refresh to be rejected (400), got ${refreshRes.status}`,
      );
    }
  }

  const logoutRes = await httpRequest(`${ssoServer}/logout`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${refreshedAccessToken}`,
    },
  });

  ensureStatus(logoutRes.status, 200, `${label}: logout failed`);

  const sessionInfoRes = await httpRequest(`${ssoServer}/session-info`, {
    headers: {
      Authorization: `Bearer ${refreshedAccessToken}`,
    },
  });

  if (sessionInfoRes.status === 200) {
    throw new Error(`${label}: session-info should fail after logout`);
  }
}

async function main() {
  const clientA = loadClientConfig("clientA");
  const clientB = loadClientConfig("clientB");
  const ssoEnv = loadSsoServerEnv();

  const ssoServer =
    process.env.SSO_SERVER || clientA.ssoServer || clientB.ssoServer;
  if (!ssoServer) {
    throw new Error("Cannot determine SSO_SERVER.");
  }

  const health = await httpRequest(
    `${ssoServer}/.well-known/openid-configuration`,
  );
  if (health.status !== 200) {
    throw new Error(
      `SSO server is not ready at ${ssoServer} (status ${health.status}). Start sso-server first.`,
    );
  }

  const adminApiKey = ssoEnv.ADMIN_API_KEY;
  if (!adminApiKey) {
    throw new Error(
      "sso-server/.env is missing ADMIN_API_KEY. Smoke test requires admin access to read client metadata.",
    );
  }

  const clientListRes = await httpRequest(`${ssoServer}/oauth-client`, {
    headers: {
      "x-admin-api-key": adminApiKey,
    },
  });

  ensureStatus(
    clientListRes.status,
    200,
    "Failed to fetch oauth-client metadata",
    JSON.stringify(clientListRes.data || clientListRes.text),
  );

  const byClientId = new Map(
    (clientListRes.data || []).map((c) => [c.clientId, c]),
  );

  function enrichClient(base) {
    const metadata = byClientId.get(base.clientId);
    if (!metadata) {
      throw new Error(
        `Client metadata not found for ${base.name} (clientId=${base.clientId})`,
      );
    }

    return {
      ...base,
      tokenEndpointAuthMethod:
        metadata.tokenEndpointAuthMethod || "client_secret_post",
      grantTypes: Array.isArray(metadata.grantTypes) ? metadata.grantTypes : [],
    };
  }

  const clientAConfig = enrichClient(clientA);
  const clientBConfig = enrichClient(clientB);

  const flows = [
    {
      label: "ClientA OAuth Flow",
      ssoServer,
      clientId: clientAConfig.clientId,
      clientSecret: clientAConfig.clientSecret,
      redirectUri: clientAConfig.redirectUri,
      tokenEndpointAuthMethod: clientAConfig.tokenEndpointAuthMethod,
      grantTypes: clientAConfig.grantTypes,
      oidc: false,
    },
    {
      label: "ClientA OIDC Flow",
      ssoServer,
      clientId: clientAConfig.clientId,
      clientSecret: clientAConfig.clientSecret,
      redirectUri: clientAConfig.redirectUri,
      tokenEndpointAuthMethod: clientAConfig.tokenEndpointAuthMethod,
      grantTypes: clientAConfig.grantTypes,
      oidc: true,
    },
    {
      label: "ClientB OAuth Flow",
      ssoServer,
      clientId: clientBConfig.clientId,
      clientSecret: clientBConfig.clientSecret,
      redirectUri: clientBConfig.redirectUri,
      tokenEndpointAuthMethod: clientBConfig.tokenEndpointAuthMethod,
      grantTypes: clientBConfig.grantTypes,
      oidc: false,
    },
    {
      label: "ClientB OIDC Flow",
      ssoServer,
      clientId: clientBConfig.clientId,
      clientSecret: clientBConfig.clientSecret,
      redirectUri: clientBConfig.redirectUri,
      tokenEndpointAuthMethod: clientBConfig.tokenEndpointAuthMethod,
      grantTypes: clientBConfig.grantTypes,
      oidc: true,
    },
  ];

  const failures = [];

  console.log("Running smoke tests...\n");

  for (const flow of flows) {
    process.stdout.write(`[RUN ] ${flow.label}\n`);
    try {
      await runFlow(flow);
      process.stdout.write(`[PASS] ${flow.label}\n\n`);
    } catch (err) {
      failures.push({ flow: flow.label, error: err.message });
      process.stdout.write(`[FAIL] ${flow.label}\n`);
      process.stdout.write(`       ${err.message}\n\n`);
    }
  }

  if (failures.length > 0) {
    console.error(`Smoke test failed: ${failures.length} flow(s) failed.`);
    for (const f of failures) {
      console.error(`- ${f.flow}: ${f.error}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log("Smoke test passed: all flows are healthy.");
}

main().catch((err) => {
  console.error("Smoke test fatal error:", err.message);
  process.exitCode = 1;
});
