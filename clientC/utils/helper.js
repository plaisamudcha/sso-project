const { createApiClient } = require("../apis/apiClient");
const crypto = require("crypto");

function destroyLocalSession(req, res, redirectPath = "/") {
  req.session.user = null;
  req.session.destroy(() => {
    res.redirect(redirectPath);
  })
}

async function ensureUpstreamSession(req, res, next) {
  if (!req.session.user?.accessToken) {
    return next();
  }

  const api = createApiClient(req);

  try {
    await api.get("/session-info");
    return next();
  } catch {
    return destroyLocalSession(req, res);
  }
}

function base64Url(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function createPkcePair() {
  const verifier = base64Url(crypto.randomBytes(64));
  const challenge = base64Url(
    crypto.createHash("sha256").update(verifier).digest(),
  );
  return { verifier, challenge };
}

module.exports = {
  destroyLocalSession,
  ensureUpstreamSession,
  base64Url,
  createPkcePair,
};