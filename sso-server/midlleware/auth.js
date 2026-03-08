const { verifyToken } = require("../services/tokenService");
const redis = require("../config/redis");
const { envConfig } = require("../config/config");

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = verifyToken(token);
    req.user = decoded;
    next();
  } catch {
    res.sendStatus(403);
  }
}

async function verifySession(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "No token" });
    }

    const token = authHeader.split(" ")[1];
    const payload = verifyToken(token);

    const sessionCount = await redis.sCard(`userSessions:${payload.userId}`);
    if (sessionCount === 0) {
      return res.status(401).json({ message: "User not found" });
    }

    const sessionRaw = await redis.get(`session:${payload.sessionId}`);
    if (!sessionRaw) {
      return res.status(401).json({ message: "Session not found" });
    }

    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Unauthorized" });
  }
}

function requireAdmin(req, res, next) {
  const apiKey = req.headers["x-admin-api-key"];
  if (!apiKey || apiKey !== envConfig.ADMIN_API_KEY) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  return next();
}

module.exports = { authMiddleware, verifySession, requireAdmin };
