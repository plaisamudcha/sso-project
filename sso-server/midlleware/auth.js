const { verifyToken } = require("../services/tokenService");
const Session = require("../model/session");

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
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const payload = verifyToken(token);

  const session = await Session.findById(payload.sessionId);

  if (!session || !session.isActive) {
    return res.status(401).json({ message: "Session expired" });
  }

  req.user = payload;
  next();
}

module.exports = { authMiddleware, verifySession };
