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
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "No token" });
    }

    const token = authHeader.split(" ")[1];

    const payload = verifyToken(token);

    const session = await Session.findById(payload.sessionId);

    if (!session || !session.isActive) {
      return res.status(401).json({ message: "Session Invalid" });
    }

    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Unauthorized" });
  }
}

module.exports = { authMiddleware, verifySession };
