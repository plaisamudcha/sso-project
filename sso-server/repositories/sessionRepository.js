const redis = require("../config/redis");

const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;

function getDeviceSessionKey(deviceType, deviceId) {
  return `deviceSession:${deviceType}:${deviceId}`;
}

async function getSessionById(sessionId) {
  const raw = await redis.get(`session:${sessionId}`);
  return raw ? JSON.parse(raw) : null;
}

async function saveSession(sessionId, data) {
  await redis.set(`session:${sessionId}`, JSON.stringify(data), {
    EX: SESSION_TTL_SECONDS,
  });
}

async function addUserSession(userId, sessionId) {
  await redis.sAdd(`userSessions:${userId}`, sessionId);
}

async function getUserSessionIds(userId) {
  return redis.sMembers(`userSessions:${userId}`);
}

async function deleteUserSessionsSet(userId) {
  await redis.del(`userSessions:${userId}`);
}

async function bindDeviceSession(deviceType, deviceId, sessionId) {
  await redis.set(getDeviceSessionKey(deviceType, deviceId), sessionId, {
    EX: SESSION_TTL_SECONDS,
  });
}

async function getSessionIdByDevice(deviceType, deviceId) {
  return redis.get(getDeviceSessionKey(deviceType, deviceId));
}

async function removeSessionById(sessionId) {
  const sessionRaw = await redis.get(`session:${sessionId}`);
  let session = null;

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

module.exports = {
  SESSION_TTL_SECONDS,
  getDeviceSessionKey,
  getSessionById,
  saveSession,
  addUserSession,
  getUserSessionIds,
  deleteUserSessionsSet,
  bindDeviceSession,
  getSessionIdByDevice,
  removeSessionById,
};
