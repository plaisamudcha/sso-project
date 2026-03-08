// Utilities
const redis = require("./config/redis");
const oAuthClient = require("./model/oAuthClient");

function getDeviceSessionKey(deviceType, deviceId) {
  return `device-session:${deviceType}:${deviceId}`;
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
    await redis.sRem(`useSession:${session.useId}`, sessionId);
  }

  if (session?.deviceType && session?.deviceId) {
    await redis.del(getDeviceSessionKey(session.deviceType, session.deviceId));
  }
}

function oauthError(res, status, error, errorDescription) {
  return res.status(status).json({
    error,
    error_description: errorDescription,
  });
}

async function validateTokenClient(clientId, clientSecret) {
  if (!clientId) {
    return {
      error: {
        status: 400,
        code: "invalid_request",
        description: "Missing client_id",
      },
    };
  }

  const client = await oAuthClient.findOne({ clientId });
  if (!client) {
    return {
      error: {
        status: 401,
        code: "invalid_client",
        description: "Client not found",
      },
    };
  }

  if (client.tokenEndpointAuthMethod === "client_secret_post") {
    if (!clientSecret) {
      return {
        error: {
          status: 401,
          code: "invalid_client",
          description: "Missing client_secret",
        },
      };
    }

    if (clientSecret !== client.clientSecret) {
      return {
        error: {
          status: 401,
          code: "invalid_client",
          description: "Invalid client_secret",
        },
      };
    }
  }

  return { client };
}

module.exports = {
  getDeviceSessionKey,
  removeSessionById,
  oauthError,
  validateTokenClient,
};
