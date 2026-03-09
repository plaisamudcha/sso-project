// Libraries
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

// Utilities
const redis = require("./config/redis");
const oAuthClient = require("./model/oAuthClient");

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

    let validSecret = false;
    const looksBcryptHash = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(
      client.clientSecret || "",
    );

    if (looksBcryptHash) {
      validSecret = await bcrypt.compare(clientSecret, client.clientSecret);
    } else {
      // รองรับข้อมูลเก่าแบบ plaintext ชั่วคราว
      validSecret = clientSecret === client.clientSecret;
    }

    if (!validSecret) {
      return {
        error: {
          status: 401,
          code: "invalid_client",
          description: "Invalid client_secret",
        },
      };
    }
  }

  if (client.tokenEndpointAuthMethod === "none" && clientSecret) {
    return {
      error: {
        status: 400,
        code: "invalid_request",
        description:
          "client_secret must not be sent for clients using token_endpoint_auth_method=none",
      },
    };
  }

  return { client };
}

function base64url(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function isValidCodeVerifier(verifier) {
  return (
    typeof verifier === "string" && /^[A-Za-z0-9._~-]{43,128}$/.test(verifier)
  );
}

function createS256CodeChallenge(verifier) {
  return base64url(crypto.createHash("sha256").update(verifier).digest());
}

module.exports = {
  getDeviceSessionKey,
  removeSessionById,
  oauthError,
  validateTokenClient,
  base64url,
  isValidCodeVerifier,
  createS256CodeChallenge,
};
