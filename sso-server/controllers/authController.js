const {
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
} = require("../services/authService");
const { AppError, OAuthError } = require("../services/errors");

function handleControllerError(res, err) {
  if (err instanceof OAuthError) {
    return res.status(err.status).json({
      error: err.code,
      error_description: err.description,
    });
  }

  if (err instanceof AppError) {
    return res.status(err.status).json({ message: err.message });
  }

  console.error(err);
  return res.status(500).json({ message: "Internal Server Error" });
}

async function register(req, res) {
  try {
    const data = await registerUser(req.body);
    return res.json(data);
  } catch (err) {
    return handleControllerError(res, err);
  }
}

async function registerOAuth(req, res) {
  try {
    const data = await registerOAuthClient(req.body);
    return res.json(data);
  } catch (err) {
    return handleControllerError(res, err);
  }
}

async function listOAuth(req, res) {
  try {
    const data = await listOAuthClients();
    return res.status(200).json(data);
  } catch (err) {
    return handleControllerError(res, err);
  }
}

async function authorize(req, res) {
  try {
    const { sessionOauth } = await validateAuthorizeRequest(req.query);
    req.session.oauth = sessionOauth;

    req.session.save(() => {
      res.render("login");
    });
  } catch (err) {
    if (err instanceof AppError) {
      return res.status(err.status).send(err.message);
    }
    console.error(err);
    return res.status(500).send("Internal Server Error");
  }
}

async function login(req, res) {
  try {
    const data = await loginAndCreateAuthCode(req.body, req.session.oauth);
    delete req.session.oauth;
    return res.redirect(data.redirectUrl);
  } catch (err) {
    if (err instanceof AppError) {
      return res.status(err.status).json({ message: err.message });
    }
    console.error(err);
    return res.status(500).json({ message: "Internal Server Error" });
  }
}

async function token(req, res) {
  try {
    const { grant_type } = req.body;

    if (!grant_type) {
      throw new OAuthError(400, "invalid_request", "Missing grant_type");
    }

    let responsePayload;
    if (grant_type === "authorization_code") {
      responsePayload = await exchangeAuthorizationCode(req.body);
    } else if (grant_type === "refresh_token") {
      responsePayload = await exchangeRefreshToken(req.body);
    } else {
      throw new OAuthError(
        400,
        "unsupported_grant_type",
        "Supported grant_type: authorization_code, refresh_token",
      );
    }

    res.set("Cache-Control", "no-store");
    res.set("Pragma", "no-cache");
    return res.json(responsePayload);
  } catch (err) {
    if (err instanceof OAuthError) {
      return res.status(err.status).json({
        error: err.code,
        error_description: err.description,
      });
    }

    if (err instanceof AppError) {
      return res.status(err.status).json({ message: err.message });
    }

    console.error("/token error", err);
    return res.status(500).json({
      error: "server_error",
      error_description: "Internal Server Error",
    });
  }
}

async function logout(req, res) {
  try {
    const data = await logoutBySessionId(req.user.sessionId);
    return res.json(data);
  } catch (err) {
    return handleControllerError(res, err);
  }
}

async function logoutAll(req, res) {
  try {
    const sessionUserId = req.user.userId || req.user.sessionUserId;
    const data = await logoutAllByUserId(sessionUserId);
    return res.json(data);
  } catch (err) {
    return handleControllerError(res, err);
  }
}

async function sessionInfo(req, res) {
  return res.json({
    userId: req.user.userId || req.user.sessionUserId || null,
    sub: req.user.sub,
    sessionId: req.user.sessionId,
    active: true,
  });
}

async function userInfo(req, res) {
  try {
    const sessionUserId = req.user.userId || req.user.sessionUserId;
    const data = await getUserInfoBySession(req.user.sessionId, sessionUserId);
    return res.json(data);
  } catch (err) {
    if (err instanceof OAuthError) {
      return res.status(err.status).json({
        error: err.code,
        error_description: err.description,
      });
    }
    return handleControllerError(res, err);
  }
}

function userInfoBackwardCompatibility(req, res, next) {
  req.url = "/userinfo";
  return next();
}

module.exports = {
  register,
  registerOAuth,
  listOAuth,
  authorize,
  login,
  token,
  logout,
  logoutAll,
  sessionInfo,
  userInfo,
  userInfoBackwardCompatibility,
};
