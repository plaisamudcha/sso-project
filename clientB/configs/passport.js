const OAuth2Strategy = require('passport-oauth2');
const envConfig = require('./config');
const { verifyIdToken } = require('../utils/helper');
const jwt = require('jsonwebtoken');
const passport = require('passport');

class DeviceAwareOAuth2Strategy extends OAuth2Strategy {
  authenticate(req, options = {}) {
    options.deviceId = req.session.browserId;
    options.deviceType = "browser";

    // PKCE from session
    options.codeVerifier = req.session.pkceVerifier;
    options.codeChallenge = req.session.pkceChallenge;
    options.codeChallengeMethod = "S256";

    // if OIDC login, add scope and nonce
    if (String(options.scope || "").includes("openid")) {
      options.nonce = req.session.oidcNonce;
    }

    return super.authenticate(req, options);
  }

  authorizationParams(options) {
    const params = {};
    if (options.nonce) {
      params.nonce = options.nonce;
    }

    if (options.codeChallenge) {
      params.code_challenge = options.codeChallenge;
      params.code_challenge_method = options.codeChallengeMethod || "S256";
    }

    return params;
  }

  tokenParams(options) {
    return {
      grant_type: "authorization_code",
      code_verifier: options.codeVerifier,
      deviceId: options.deviceId,
      deviceType: options.deviceType,
      client_id: envConfig.CLIENT_ID,
      redirect_uri: envConfig.REDIRECT_URI,
    };
  }
}

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

passport.use(
  "sso",
  new DeviceAwareOAuth2Strategy(
    {
      authorizationURL: `${envConfig.SSO_SERVER}/authorize`,
      tokenURL: `${envConfig.SSO_SERVER}/token`,
      clientID: envConfig.CLIENT_ID,
      clientSecret: envConfig.CLIENT_SECRET,
      callbackURL: envConfig.REDIRECT_URI,
      state: true,
      passReqToCallback: true,
    },
    async (req, accessToken, refreshToken, params, _profile, done) => {
      try {
        console.log("token params", params);

        const expectedNonce = req.session.oidcNonce || null;
        const expectsOidc = Boolean(expectedNonce);

        if (expectsOidc && !params.id_token) {
          return done(null, false, { message: "Missing id_token" });
        }

        let idTokenClaims = null;
        if (params.id_token) {
          idTokenClaims = await verifyIdToken(params.id_token, {
            issuer: envConfig.SSO_SERVER,
            audience: envConfig.CLIENT_ID,
            nonce: expectedNonce,
          });
          console.log("verified id_token claims:", idTokenClaims);
        }

        const payload = jwt.decode(accessToken) || {};

        // PKCE/nonce are one-time values per auth attempt.
        delete req.session.pkceVerifier;
        delete req.session.pkceChallenge;
        delete req.session.oidcNonce;

        return done(null, {
          userId: payload.userId,
          sessionId: payload.sessionId,
          accessToken,
          refreshToken,
          idToken: params.id_token,
          idTokenClaims,
        });
      } catch (err) {
        return done(err);
      }
    },
  ),
);


