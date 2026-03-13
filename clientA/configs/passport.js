const passport = require("passport");
const OAuth2Strategy = require("passport-oauth2");

const { envConfig } = require("../config");
const { parseJwt, verifyIdToken } = require("../helper");

class DeviceAwareOAuth2Strategy extends OAuth2Strategy {
  authenticate(req, options = {}) {
    options.deviceId = req.session.browserId;
    options.deviceType = "browser";
    options.codeVerifier = req.session.pkceVerifier;
    options.codeChallenge = req.session.pkceChallenge;
    options.codeChallengeMethod = "S256";

    if (String(options.scope || "").includes("openid")) {
      options.nonce = req.session.oauthNonce;
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
      authorizationURL: `${envConfig.SSO_FRONT}/login`,
      tokenURL: `${envConfig.SSO_SERVER}/oauth/token`,
      clientID: envConfig.CLIENT_ID,
      clientSecret: envConfig.CLIENT_SECRET,
      callbackURL: envConfig.REDIRECT_URI,
      state: true,
      passReqToCallback: true,
    },
    async (req, accessToken, refreshToken, params, _profile, done) => {
      try {
        const expectedNonce = req.session.oauthNonce || null;
        const expectsOidc = Boolean(expectedNonce);

        if (expectsOidc && !params.id_token) {
          return done(null, false, { message: "Missing id_token for OIDC login" });
        }

        let idTokenClaims = null;
        if (params.id_token) {
          idTokenClaims = await verifyIdToken(params.id_token, {
            issuer: envConfig.ISSUER,
            audience: envConfig.CLIENT_ID,
            nonce: expectedNonce,
          });
        }

        const tokenPayload = parseJwt(accessToken);

        delete req.session.pkceVerifier;
        delete req.session.pkceChallenge;
        delete req.session.oauthNonce;

        return done(null, {
          accessToken,
          refreshToken,
          tokenType: params.token_type,
          expiresIn: params.expires_in,
          sub: tokenPayload.sub,
          sessionId: tokenPayload.sessionId,
          scope: tokenPayload.scope || "",
          idTokenClaims,
        });
      } catch (err) {
        return done(err);
      }
    },
  ),
);

module.exports = passport;