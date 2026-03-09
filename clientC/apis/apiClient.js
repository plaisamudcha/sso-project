const axios = require("axios");
const envConfig = require("../configs/config");

function createApiClient(req) {
  const api = axios.create({
    baseURL: envConfig.SSO_SERVER,
  });

  api.interceptors.request.use((config) => {
    if (req.session.user?.accessToken) {
      config.headers.Authorization = `Bearer ${req.session.user.accessToken}`;
    }
    return config;
  });

  api.interceptors.response.use(
    (res) => res,
    async (error) => {
      const original = error.config || {};

      if (
        error.response?.status === 401 &&
        req.session.user?.refreshToken &&
        !original._retry
      ) {
        original._retry = true;

        try {
          const refreshRes = await axios.post(`${envConfig.SSO_SERVER}/token`, {
            grant_type: "refresh_token",
            refresh_token: req.session.user.refreshToken,
            client_id: envConfig.CLIENT_ID,
            client_secret: envConfig.CLIENT_SECRET,
          });

          const accessToken =
            refreshRes.data.access_token || refreshRes.data.accessToken;
          const refreshToken =
            refreshRes.data.refresh_token || refreshRes.data.refreshToken;

          if (!accessToken || !refreshToken) {
            throw new Error("Invalid refresh token response payload");
          }

          if (req.session.user) {
            req.session.user.accessToken = accessToken;
            req.session.user.refreshToken = refreshToken;
          }

          original.headers = original.headers || {};
          original.headers.Authorization = `Bearer ${accessToken}`;
          return api(original);
        } catch (refreshErr) {
          req.session.user = null;
          req.session.destroy(() => { });
          return Promise.reject(refreshErr);
        }
      }

      return Promise.reject(error);
    },
  );

  return api;
}

module.exports = { createApiClient };