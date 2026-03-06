const axios = require("axios");
const envConfig = require("../config");

function createApiClient(req) {
  const api = axios.create({
    baseURL: envConfig.SSO_SERVER,
  });

  api.interceptors.request.use((config) => {
    if (req.user?.accessToken) {
      config.headers.Authorization = `Bearer ${req.user.accessToken}`;
    }
    return config;
  });

  api.interceptors.response.use(
    (res) => res,
    async (error) => {
      const original = error.config || {};

      if (
        error.response?.status === 401 &&
        req.user?.refreshToken &&
        !original._retry
      ) {
        original._retry = true;

        try {
          const refreshRes = await axios.post(
            `${envConfig.SSO_SERVER}/refresh`,
            {
              refreshToken: req.user.refreshToken,
            },
          );

          const { accessToken, refreshToken } = refreshRes.data;

          req.user.accessToken = accessToken;
          req.user.refreshToken = refreshToken;

          await new Promise((resolve, reject) => {
            req.login(req.user, (err) => (err ? reject(err) : resolve()));
          });

          original.headers = original.headers || {};
          original.headers.Authorization = `Bearer ${accessToken}`;
          return api(original);
        } catch (refreshErr) {
          await new Promise((resolve) => req.logout(() => resolve()));
          req.session.destroy(() => {});
          return Promise.reject(refreshErr);
        }
      }

      return Promise.reject(error);
    },
  );

  return api;
}

module.exports = { createApiClient };
