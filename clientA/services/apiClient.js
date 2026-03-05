const axios = require("axios");
const { envConfig } = require("../config");

function createApiClient(req) {
  const api = axios.create({
    baseURL: envConfig.SSO_SERVER,
  });

  // แนบ accessToken อัตโนมัติ
  api.interceptors.request.use((config) => {
    if (req.session.user?.accessToken) {
      config.headers.Authorization = `Bearer ${req.session.user.accessToken}`;
    }

    return config;
  });

  // จัดการ 401 => refresh
  api.interceptors.response.use(
    (res) => res,
    async (error) => {
      if (
        error.response?.status === 401 &&
        req.session.user?.refreshToken &&
        !error.config._retry
      ) {
        try {
          error.config._retry = true;

          const refreshRes = await axios.post(
            `${envConfig.SSO_SERVER}/refresh`,
            {
              refreshToken: req.session.user.refreshToken,
            },
          );

          const { accessToken, refreshToken } = refreshRes.data;

          // update session
          req.session.user.accessToken = accessToken;
          req.session.user.refreshToken = refreshToken;

          // retry old request
          error.config.headers.Authorization = `Bearer ${accessToken}`;
          return api(error.config);
        } catch (refreshError) {
          req.session.destroy(() => {});
          return Promise.reject(refreshError);
        }
      }
      return Promise.reject(error);
    },
  );

  return api;
}

module.exports = { createApiClient };
