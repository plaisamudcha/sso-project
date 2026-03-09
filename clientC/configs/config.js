require("dotenv").config();

const envConfig = {
  NODE_ENV: process.env.NODE_ENV || "development",
  APP_SESSION_SECRET: process.env.APP_SESSION_SECRET,
  ID_TOKEN_SECRET: process.env.ID_TOKEN_SECRET,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  CLIENT_ID: process.env.CLIENT_ID,
  SSO_SERVER: process.env.SSO_SERVER,
  REDIRECT_URI: process.env.REDIRECT_URI,
  REDIS_URL: process.env.REDIS_URL,
  PORT: process.env.PORT,
};

module.exports = envConfig;