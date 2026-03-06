require("dotenv").config();

const envConfig = {
  APP_SESSION_SECRET: process.env.APP_SESSION_SECRET,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  CLIENT_ID: process.env.CLIENT_ID,
  SSO_SERVER: process.env.SSO_SERVER,
  REDIRECT_URI: process.env.REDIRECT_URI,
  REDIS_URL: process.env.REDIS_URL,
  PORT: process.env.PORT,
};

module.exports = envConfig;
