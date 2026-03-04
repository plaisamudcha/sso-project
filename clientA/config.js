const dotenv = require("dotenv");

dotenv.config();

const envConfig = {
  CLIENTA_SECRET: process.env.CLIENTA_SECRET,
  CLIENT_ID: process.env.CLIENT_ID,
  SSO_SERVER: process.env.SSO_SERVER,
  REDIRECT_URI: process.env.REDIRECT_URI,
  PORT: process.env.PORT,
  REDIS_URL: process.env.REDIS_URL,
};

module.exports = { envConfig };
