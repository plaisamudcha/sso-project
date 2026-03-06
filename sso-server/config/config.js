const dotenv = require("dotenv");

dotenv.config();

const envConfig = {
  MONGODB_URI: process.env.MONGODB_URI,
  ACCESS_SECRET: process.env.ACCESS_SECRET,
  REFRESH_SECRET: process.env.REFRESH_SECRET,
  SALT_ROUNDS: Number(process.env.SALT_ROUNDS),
  PORT: process.env.PORT,
  SSO_SECRET: process.env.SSO_SECRET,
  REDIS_URL: process.env.REDIS_URL,

  // OIDC
  ISSUER: process.env.ISSUER,
  ID_TOKEN_SECRET: process.env.ID_TOKEN_SECRET,
};

module.exports = { envConfig };
