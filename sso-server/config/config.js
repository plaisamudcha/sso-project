const dotenv = require("dotenv");

dotenv.config();

const envConfig = {
  MONGODB_URI: process.env.MONGODB_URI,
  ACCESS_SECRET: process.env.ACCESS_SECRET,
  REFRESH_SECRET: process.env.REFRESH_SECRET,
  SALT_ROUNDS: Number(process.env.SALT_ROUNDS),
  PORT: process.env.PORT,
  SSO_SECRET: process.env.SSO_SECRET,
};

module.exports = { envConfig };
