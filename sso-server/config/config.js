const dotenv = require("dotenv");

dotenv.config();

const requiredEnvVars = [
  "MONGODB_URI",
  "ACCESS_SECRET",
  "REFRESH_SECRET",
  "SSO_SECRET",
  "REDIS_URL",
  "ISSUER",
  "OIDC_PRIVATE_KEY_PATH",
  "OIDC_PUBLIC_KEY_PATH",
  "OIDC_KID",
  "ADMIN_API_KEY",
  "NODE_ENV",
  "PORT",
];

for (const key of requiredEnvVars) {
  if (!process.env[key]) {
    throw new Error(`Environment variable ${key} is required but not set.`);
  }
}

const saltRounds = Number(process.env.SALT_ROUNDS);
if (!Number.isInteger(saltRounds) || saltRounds <= 0) {
  throw new Error("SALT_ROUNDS must be a positive integer.");
}

const port = Number(process.env.PORT);
if (!Number.isInteger(port) || port <= 0 || port > 65535) {
  throw new Error("PORT must be a valid integer between 1 and 65535.");
}

const envConfig = {
  MONGODB_URI: process.env.MONGODB_URI,
  ACCESS_SECRET: process.env.ACCESS_SECRET,
  REFRESH_SECRET: process.env.REFRESH_SECRET,
  SALT_ROUNDS: saltRounds,
  PORT: port,
  SSO_SECRET: process.env.SSO_SECRET,
  REDIS_URL: process.env.REDIS_URL,
  NODE_ENV: process.env.NODE_ENV,

  // OIDC
  ISSUER: process.env.ISSUER,
  OIDC_PRIVATE_KEY_PATH: process.env.OIDC_PRIVATE_KEY_PATH,
  OIDC_PUBLIC_KEY_PATH: process.env.OIDC_PUBLIC_KEY_PATH,
  OIDC_KID: process.env.OIDC_KID,
  ADMIN_API_KEY: process.env.ADMIN_API_KEY,
};

module.exports = { envConfig };
