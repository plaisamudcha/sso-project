const fs = require("fs");
const crypto = require("crypto");
const path = require("path");
const { envConfig } = require("./config");

function resolveKeyPath(inputPath) {
  if (!inputPath) return inputPath;
  return path.isAbsolute(inputPath)
    ? inputPath
    : path.resolve(__dirname, "..", inputPath);
}

function candidatePaths(filePath) {
  const list = [filePath];

  // Accept both filename styles: oidc-private.pem and oidc_private.pem
  if (filePath.includes("_")) {
    list.push(filePath.replace(/_/g, "-"));
  }
  if (filePath.includes("-")) {
    list.push(filePath.replace(/-/g, "_"));
  }

  return [...new Set(list)];
}

function readKeyFile(envName, configuredPath) {
  const absPath = resolveKeyPath(configuredPath);
  const paths = candidatePaths(absPath);

  for (const p of paths) {
    if (fs.existsSync(p)) {
      return fs.readFileSync(p, "utf8");
    }
  }

  throw new Error(
    `${envName} points to a missing key file. Checked: ${paths.join(", ")}`,
  );
}

const privateKeyPem = readKeyFile(
  "OIDC_PRIVATE_KEY_PATH",
  envConfig.OIDC_PRIVATE_KEY_PATH,
);
const publicKeyPem = readKeyFile(
  "OIDC_PUBLIC_KEY_PATH",
  envConfig.OIDC_PUBLIC_KEY_PATH,
);

const publicJwk = crypto
  .createPublicKey(publicKeyPem)
  .export({ format: "jwk" });

const jwks = {
  keys: [
    {
      ...publicJwk,
      use: "sig",
      kid: envConfig.OIDC_KID,
      alg: "RS256",
    },
  ],
};

module.exports = {
  privateKeyPem,
  jwks,
  kid: envConfig.OIDC_KID,
};
