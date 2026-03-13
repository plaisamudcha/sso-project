const crypto = require("crypto");
const redis = require("../config/redis");

const AUTH_CODE_TTL_SECONDS = 5 * 60;
const CONSUME_AUTH_CODE_LUA = [
  'local v = redis.call("GET", KEYS[1])',
  "if v then",
  '  redis.call("DEL", KEYS[1])',
  "end",
  "return v",
].join("\n");

function buildAuthCodeRedisKey(clientId, redirectUri, code) {
  const redirectHash = crypto
    .createHash("sha256")
    .update(String(redirectUri))
    .digest("hex");

  return `authcode:${clientId}:${redirectHash}:${code}`;
}

async function saveAuthCode(clientId, redirectUri, code, payload) {
  const key = buildAuthCodeRedisKey(clientId, redirectUri, code);
  await redis.set(key, JSON.stringify(payload), {
    EX: AUTH_CODE_TTL_SECONDS,
    NX: true,
  });
  return key;
}

async function consumeAuthCode(clientId, redirectUri, code) {
  const key = buildAuthCodeRedisKey(clientId, redirectUri, code);
  const raw = await redis.sendCommand(["EVAL", CONSUME_AUTH_CODE_LUA, "1", key]);

  return raw ? JSON.parse(raw) : null;
}

module.exports = {
  saveAuthCode,
  consumeAuthCode,
};
