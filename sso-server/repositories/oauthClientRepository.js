const OAuthClient = require("../model/oAuthClient");

async function findByClientId(clientId) {
  return OAuthClient.findOne({ clientId });
}

async function createClient(payload) {
  return OAuthClient.create(payload);
}

async function findAllWithoutSecrets() {
  return OAuthClient.find({}, { clientSecret: 0, __v: 0 }).lean();
}

module.exports = {
  findByClientId,
  createClient,
  findAllWithoutSecrets,
};
