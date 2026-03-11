const bcrypt = require("bcryptjs");
const { findByClientId } = require("../repositories/oauthClientRepository");
const { OAuthError } = require("./errors");

async function validateTokenClient(clientId, clientSecret) {
  if (!clientId) {
    throw new OAuthError(400, "invalid_request", "Missing client_id");
  }

  const client = await findByClientId(clientId);
  if (!client) {
    throw new OAuthError(401, "invalid_client", "Client not found");
  }

  const hasClientSecret =
    typeof client.clientSecret === "string" && client.clientSecret.length > 0;

  if (hasClientSecret) {
    if (!clientSecret) {
      throw new OAuthError(401, "invalid_client", "Missing client_secret");
    }

    let validSecret = false;
    const looksBcryptHash = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(
      client.clientSecret || "",
    );

    if (looksBcryptHash) {
      validSecret = await bcrypt.compare(clientSecret, client.clientSecret);
    } else {
      validSecret = clientSecret === client.clientSecret;
    }

    if (!validSecret) {
      throw new OAuthError(401, "invalid_client", "Invalid client_secret");
    }
  }

  if (!hasClientSecret && clientSecret) {
    throw new OAuthError(
      400,
      "invalid_request",
      "client_secret must not be sent for public clients",
    );
  }

  return client;
}

module.exports = {
  validateTokenClient,
};
