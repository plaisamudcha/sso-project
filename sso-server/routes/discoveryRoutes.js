const express = require("express");
const {
  openIdConfiguration,
  jwksEndpoint,
} = require("../controllers/discoveryController");

const router = express.Router();

router.get("/.well-known/openid-configuration", openIdConfiguration);
router.get("/.well-known/jwks.json", jwksEndpoint);

module.exports = router;
