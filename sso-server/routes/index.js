const express = require("express");
const authRoutes = require("./authRoutes");
const discoveryRoutes = require("./discoveryRoutes");

const router = express.Router();

router.use(authRoutes);
router.use(discoveryRoutes);

module.exports = router;
