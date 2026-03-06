// Libraries
const express = require("express");
const axios = require("axios");
const session = require("express-session");
const { RedisStore } = require("connect-redis");
const { createClient } = require("redis");
const { v4: uuidv4 } = require("uuid");

// Utilities
const { createApiClient } = require("./services/apiClient");
const { parseJwt } = require("./helper");
const { envConfig } = require("./config");

const app = express();
const redisClient = createClient({
  url: envConfig.REDIS_URL,
});

redisClient.connect().catch(console.error);

app.use(
  session({
    store: new RedisStore({ client: redisClient }),
    secret: envConfig.APP_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false },
  }),
);
app.use((req, res, next) => {
  if (!req.session.browserId) {
    req.session.browserId = uuidv4();
  }
  next();
});

app.set("view engine", "ejs");

app.get("/", (req, res) => {
  res.render("home", {
    user: req.session.user,
  });
});

app.get("/login", (req, res) => {
  const url = `${envConfig.SSO_SERVER}/authorize?client_id=${envConfig.CLIENT_ID}&redirect_uri=${envConfig.REDIRECT_URI}`;
  res.redirect(url);
});

app.get("/callback", async (req, res) => {
  const { code } = req.query;

  try {
    const tokenResponse = await axios.post(`${envConfig.SSO_SERVER}/token`, {
      code,
      client_id: envConfig.CLIENT_ID,
      redirect_uri: envConfig.REDIRECT_URI,
      deviceId: req.session.browserId,
      deviceType: "browser",
    });

    const { accessToken, refreshToken } = tokenResponse.data;

    req.session.user = {
      accessToken,
      refreshToken,
      userId: parseJwt(accessToken).userId,
    };

    console.log("user logged in", req.session.user);

    res.redirect("/");
  } catch (err) {
    res.send("login failed");
  }
});

app.get("/profile", async (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
  }

  res.render("profile", {
    user: req.session.user,
  });
});

app.get("/logout", async (req, res) => {
  const api = createApiClient(req);

  try {
    await api.post("/logout");
  } catch (err) {
    // SSO server อาจ return 401 ถ้า token หมดอายุแล้ว
    // ไม่ต้อง block การ logout ฝั่ง client
    console.error("SSO logout error:", err.message);
  }

  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.get("/logout-all", async (req, res) => {
  const api = createApiClient(req);

  try {
    await api.post("/logout-all");
  } catch (err) {
    // SSO server อาจ return 401 ถ้า token หมดอายุแล้ว
    // ไม่ต้อง block การ logout ฝั่ง client
    console.error("SSO global logout error:", err.message);
  }

  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.listen(envConfig.PORT, () => {
  console.log(`ClientA is running on port http://localhost:${envConfig.PORT}`);
});
