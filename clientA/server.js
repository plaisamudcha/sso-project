// Libraries
const express = require("express");
const axios = require("axios");
const session = require("express-session");
const { RedisStore } = require("connect-redis");
const { createClient } = require("redis");
const { v4: uuidv4 } = require("uuid");

// Utilities
const { envConfig } = require("./config");
const { parseJwt } = require("./helper");
const { createApiClient } = require("./services/apiClient");

const app = express();
const redisClient = createClient({
  url: envConfig.REDIS_URL,
});

redisClient.connect().catch(console.error);

app.use(
  session({
    store: new RedisStore({ client: redisClient }),
    secret: envConfig.CLIENTA_SECRET,
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

    // เก็บ refreshToken ใน redis
    await redisClient.set(`refresh:${req.session.browserId}`, refreshToken, {
      EX: 60 * 60 * 24 * 30,
    });

    // เก็บ accessToken ใน cookie
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 15 * 60 * 1000,
    });

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

  await api.post("/logout");

  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.listen(envConfig.PORT, () => {
  console.log(`ClientA is running on port http://localhost:${envConfig.PORT}`);
});
