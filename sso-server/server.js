const express = require("express");
const session = require("express-session");
const cors = require("cors");
const { RedisStore } = require("connect-redis");
const { envConfig } = require("./config/config");
const { connectDB } = require("./config/db");
const redisClient = require("./config/redis");
const routes = require("./routes");

const app = express();

app.use(express.json());
app.use(
  cors({
    origin: [
      "http://localhost:5000",
      "http://localhost:5002",
      "http://localhost:5003",
    ],
    methods: ["GET", "POST"],
    credentials: true,
  }),
);

const isProd = envConfig.NODE_ENV === "production";
app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(
  session({
    name: "sso.sid",
    store: new RedisStore({ client: redisClient }),
    secret: envConfig.SSO_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: isProd,
      sameSite: isProd ? "none" : "lax",
      httpOnly: true,
    },
  }),
);

app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");

connectDB();
app.use(routes);

app.get("/validate-token", (_req, res) => {
  return res.status(501).json({ message: "Not implemented" });
});

app.listen(envConfig.PORT, () => {
  console.log(`Server is running on port http://localhost:${envConfig.PORT}`);
});
