const express = require("express");
const bcrypt = require("bcryptjs");
const { envConfig } = require("./config/config.js");
const { connectDB } = require("./config/db.js");
const User = require("./model/user.js");
const Session = require("./model/session.js");
const AuthCode = require("./model/authCode.js");
const { v4: uuidv4 } = require("uuid");
const {
  generateRefreshToken,
  generateToken,
} = require("./services/tokenService.js");
const session = require("express-session");

const app = express();

app.use(express.json());
app.use(
  session({
    secret: envConfig.SSO_SECRET,
    resave: false,
    saveUninitialized: false,
  }),
);
app.use(express.urlencoded({ extended: true }));

app.set("view engine", "ejs");
connectDB();

app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  const hashed = await bcrypt.hash(password, envConfig.SALT_ROUNDS);

  await User.create({
    email,
    password: hashed,
  });

  res.json({ message: "Register successfully" });
});

app.get("/authorize", (req, res) => {
  const { client_id, redirect_uri } = req.query;

  if (!client_id || !redirect_uri) {
    return res.status(400).send("Invalid request");
  }

  req.session.oauth = {
    client_id,
    redirect_uri,
  };

  res.render("login");
});

app.post("/login", async (req, res) => {
  const { email, password, deviceId, deviceType } = req.body;

  if (!req.session.oauth) {
    return res.status(400).send("Unauthorized flow");
  }

  const { client_id, redirect_uri } = req.session.oauth;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: "user not found" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ message: "user not found" });

  // mobile จำกัดต่อ 1 เครื่อง
  if (deviceType === "mobile") {
    const existing = await Session.findOne({
      deviceId,
      deviceType: "mobile",
      isActive: true,
    });

    if (existing && existing.userId.toString() !== user._id.toString()) {
      return res.status(400).json({
        message: "device already used by another account",
      });
    }
  }

  const code = uuidv4();

  await AuthCode.create({
    code,
    userId: user._id,
    clientId: client_id,
    redirectUri: redirect_uri,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000),
  });

  delete req.session.oauth;

  res.redirect(`${redirect_uri}?code=${code}`);
});

app.post("/token", async (req, res) => {
  const { code, deviceId, deviceType } = req.body;

  const authCode = await AuthCode.findOne({ code });

  if (!authCode) {
    return res.status(400).json({ message: "Invalid code" });
  }

  if (authCode.expiresAt < new Date()) {
    return res.status(400).json({ message: "Code expired" });
  }

  const accessToken = generateToken({ id: authCode.userId });

  const session = await Session.create({
    userId: authCode.userId,
    deviceId,
    deviceType,
  });
  const refreshToken = generateRefreshToken(session._id.toString());
  session.refreshToken = refreshToken;
  await session.save();

  await AuthCode.deleteOne({ code });

  res.json({
    accessToken,
    refreshToken,
  });
});

app.post("/logout", async (req, res) => {
  const { refreshToken } = req.body;

  await Session.updateOne({ refreshToken }, { isActive: false });

  res.json({ message: "logout success" });
});

app.post("/logout-all", async (req, res) => {
  const { userId } = req.body;

  await Session.updateMany({ userId }, { isActive: false });

  res.json({ message: "global logout success" });
});

app.listen(envConfig.PORT, () => {
  console.log(`Server is running on port http://localhost:${envConfig.PORT}`);
});
