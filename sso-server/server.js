const express = require("express");
const bcrypt = require("bcryptjs");
const { envConfig } = require("./config/config.js");
const { connectDB } = require("./config/db.js");
const User = require("./model/user.js");
const AuthCode = require("./model/authCode.js");
const { v4: uuidv4 } = require("uuid");
const {
  generateRefreshToken,
  generateToken,
  verifyRefreshToken,
} = require("./services/tokenService.js");
const session = require("express-session");
const { verifySession } = require("./midlleware/auth.js");
const redis = require("./config/redis.js");

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
    const sessionIds = await redis.sMembers(`userSessions:${user._id}`);

    for (const id of sessionIds) {
      const sessionRaw = await redis.get(`session:${id}`);
      if (!sessionRaw) continue;

      const session = JSON.parse(sessionRaw);

      if (session.deviceType === "mobile") {
        await redis.del(`session:${id}`);
        await redis.sRem(`userSessions:${user._id}`, id);
      }
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

  const sessionId = uuidv4();

  const sessionData = {
    userId: authCode.userId.toString(),
    deviceId,
    deviceType,
    refreshToken: "",
    isActive: true,
  };

  // เก็บ session พร้อม TTL 7 วัน
  await redis.set(`session:${sessionId}`, JSON.stringify(sessionData), {
    EX: 60 * 60 * 24 * 7,
  });

  // เพิ่ม session เข้า userSessions
  await redis.sAdd(`userSessions:${authCode.userId}`, sessionId);

  const accessToken = generateToken({
    userId: authCode.userId,
    sessionId,
  });

  const refreshToken = generateRefreshToken(sessionId);

  // update refreshtoken ใน redis
  sessionData.refreshToken = refreshToken;

  await redis.set(`session:${sessionId}`, JSON.stringify(sessionData), {
    EX: 60 * 60 * 24 * 7,
  });

  await AuthCode.deleteOne({ code });

  res.json({
    accessToken,
    refreshToken,
  });
});

app.post("/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const payload = verifyRefreshToken(refreshToken);

    const sessionRaw = await redis.get(`session:${payload.sessionId}`);
    if (!sessionRaw) {
      return res.status(401).json({ message: "Invalid session" });
    }

    const session = JSON.parse(sessionRaw);

    if (session.refreshToken !== refreshToken) {
      return res.status(401).json({ message: "Token mismatch" });
    }

    // rotate refresh token
    const newRefreshToken = generateRefreshToken(payload.sessionId);

    // สร้าง access token ใหม่
    const newAccessToken = generateToken({
      userId: session.userId,
      sessionId: payload.sessionId,
    });

    session.refreshToken = newRefreshToken;

    await redis.set(`session:${payload.sessionId}`, JSON.stringify(session), {
      EX: 60 * 60 * 24 * 7,
    });

    res.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch (err) {
    return res.status(401).json({ message: "Invalid refresh token" });
  }
});

app.post("/logout", verifySession, async (req, res) => {
  await redis.del(`session:${req.user.sessionId}`);

  res.json({ message: "logout success" });
});

app.post("/logout-all", verifySession, async (req, res) => {
  const sessionIds = await redis.sMembers(`userSessions:${req.user.userId}`);

  for (const id of sessionIds) {
    await redis.del(`session:${id}`);
  }

  await redis.del(`userSession:${req.user.userId}`);

  res.json({ message: "global logout success" });
});

app.listen(envConfig.PORT, () => {
  console.log(`Server is running on port http://localhost:${envConfig.PORT}`);
});
