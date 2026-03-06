# Flow SSO project

## ✅ FINAL CLEAN SEQUENCE DIAGRAM

![FLOW-DIAGRAM](./assets/sso-flow.png)

## 🔄 REFRESH FLOW

![REFRESH-FLOW](./assets/token-flow.png)

## 🚪 LOGOUT FLOW

![LOGOUT-FLOW](./assets/logout-flow.png)

## 🌍 GLOBAL LOGOUT FLOW

![GLOBAL-LOGOUT-FLOW](./assets/global-logout-flow.png)

## Redis Final Data Structure

session:<sessionId>
{
userId,
deviceId,
deviceType,
refreshToken
}

userSessions:<userId> (SET)
Set [
sessionId1
sessionId2
sessionId3
]

deviceSession:<deviceType>:<deviceId>
sessionId

sess:{sessionId}
{
oauth: {
client_id,
redirect_uri,
state
}
}

## MongoDB

User
{
id,
email,
password
}

AuthCode
{
code,
userId,
clientId,
redirectUri,
expiresAt
}

oAuthClients
{
name,
clientId,
clientSecret,
redirectUris[]
}

## ภาพรวม Architecture (3 ระบบ)

#### 1️⃣ SSO Server (Auth Center)

• login
• issue authorization code
• exchange token
• manage session ใน Redis
• refresh
• logout / logout-all

#### 2️⃣ ClientA

• redirect ไป SSO
• รับ code
• ขอ access/refresh token
• เก็บไว้ใน express-session
• auto refresh ถ้า 401

#### 3️⃣ ClientB (Passport OAuth2)

• redirect ไป SSO ผ่าน passport-oauth2
• รับ code แล้วแลก token ผ่าน OAuth2 strategy
• เก็บ user/token ใน passport session
• auto refresh ถ้า 401
• verify upstream session ผ่าน /session-info

## Flow Step

#### STEP 0 — Developer Register OAuth Client

• Developer เรียก /register-oauth-client
• sso_server สร้าง { client_id, client_secret, redirect_uris } เก็บใน OAuthClients
• client นำ client_id กับ client_secret ไปใช้

#### 🔐 STEP 1 — User กด Login ที่ ClientA

• User เข้า GET /login
• ClientA สร้าง state แล้วเก็บใน req.session.oauthState
• Browser ถูก redirect ไป /authorize?client_id=xxx&redirect_uri=xxx&state=xxx
• query ที่ส่งไปมี client_id, redirect_uri และ state

#### 🔑 STEP 2 — เข้า SSO /authorize

• ตรวจว่า client_id และ redirect_uri ถูกต้องหรือไม่ (ตรวจจาก OAuthClients)
• เก็บข้อมูล req.session.oauth = { client_id, redirect_uri, state } ใน redis
• แสดงหน้า login page

#### 👤 STEP 3 — User login ที่ SSO

• POST /login ส่ง body = { email, password }
• เชค email, password ใน Users
• gen code ผ่าน uuid() บันทึกลงใน Authorization Code
• redirect กลับ /redirect_uri?code=xxxx&state=xxxx

#### 🔁 STEP 4 — ClientA รับ code

• รับ Authorization code และ state มาทาง /callback?code=xxxx&state=xxxx
• verify state กับ req.session.oauthState
• client เรียก /token ส่ง body = {code, client_id, redirect_uri, deviceId, deviceType }

#### 🎟 STEP 5 — SSO /token

• ตรวจ code จาก Authorization code ใน DB
• เชค mandatory body = { code, client_id, redirect_uri, deviceId, deviceType }
• เชค deviceType ต้องเป็น mobile หรือ browser เท่านั้น
• เชค key redis: deviceSession:{deviceType}:{deviceId}
• ถ้ามี session เดิมบน device/browser เดียวกัน จะลบ session เก่าก่อน (1 account ต่อ 1 device/browser)
• สร้าง sessionId ผ่าน uuidv4()
• sign refreshToken
• สร้าง session ใน redis ชื่อ session:{sessionId} = { userId, deviceId, deviceType, refreshToken, isActive } TTL 7 วัน
• เพิ่ม session เข้า redis ชื่อ userSessions:{userId} = Set(sessionId)
• set redis key deviceSession:{deviceType}:{deviceId} = sessionId (TTL 7 วัน)
• สร้าง accessToken จาก payload = { userId, sessionId }
• ลบ Authorization code ออกจาก DB
• ส่ง token กลับ client = { access_token, token_type, expires_in, refresh_token }

#### 🧾 STEP 6 — ClientA เก็บ token ใน session

• req.session.user = { accessToken, refreshToken, tokenType, expiresIn, userId, sessionId }

#### 🔄 STEP 7 — Client เรียก API ที่ต้องใช้ auth

• client ส่ง Authorization: Bearer accessToken ไปยัง API

#### 🛡 STEP 8 — SSO verifySession

• decode accessToken ได้ { userId, sessionId } ตรวจ redis ชื่อ session:{sessionId}
• ถ้าไม่มี session return 401 Unauthorized

#### 🔄 STEP 9 — Access token หมดอายุ

• หมดอายุขึ้น 401 interceptor ส่งไป POST /refresh

#### 🔁 STEP 10 — SSO /refresh

• รับ refreshToken มา decode ได้ sessionId ตรวจกับ redis ชื่อ session:{sessionId} ว่าตรงกันไหม
• สร้าง newRefreshToken
• อัพเดต redis session.refreshToken = newRefreshToken
• ต่ออายุ deviceSession:{deviceType}:{deviceId} ให้ผูกกับ sessionId เดิม
• สร้าง newAccessToken
• ส่งกลับ client = { access_token, token_type, expires_in, refresh_token }

#### 🔍 STEP 10.1 — Cross-client Session Sync

• ClientA/ClientB เรียก GET /session-info เพื่อตรวจว่า session ยัง active บน SSO
• ถ้า /session-info ตอบ 401 ให้ลบ local session แล้วถือว่า logout แล้ว

#### 🚪 STEP 11 — Logout เฉพาะเครื่อง

• ส่งไป POST /logout
• ลบ session:{sessionId}
• ลบ sessionId นั้นออกจาก userSessions:{userId}
• ลบ key deviceSession:{deviceType}:{deviceId} ของเครื่องนั้น

#### 🌍 STEP 12 — Logout All Devices

• POST /logout-all
• SMEMBERS userSessions:{userId}
• DEL session:{sessionId} ทุกตัว
• DEL deviceSession:{deviceType}:{deviceId} ทุกตัวที่อ้างถึง session ของ user นี้
• DEL userSessions:{userId}
