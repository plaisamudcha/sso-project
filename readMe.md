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

userSession:<userId> (SET)
Set [
sessionId1
sessionId2
sessionId3
]

oauthSession:{sessionId}
{
client_id
redirect_uri
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
redeirectUris[]
}

## ภาพรวม Architecture (2 ระบบ)

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

## Flow Step

#### STEP 0 — Developer Register OAuth Client

• Developer เรียก /register-oauth-client
• sso_server สร้าง { client_id, client_secret, redirect_uris } เก็บใน OAuthClients
• client นำ client_id กับ client_secret ไปใช้

#### 🔐 STEP 1 — User กด Login ที่ ClientA

• User เข้า GET /login
• Browser ถูก redirect ไป /authorize?client_id=xxx&redirect_uri=xxx
• query ที่ส่งไปมี client_id และ redirect_uri

#### 🔑 STEP 2 — เข้า SSO /authorize

• ตรวจว่า client_id และ redirect_uri ถูกต้องหรือไม่ (ตรวจจาก OAuthClients)
• เก็บข้อมูล req.session.oauth = { client_id, redirect_uri } ใน redis
• แสดงหน้า login page

#### 👤 STEP 3 — User login ที่ SSO

• POST /login ส่ง body = { email, password, deviceType }
• เชค email, password ใน Users
• เชคถ้า deviceType = 'mobile' ไปเชค redis userSessions:{userId} ถ้ามี mobile session จะลบอันเก่า
• gen code ผ่าน uuid() บันทึกลงใน Authorization Code
• redirect กลับ /redirect_uri?code=xxxx

#### 🔁 STEP 4 — ClientA รับ code

• รับ Authorization code มาทาง /callback?code=xxxx
• client เรียก /token ส่ง body = {code, client_id, redirect_uri, deviceId, deviceType }

#### 🎟 STEP 5 — SSO /token

• ตรวจ code จาก Authorization code ใน DB
• เชค client_id และ redirect_uri ว่ามีส่งมาหรือไม่
• สร้าง sessionId ผ่าน uuidv4()
• sign refreshToken
• สร้าง session ใน redis ชื่อ session:{sessionId} = { userId, deviceId, deviceType, refreshToken, isActive } TTL 7 วัน
• เพิ่ม session เข้า redis ชื่อ userSession:{userId} = Set(sessionId)
• สร้าง accessToken จาก payload = { userId, sessionId }
• ลบ Authorization code ออกจาก DB
• ส่ง token กลับ client = { accessToken, refreshToken }

#### 🧾 STEP 6 — ClientA เก็บ token ใน session

• req.session.user = { accessToken, refreshToken }

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
• สร้าง newAccessToken
• ส่งกลับ client = { accessToken, refreshToken }

#### 🚪 STEP 11 — Logout เฉพาะเครื่อง

• ส่งไป POST /logout
• ลบ session:{sessionId}
• userSession:{userId},sessionId ลบแค่ sessionId นั้นใน set user

#### 🌍 STEP 12 — Logout All Devices

• POST /logout-all
• SMEMBERS userSession:{userId}
• DEL session:{sessionId}
• DEL userSessions:{userId}
