# Flow SSO project

## ✅ FINAL CLEAN SEQUENCE DIAGRAM

![FLOW-DIAGRAM](./sso-flow.png)

## 🔄 REFRESH FLOW

![REFRESH-FLOW](./token-flow.png)

## 🚪 LOGOUT FLOW

![LOGOUT-FLOW](./logout-flow.png)

## Redis Final Data Structure

session:<sessionId>
{
userId,
deviceId,
deviceType,
refreshToken
}

userSession:<userId> (SET)

- sessionId1
- sessionId2

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

#### 🔐 STEP 1 — User กด Login ที่ ClientA

• User เข้า GET /login
• Browser ถูก redirect ไป sso_server/authorize?
• query ที่ส่งไปมี client_id และ redirect_uri

#### 🔑 STEP 2 — เข้า SSO /authorize

• นำ query ที่มาได้เก็บไว้ใน session
• แสดงหน้า login

#### 👤 STEP 3 — User login ที่ SSO

• ตรวจสอบ user + password กับ database
• check กับ redis ว่าถ้าเป็น mobile แล้วมี mobile อื่น login อยู่ไหม
• สร้าง Authorization code
• บันทึก Authorization code ลง AuthCode database อายุ 5 นาที
• redirect กลับ ClientA โดยแถม Authorization Code กลับไปทาง params

#### 🔁 STEP 4 — ClientA รับ code

• รับ Authorization code มาทาง /callback?code=xxxx
• นำ code ที่ได้มาแนบ id ของ device ส่งผ่าน body ไปที่ sso_server/token โดย body คือ { code, client_id, redirect_uri, deviceId, deviceType }
• redirect ไปที่ sso_server/token

#### 🎟 STEP 5 — SSO /token

• นำ body ที่ได้มาจาก ClentA ตรวจ code เชคกับ database
• เชค client_id และ redirect_uri ว่ามีส่งมาหรือไม่
• สร้าง sessionId ผ่าน uuidv4()
• sign refreshToken
• สร้าง session ใน redis ชื่อ session:{sessionId}
• เก็บ session user ใน set ชื่อ userSession:{userId}
• ตอนนี้ redis จะมี
session:abc123 → { userId, deviceId, refreshToken }
userSessions:userid → Set(abc123)
• สร้าง accessToken
• ลบ Authorization code ออกจาก database
• ส่ง access+refresh กลับไปทาง ClientA

#### 🧾 STEP 6 — ClientA เก็บ token ใน session

• req.session.user = { accessToken, refreshToken, userId }

#### 🔄 STEP 7 — Client เรียก API ที่ต้องใช้ auth

• ก่อนยิง request check refreshToken และ AccessToken ผ่าน headers โดยใช้ flow refreshToken

#### 🛡 STEP 8 — SSO verifySession

• เชคถ้าไม่มี token => 401, token หมดอายุ => 401, session ไม่มีใน redis => 401

#### 🔄 STEP 9 — Access token หมดอายุ

• หมดอายุขึ้น 401 interceptor ส่งไป post sso_server/refresh ตอนยิง

#### 🔁 STEP 10 — SSO /refresh

• นำ refreshToken ที่ได้มาจาก ClientA มา verify
• เชค session ใน Redis และเชค refreshToken ที่ได้มาว่าตรงกับ refreshToken ใน redis ไหม
• สร้าง refresh token ใหม่รวมถึง update session ใน redis ใหม่
• สร้าง accessToken แล้วส่งกลับ client

#### 🚪 STEP 11 — Logout เฉพาะเครื่อง

• ส่งไป post sso_server/logout
• ลบ session:{sessionId}
• userSession:{userId},sessionId ลบแค่ sessionId นั้นใน set user

#### 🌍 STEP 12 — Logout All

• ลบทุก session
• ลบ set ทั้งก้อน
