# Sekuvo Admin Panel 🔐

A secure admin panel for Sekuvo — protected by USB authentication.

## Features
- 🔑 Passkey Authentication (WebAuthn/FIDO2) — sign in using your phone's biometrics or a hardware security key instead of a password
-📱 Multi-device support — register multiple authenticators (phone, security key) and manage them from the dashboard, each shown with a name and last-used date
-🔒 Machine Lock — sessions are bound to the authorized machine
-⏱️ 15-minute session timeout — auto-expiring JWT-based sessions
-🚫 Rate limiting — 3 failed attempts then a 15-minute block
-🆘 Emergency recovery code — one-time-use recovery code emailed to registered addresses if all authenticators are lost (never shown on screen, invalidated on regeneration)
-📋 Activity Logs — track registration and login activity per device

## Tech Stack
- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Node.js, Express
- **Auth:** JWT + HMAC-SHA256 Encrypted USB Key

## Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/raghupatil1007/sekuvo-admin.git
cd sekuvo-admin
```

### 2. Install dependencies
```bash
cd backend
npm install
```

### 3. Generate your USB key
```bash
node generateKey.js
```
Copy the output to your pendrive as `sekuvo-key.json`

### 4. Update allowed machine
In `backend/server.js`


## Security
- USB key is HMAC-SHA256 encrypted
- Machine locked — only authorized machine can access
- Session expires in 15 minutes
- 3 wrong attempts = 15 minute block

## ⚠️ Important
- Never share your `sekuvo-key.json` file
- Never commit `sekuvo-key.json` to GitHub
- Keep your `SECRET_MASTER` safe in `server.js`

---
Built by Sekuvo Team 🚀
