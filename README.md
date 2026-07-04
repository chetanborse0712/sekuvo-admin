# Sekuvo Admin Panel 🔐

A secure admin panel for Sekuvo — protected by USB authentication.

## Features
- 🔑 USB Key Authentication
- 🔒 Machine Lock — runs only on authorized machine
- ⏱️ 15 minute session timeout
- 🚫 Rate limiting — 3 attempts then 15 min block
- 🔐 Encrypted key verification
- 📋 Activity Logs

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