# Sekuvo Admin Panel 🔐

A secure admin panel for Sekuvo — protected by **WebAuthn (FIDO2) passkey
authentication**, replacing traditional passwords with passwordless,
phishing-resistant sign-in.

## Features

- 🔑 **Passkey Authentication (WebAuthn/FIDO2)** — sign in using your
  phone's biometrics or a hardware security key instead of a password
- 📱 **Multi-device support** — register multiple authenticators (phone,
  security key) and manage them from the dashboard, each shown with a
  name and last-used date
- 🔒 **Machine Lock** — sessions are bound to the authorized machine
- ⏱️ **15-minute session timeout** — auto-expiring JWT-based sessions
- 🚫 **Rate limiting** — 3 failed attempts then a 15-minute block
- 🆘 **Emergency recovery code** — one-time-use recovery code emailed to
  registered addresses if all authenticators are lost (never shown on
  screen, invalidated on regeneration)
- 📋 **Activity Logs** — track registration and login activity per device

## How authentication works

1. The server generates a WebAuthn registration/authentication challenge.
2. The browser's native passkey UI takes over — the user scans a QR code
   with their phone (or uses a security key), and the phone/OS handles
   biometric verification and the underlying Bluetooth/NFC transport.
3. The signed credential is sent back to the server and verified against
   the stored public key for that user's registered device.
4. On success, a JWT session token is issued with a 15-minute expiry.

This project focuses on the **server-side WebAuthn integration** —
challenge generation, credential verification, device management, and
session handling — while the passkey ceremony itself (QR display,
biometric prompt, device pairing) is handled by the browser/OS via the
WebAuthn standard.

## Tech Stack

- **Frontend**: HTML, CSS, JavaScript
- **Backend**: Node.js, Express
- **Auth**: WebAuthn (FIDO2) Passkeys + JWT

## Setup Instructions

### 1. Clone the repository

```
git clone https://github.com/chetanborse0712/sekuvo-admin.git
cd sekuvo-admin
```

### 2. Install dependencies

```
cd backend
npm install
```

### 3. Configure environment variables

Create a `.env` file in the `backend` folder with your own values (e.g.
JWT secret, port, email service credentials for recovery codes). See
`.env.example` if provided, or check `backend` source for required keys.

### 4. Run the server

```
npm start
```

### 5. Register your first passkey

Open the app in your browser, go to the admin dashboard, and click
**"Register New Security Key"**. Follow the browser's native passkey
prompt to register your phone or a hardware security key — no manual
key file generation needed.

> Note: The older USB-file-based key generation (`generateKey.js`) is
> deprecated in favor of WebAuthn passkey registration.
