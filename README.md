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

Node.js, Express.js, JavaScript, WebAuthn/FIDO2, JWT, Crypto, HTML, CSS

## ⚠️ Note
This was built as a learning project to understand passwordless authentication flows. Not intended for production use without a full security review.
This was built as a learning project to understand passwordless
authentication flows. Not intended for production use without a full
security review.
