const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const os = require('os');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

const SECRET = process.env.SECRET || 'sekuvo_secret_key_2024';
const SECRET_MASTER = process.env.SECRET_MASTER || 'SEKUVO_MASTER_SECRET_2024';
const ALLOWED_MACHINE = process.env.ALLOWED_MACHINE || 'LAPTOP-2JQ20K53';

// Recovery code store (in memory — production mein database use karo)
let recoveryCodeHash = null;
let recoveryCodeUsed = false;

// Recovery code generate karo — server start hone pe
async function generateRecoveryCode() {
  const code = crypto.randomBytes(12).toString('hex').toUpperCase();
  const formatted = code.match(/.{1,6}/g).join('-'); // Format: XXXXXX-XXXXXX-XXXXXX-XXXXXX
  recoveryCodeHash = await bcrypt.hash(formatted, 10);
  recoveryCodeUsed = false;
  console.log('=================================');
  console.log('⚠️  MASTER RECOVERY CODE:');
  console.log(formatted);
  console.log('Save this code safely!');
  console.log('=================================');
  return formatted;
}

generateRecoveryCode();

// USB verify
const rateLimit = require('express-rate-limit');
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: { success: false, message: 'Too many attempts! Try again after 15 minutes.' },
  skipSuccessfulRequests: true
});

app.post('/api/verify-key', authLimiter, (req, res) => {
  const { key, deviceId, machine, expiresAt } = req.body;

  const currentMachine = os.hostname();
  if (currentMachine !== ALLOWED_MACHINE) {
    return res.status(401).json({ success: false, message: 'Unauthorized machine!' });
  }

  const expiry = new Date(expiresAt);
  if (expiry < new Date()) {
    return res.status(401).json({ success: false, message: 'USB key has expired!' });
  }

  const expectedKey = crypto
    .createHmac('sha256', SECRET_MASTER)
    .update(machine + '_SEKUVO_ADMIN')
    .digest('hex');

  if (key !== expectedKey) {
    return res.status(401).json({ success: false, message: 'Invalid USB key!' });
  }

  const expectedDeviceId = 'SEKUVO_' + machine.toUpperCase();
  if (deviceId !== expectedDeviceId) {
    return res.status(401).json({ success: false, message: 'Invalid device ID!' });
  }

  const token = jwt.sign({ machine, deviceId }, SECRET, { expiresIn: '15m' });
  res.json({ success: true, token, deviceName: deviceId });
});

// Recovery code verify
app.post('/api/verify-recovery', authLimiter, async (req, res) => {
  const { code } = req.body;

  if (!code) {
    return res.status(400).json({ success: false, message: 'Recovery code required!' });
  }

  if (recoveryCodeUsed) {
    return res.status(401).json({ success: false, message: 'Recovery code already used! Generate a new one.' });
  }

  const match = await bcrypt.compare(code.trim().toUpperCase(), recoveryCodeHash);

  if (!match) {
    return res.status(401).json({ success: false, message: 'Invalid recovery code!' });
  }

  // Code use ho gaya — expire karo
  recoveryCodeUsed = true;

  // Naya code generate karo
  const newCode = await generateRecoveryCode();

  const token = jwt.sign({ machine: 'RECOVERY', deviceId: 'RECOVERY_ACCESS' }, SECRET, { expiresIn: '15m' });

  res.json({ 
    success: true, 
    token, 
    deviceName: 'Recovery Access',
    newCode: newCode,
    message: 'Access granted! New recovery code generated — save it!'
  });
});

// Admin stats
app.get('/api/admin/stats', verifyToken, (req, res) => {
  res.json({ users: 128, sessions: 7, alerts: 3, deviceName: req.user.deviceId });
});

function verifyToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1] || req.query.token;
  if (!token) return res.status(403).json({ message: 'Token required!' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Token invalid or expired!' });
  }
}

app.listen(3000, () => {
  console.log('✅ Sekuvo Admin Server running: http://localhost:3000');
});