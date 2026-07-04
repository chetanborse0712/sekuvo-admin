const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const os = require('os');
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(cors());
app.use(express.json());

// Serve frontend files from server
app.use(express.static(path.join(__dirname, '../frontend')));

const SECRET = 'sekuvo_secret_key_2024';
const SECRET_MASTER = 'SEKUVO_MASTER_SECRET_2024';
const ALLOWED_MACHINE = 'LAPTOP-2JQ20K53';

// Rate limiting — 3 baar galat try pe 15 min block
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: { success: false, message: 'Too many attempts! Try again after 15 minutes.' },
  skipSuccessfulRequests: true
});

app.post('/api/verify-key', authLimiter, (req, res) => {
  const { key, deviceId, machine, expiresAt } = req.body;

  // 1. Machine check
  const currentMachine = os.hostname();
  if (currentMachine !== ALLOWED_MACHINE) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized machine!'
    });
  }

  // 2. Expiry check
  const expiry = new Date(expiresAt);
  if (expiry < new Date()) {
    return res.status(401).json({
      success: false,
      message: 'USB key has expired!'
    });
  }

  // 3. Key verify
  const expectedKey = crypto
    .createHmac('sha256', SECRET_MASTER)
    .update(machine + '_SEKUVO_ADMIN')
    .digest('hex');

  if (key !== expectedKey) {
    return res.status(401).json({
      success: false,
      message: 'Invalid USB key!'
    });
  }

  // 4. DeviceId check
  const expectedDeviceId = 'SEKUVO_' + machine.toUpperCase();
  if (deviceId !== expectedDeviceId) {
    return res.status(401).json({
      success: false,
      message: 'Invalid device ID!'
    });
  }

  // Token — 15 min valid
  const token = jwt.sign(
    { machine, deviceId },
    SECRET,
    { expiresIn: '15m' }
  );

  res.json({ success: true, token, deviceName: deviceId });
});

// Protected admin routes
app.get('/api/admin/stats', verifyToken, (req, res) => {
  res.json({
    users: 128,
    sessions: 7,
    alerts: 3,
    deviceName: req.user.deviceId
  });
});

// Serve admin panel only with valid token
app.get('/admin', verifyToken, (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/admin.html'));
});

function verifyToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1] 
    || req.query.token;
    
  if (!token) {
    return res.status(403).json({ message: 'Token required!' });
  }

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