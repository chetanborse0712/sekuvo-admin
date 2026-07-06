const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const os = require('os');
const bcrypt = require('bcryptjs');
const path = require('path');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

const SECRET = process.env.SECRET || 'sekuvo_secret_key_2024';
const SECRET_MASTER = process.env.SECRET_MASTER || 'SEKUVO_MASTER_SECRET_2024';
const ALLOWED_MACHINE = process.env.ALLOWED_MACHINE || 'LAPTOP-2JQ20K53';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const FIXED_RECOVERY_CODE = process.env.RECOVERY_CODE 
  ? process.env.RECOVERY_CODE.trim().toUpperCase() 
  : null;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

async function initRecoveryCode() {
  // Check karo Supabase mein already koi unused code hai ya nahi
  const { data: existing, error: fetchError } = await supabase
    .from('recovery_codes')
    .select('*')
    .eq('is_used', false)
    .order('created_at', { ascending: false })
    .limit(1);

  if (fetchError) {
    console.error('❌ Supabase fetch error:', fetchError.message);
    return;
  }

  if (existing && existing.length > 0) {
    console.log('✅ Existing unused recovery code found in Supabase, reusing it.');
    return; // pehle se hai, naya banane ki zaroorat nahi
  }

  let formatted;
  if (FIXED_RECOVERY_CODE) {
    formatted = FIXED_RECOVERY_CODE;
    console.log('=================================');
    console.log('✅ Fixed recovery code loaded');
    console.log('=================================');
  } else {
    const code = crypto.randomBytes(12).toString('hex').toUpperCase();
    formatted = code.match(/.{1,6}/g).join('-');
    console.log('=================================');
    console.log('⚠️  MASTER RECOVERY CODE:');
    console.log(formatted);
    console.log('Save this code safely!');
    console.log('=================================');
  }

  const codeHash = await bcrypt.hash(formatted, 10);

  const { error: insertError } = await supabase
    .from('recovery_codes')
    .insert([{ code_hash: codeHash, is_used: false }]);

  if (insertError) {
    console.error('❌ Supabase insert error:', insertError.message);
  } else {
    console.log('✅ Recovery code saved to Supabase');
  }
}

initRecoveryCode();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: { success: false, message: 'Too many attempts! Try again after 15 minutes.' },
  skipSuccessfulRequests: true
});

app.post('/api/verify-key', authLimiter, (req, res) => {
  const { key, deviceId, machine, expiresAt } = req.body;

  if (!IS_PRODUCTION) {
    const currentMachine = os.hostname();
    if (currentMachine !== ALLOWED_MACHINE) {
      return res.status(401).json({ success: false, message: 'Unauthorized machine!' });
    }
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

app.post('/api/verify-recovery', authLimiter, async (req, res) => {
  const { code } = req.body;

  if (!code) {
    return res.status(400).json({ success: false, message: 'Recovery code required!' });
  }

  const { data: rows, error } = await supabase
    .from('recovery_codes')
    .select('*')
    .eq('is_used', false);

  if (error) {
    console.error('Supabase fetch error:', error.message);
    return res.status(500).json({ success: false, message: 'Server error!' });
  }

  if (!rows || rows.length === 0) {
    return res.status(401).json({ success: false, message: 'Recovery code already used!' });
  }

  const inputCode = code.trim().toUpperCase();
  let matchedRow = null;

  for (const row of rows) {
    const match = await bcrypt.compare(inputCode, row.code_hash);
    if (match) {
      matchedRow = row;
      break;
    }
  }

  if (!matchedRow) {
    return res.status(401).json({ success: false, message: 'Invalid recovery code!' });
  }

  // Mark as used in Supabase
  await supabase
    .from('recovery_codes')
    .update({ is_used: true })
    .eq('id', matchedRow.id);

  const token = jwt.sign({ machine: 'RECOVERY', deviceId: 'RECOVERY_ACCESS' }, SECRET, { expiresIn: '15m' });

  res.json({
    success: true,
    token,
    deviceName: 'Recovery Access',
    message: 'Access granted!'
  });
});

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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Sekuvo Admin Server running on port ${PORT}`);
});
