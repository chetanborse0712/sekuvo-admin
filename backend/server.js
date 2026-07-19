const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const path = require('path');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

// ===== FAIL-SAFE ENV VALIDATION =====
// Server ko zaroori secrets ke bina start hi nahi hone denge.
// Isse silently weak/default secrets production mein use hone se bachte hain.
const REQUIRED_ENV_VARS = [
  'SECRET',
  'SUPABASE_URL',
  'SUPABASE_SERVICE_KEY',
  'SENDGRID_API_KEY',
  'EMAIL_USER'
];

const missingVars = REQUIRED_ENV_VARS.filter(name => !process.env[name] || process.env[name].trim() === '');

if (missingVars.length > 0) {
  console.error('=================================');
  console.error('❌ FATAL: Missing required environment variables:');
  missingVars.forEach(v => console.error(`   - ${v}`));
  console.error('Server startup aborted for security reasons.');
  console.error('Set these in your .env file (local) or Render Environment tab (production).');
  console.error('=================================');
  process.exit(1); // Server crash — chalu nahi hoga bina in vars ke
}

const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

const SECRET = process.env.SECRET;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ===== EMAIL CONFIG (Recovery Code delivery) =====
// SendGrid HTTPS API use karte hain — SMTP ports (587/465) Render pe blocked/unreachable the,
// HTTPS (443) kabhi block nahi hota, isliye ye reliably kaam karega.
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const RECOVERY_EMAILS = (process.env.RECOVERY_EMAILS || '')
  .split(',')
  .map(e => e.trim())
  .filter(Boolean);

const RECOVERY_CODE_EXPIRY_MINUTES = 15;

// Email ko masked format mein dikhata hai — jaise ra***********2@gmail.com
function maskEmail(email) {
  const [local, domain] = email.split('@');
  if (local.length <= 3) return local[0] + '***@' + domain;
  const visibleStart = local.slice(0, 2);
  const visibleEnd = local.slice(-1);
  const masked = '*'.repeat(Math.max(local.length - 3, 3));
  return `${visibleStart}${masked}${visibleEnd}@${domain}`;
}

// ===== WEBAUTHN CONFIG =====
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');

// rpID = domain jispe credential "bind" hoga (bina https:// ke, bina port ke)
// Production aur local dono ke liye alag, kyunki WebAuthn domain-locked hota hai
const RP_NAME = 'Sekuvo Admin';
const RP_ID = IS_PRODUCTION ? 'sekuvo-admin.onrender.com' : 'localhost';
const ORIGIN = IS_PRODUCTION ? 'https://sekuvo-admin.onrender.com' : `http://localhost:${process.env.PORT || 3000}`;

// Challenges temporarily yahan store honge (in-memory) — ye short-lived hote hain (kuch minute), DB mein rakhne ki zaroorat nahi
const pendingChallenges = new Map();

async function checkRecoveryCodeStatus() {
  // Startup pe sirf inform karta hai — koi naya code khud se generate NAHI karta.
  // Naya code sirf admin dashboard se manually generate hoga (on-demand), taaki
  // "restart hote hi purana used code phir se active ho jaye" wala bug na ho.
  const { data: existing, error: fetchError } = await supabase
    .from('recovery_codes')
    .select('id')
    .eq('is_used', false)
    .limit(1);

  if (fetchError) {
    console.error('❌ Supabase fetch error:', fetchError.message);
    return;
  }

  if (existing && existing.length > 0) {
    console.log('✅ An active recovery code exists in Supabase.');
  } else {
    console.log('⚠️  No active recovery code exists. Generate one from the admin dashboard (Security Key Management → Generate Recovery Code) after logging in via WebAuthn.');
  }
}

checkRecoveryCodeStatus();

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

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: { success: false, message: 'Too many attempts! Try again after 15 minutes.' },
  skipSuccessfulRequests: true
});

// Naya recovery code on-demand generate karta hai (protected — sirf logged-in admin).
// Purane sabhi codes turant invalid ho jate hain. Code response mein NAHI aata — seedha registered emails pe jata hai.
app.post('/api/recovery/generate', verifyToken, async (req, res) => {
  if (RECOVERY_EMAILS.length === 0) {
    return res.status(500).json({ success: false, message: 'No recovery emails configured on server!' });
  }

  try {
    // Purane sabhi recovery codes delete karo (invalidate)
    const { error: deleteError } = await supabase
      .from('recovery_codes')
      .delete()
      .neq('id', 0); // sab rows match karega

    if (deleteError) {
      console.error('Supabase delete error:', deleteError.message);
    }

    // Naya random code generate karo
    const code = crypto.randomBytes(15).toString('hex').toUpperCase();
    const formatted = code.match(/.{1,6}/g).join('-');
    const codeHash = await bcrypt.hash(formatted, 10);

    const { error: insertError } = await supabase
      .from('recovery_codes')
      .insert([{ code_hash: codeHash, is_used: false }]);

    if (insertError) {
      console.error('Supabase insert error:', insertError.message);
      return res.status(500).json({ success: false, message: 'Failed to generate recovery code!' });
    }

    // Email bhejo sabhi registered partners ko (SendGrid HTTPS API se)
    await sgMail.send({
      to: RECOVERY_EMAILS,
      from: process.env.EMAIL_USER, // ye SendGrid mein verified sender hona chahiye
      subject: '🔑 New Sekuvo Admin Recovery Code Generated',
      html: `
        <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
          <h2 style="color: #6c63ff;">Sekuvo Admin — Emergency Recovery Code</h2>
          <p>A new emergency recovery code has been generated for the Sekuvo Admin panel. Any previous code is now invalid.</p>
          <div style="background: #f5f5f5; padding: 16px; border-radius: 8px; font-size: 20px; font-weight: bold; letter-spacing: 2px; text-align: center; margin: 16px 0;">
            ${formatted}
          </div>
          <p style="color: #888; font-size: 13px;">This code can be used only once, and is valid for ${RECOVERY_CODE_EXPIRY_MINUTES} minutes only. If you did not request this, please investigate immediately and revoke all security key access from the dashboard.</p>
        </div>
      `
    });

    res.json({ 
      success: true, 
      message: 'Recovery code generated and sent to registered emails.',
      sentTo: RECOVERY_EMAILS.map(maskEmail)
    });

  } catch (err) {
    console.error('Recovery generate error:', err.message);
    res.status(500).json({ success: false, message: 'Server error: ' + err.message });
  }
});

// Masked recovery emails ki list dikhata hai (protected) — taaki UI mein confirm ho sake kahan bheja jayega
app.get('/api/recovery/emails', verifyToken, (req, res) => {
  res.json({ success: true, emails: RECOVERY_EMAILS.map(maskEmail) });
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

  // Expiry check karo — code ka age nikaalo aur EXPIRY_MINUTES se compare karo
  const codeAgeMs = Date.now() - new Date(matchedRow.created_at).getTime();
  const codeAgeMinutes = codeAgeMs / (1000 * 60);

  if (codeAgeMinutes > RECOVERY_CODE_EXPIRY_MINUTES) {
    // Expired code ko turant delete karo — reuse na ho paye
    await supabase.from('recovery_codes').delete().eq('id', matchedRow.id);
    return res.status(401).json({ success: false, message: `Recovery code has expired! Codes are valid for only ${RECOVERY_CODE_EXPIRY_MINUTES} minutes after generation. Please generate a new one.` });
  }

  // Delete karo Supabase se — truly single-use, dobara kabhi active nahi hoga
  await supabase
    .from('recovery_codes')
    .delete()
    .eq('id', matchedRow.id);

  const token = jwt.sign({ machine: 'RECOVERY', deviceId: 'RECOVERY_ACCESS' }, SECRET, { expiresIn: '15m' });

  res.json({
    success: true,
    token,
    deviceName: 'Recovery Access',
    message: 'Access granted!'
  });
});

// ===== WEBAUTHN: DEVICE REGISTRATION =====
// Step 1: Server ek "challenge" generate karta hai, jo device ko sign karna hoga.
// Protected hai (verifyToken) — matlab sirf already-logged-in admin naya device register kar sakta hai.
app.post('/api/webauthn/register-options', verifyToken, async (req, res) => {
  const adminUsername = req.user.deviceId || 'admin';

  // Existing registered credentials — taaki same device dobara register na ho
  const { data: existingCreds } = await supabase
    .from('webauthn_credentials')
    .select('credential_id')
    .eq('admin_username', adminUsername);

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: adminUsername,
    attestationType: 'none',
    excludeCredentials: (existingCreds || []).map(c => ({
      id: c.credential_id,
    })),
    authenticatorSelection: {
      authenticatorAttachment: 'cross-platform', // sirf USB/external security key allowed, laptop ka built-in PIN/fingerprint NAHI
      residentKey: 'preferred',
      userVerification: 'required' // USB key ka apna PIN/touch zaroori hoga
    }
  });

  // Challenge ko temporarily store karo, verify step mein match karenge
  pendingChallenges.set(adminUsername, options.challenge);

  res.json(options);
});

// Step 2: Device ne challenge sign kar diya, ab verify karke DB mein save karenge
app.post('/api/webauthn/register-verify', verifyToken, async (req, res) => {
  const adminUsername = req.user.deviceId || 'admin';
  const expectedChallenge = pendingChallenges.get(adminUsername);

  if (!expectedChallenge) {
    return res.status(400).json({ success: false, message: 'No pending registration found. Try again.' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ success: false, message: 'Verification failed!' });
    }

    const { credential } = verification.registrationInfo;

    const { error: insertError } = await supabase
      .from('webauthn_credentials')
      .insert([{
        credential_id: credential.id,
        public_key: Buffer.from(credential.publicKey).toString('base64'),
        counter: credential.counter,
        device_name: req.body.deviceName || 'Unnamed Device',
        admin_username: adminUsername
      }]);

    if (insertError) {
      console.error('Supabase insert error:', insertError.message);
      return res.status(500).json({ success: false, message: 'Failed to save device!' });
    }

    pendingChallenges.delete(adminUsername);
    res.json({ success: true, message: 'Device registered successfully!' });

  } catch (err) {
    console.error('Registration verify error:', err.message);
    res.status(400).json({ success: false, message: 'Registration failed: ' + err.message });
  }
});

// ===== WEBAUTHN: LOGIN (AUTHENTICATION) =====
// Step 1: Server ek challenge deta hai — koi bhi USB key jo pehle register hui hai, use sign kar sakti hai
app.post('/api/webauthn/login-options', authLimiter, async (req, res) => {
  // Sabhi registered credentials nikalo (chahe kisi bhi admin ki hon)
  const { data: allCreds, error } = await supabase
    .from('webauthn_credentials')
    .select('credential_id');

  if (error) {
    console.error('Supabase fetch error:', error.message);
    return res.status(500).json({ success: false, message: 'Server error!' });
  }

  if (!allCreds || allCreds.length === 0) {
    return res.status(400).json({ success: false, message: 'No USB key registered yet! Register one first.' });
  }

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'required',
    allowCredentials: allCreds.map(c => ({
      id: c.credential_id,
    })),
  });

  // Session-less system hai, isliye challenge ko ek temporary key se store karte hain
  pendingChallenges.set('LOGIN_' + options.challenge.slice(0, 10), options.challenge);
  res.json(options);
});

// Step 2: Signature verify karo — agar sahi USB key se sign hua hai, tabhi login milega
app.post('/api/webauthn/login-verify', authLimiter, async (req, res) => {
  const { credentialId, response, clientChallenge } = req.body;

  const challengeKey = 'LOGIN_' + clientChallenge.slice(0, 10);
  const expectedChallenge = pendingChallenges.get(challengeKey);

  if (!expectedChallenge) {
    return res.status(400).json({ success: false, message: 'Login session expired. Try again.' });
  }

  // DB se ye specific credential dhoondo
  const { data: cred, error } = await supabase
    .from('webauthn_credentials')
    .select('*')
    .eq('credential_id', credentialId)
    .single();

  if (error || !cred) {
    return res.status(401).json({ success: false, message: 'Invalid USB key!' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: cred.credential_id,
        publicKey: Buffer.from(cred.public_key, 'base64'),
        counter: Number(cred.counter),
      },
    });

    if (!verification.verified) {
      return res.status(401).json({ success: false, message: 'Invalid USB key!' });
    }

    // Counter update karo — clone-detection ke liye (agar counter kabhi peeche jaye, suspicious hai)
    await supabase
      .from('webauthn_credentials')
      .update({
        counter: verification.authenticationInfo.newCounter,
        last_used_at: new Date().toISOString()
      })
      .eq('credential_id', credentialId);

    pendingChallenges.delete(challengeKey);

    const token = jwt.sign(
      { machine: cred.device_name, deviceId: 'WEBAUTHN_' + cred.admin_username },
      SECRET,
      { expiresIn: '15m' }
    );

    res.json({ success: true, token, deviceName: cred.device_name });

  } catch (err) {
    console.error('Login verify error:', err.message);
    res.status(401).json({ success: false, message: 'Invalid USB key!' });
  }
});

// ===== WEBAUTHN: DEVICE MANAGEMENT (list + revoke) =====
const CORE_ADMIN_COUNT = 3; // Pehle 3 registered devices "core admins" hain — inhe revoke nahi kiya ja sakta

// Registered devices ki list dikhata hai (protected — sirf logged-in admin dekh sakta hai)
app.get('/api/webauthn/list-credentials', verifyToken, async (req, res) => {
  const { data, error } = await supabase
    .from('webauthn_credentials')
    .select('id, device_name, created_at, last_used_at')
    .order('created_at', { ascending: true }); // ascending — sabse purana pehle, taaki rank sahi mile

  if (error) {
    console.error('Supabase fetch error:', error.message);
    return res.status(500).json({ success: false, message: 'Failed to fetch devices!' });
  }

  // Pehle CORE_ADMIN_COUNT devices ko "protected" mark karo
  const devicesWithProtection = data.map((d, index) => ({
    ...d,
    protected: index < CORE_ADMIN_COUNT
  }));

  // Latest-first order mein wapas bhejo (UI mein naye upar dikhein)
  res.json({ success: true, devices: devicesWithProtection.reverse() });
});

// Kisi specific device ka access revoke/remove karta hai
app.delete('/api/webauthn/remove-credential/:id', verifyToken, async (req, res) => {
  const { id } = req.params;

  // Pehle check karo ye device "core admin" (protected) toh nahi hai
  const { data: allDevices, error: fetchError } = await supabase
    .from('webauthn_credentials')
    .select('id, created_at')
    .order('created_at', { ascending: true });

  if (fetchError) {
    console.error('Supabase fetch error:', fetchError.message);
    return res.status(500).json({ success: false, message: 'Failed to verify device!' });
  }

  const protectedIds = allDevices.slice(0, CORE_ADMIN_COUNT).map(d => d.id);

  if (protectedIds.includes(Number(id))) {
    return res.status(403).json({ success: false, message: 'This is a core admin device and cannot be revoked!' });
  }

  const { error } = await supabase
    .from('webauthn_credentials')
    .delete()
    .eq('id', id);

  if (error) {
    console.error('Supabase delete error:', error.message);
    return res.status(500).json({ success: false, message: 'Failed to remove device!' });
  }

  res.json({ success: true, message: 'Device access revoked successfully!' });
});

app.get('/api/admin/stats', verifyToken, (req, res) => {
  res.json({ users: 128, sessions: 7, alerts: 3, deviceName: req.user.deviceId });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Sekuvo Admin Server running on port ${PORT}`);
});
