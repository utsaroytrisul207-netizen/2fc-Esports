import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import nodemailer from 'nodemailer';
import admin from 'firebase-admin';
import crypto from 'node:crypto';

const app = express();
const PORT = Number(process.env.PORT || 3000);
const OTP_TTL_MS = 60_000;
const RESEND_COOLDOWN_MS = 60_000;
const RESET_SESSION_TTL_MS = 10 * 60_000;
const MAX_OTP_ATTEMPTS = 5;

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

function parseAllowedOrigins() {
  const raw = process.env.ALLOWED_ORIGINS || '*';
  return raw === '*' ? true : raw.split(',').map(v => v.trim()).filter(Boolean);
}

app.disable('x-powered-by');
app.use(cors({
  origin: parseAllowedOrigins(),
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400
}));
app.use(express.json({ limit: '20kb' }));

// Small security-header layer without adding another npm dependency.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// Firebase Admin initialization.
// Prefer FIREBASE_SERVICE_ACCOUNT_JSON in the server .env.
// Never put this credential in either HTML file.
if (!admin.apps.length) {
  const serviceAccountJson = required('FIREBASE_SERVICE_ACCOUNT_JSON');
  let serviceAccount;
  try {
    serviceAccount = JSON.parse(serviceAccountJson);
  } catch {
    throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON.');
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();
const auth = admin.auth();

const gmailUser = required('GMAIL_USER');
const gmailAppPassword = required('GMAIL_APP_PASSWORD');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: gmailUser,
    pass: gmailAppPassword
  }
});

const otpStore = new Map();

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function validGmail(email) {
  return /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@gmail\.com$/i.test(email);
}

function randomOtp() {
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
}

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function randomToken() {
  return crypto.randomBytes(32).toString('hex');
}

function now() {
  return Date.now();
}

function cleanupExpired() {
  const t = now();
  for (const [email, record] of otpStore) {
    if (record.otpExpiresAt <= t && (!record.resetExpiresAt || record.resetExpiresAt <= t)) {
      otpStore.delete(email);
    }
  }
}

setInterval(cleanupExpired, 60_000).unref();

async function sendOtpEmail(email, otp) {
  await transporter.sendMail({
    from: `"2FC E-SPORTS" <${gmailUser}>`,
    to: email,
    subject: '2FC E-SPORTS — Password Reset OTP',
    text:
      `Your 2FC E-SPORTS password reset OTP is ${otp}.\n\n` +
      `This OTP is valid for 60 seconds.\n` +
      `After 5 wrong attempts, the OTP becomes invalid.\n\n` +
      `If you did not request this, you can ignore this email.`,
    html: `
      <div style="font-family:Arial,sans-serif;line-height:1.5">
        <h2>2FC E-SPORTS — Password Reset</h2>
        <p>Your 6-digit OTP is:</p>
        <div style="font-size:32px;font-weight:800;letter-spacing:8px">${otp}</div>
        <p>This OTP is valid for <b>60 seconds</b>.</p>
        <p>After 5 wrong attempts, the current OTP becomes invalid.</p>
        <p>If you did not request a password reset, ignore this email.</p>
      </div>
    `
  });
}

app.get('/health', (req, res) => {
  res.json({ ok: true, service: '2FC E-SPORTS OTP backend' });
});

// Action verification OTPs are stored in Firestore so they survive server restarts.
async function requireGoogleIdentity(req, res) {
  const header = String(req.headers.authorization || '');
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    res.status(401).json({ ok: false, message: 'Please login again before verification.' });
    return null;
  }
  try {
    const decoded = await auth.verifyIdToken(match[1]);
    const email = normalizeEmail(decoded.email);
    if (!decoded.email_verified || !validGmail(email)) {
      res.status(403).json({ ok: false, message: 'A verified Gmail account is required.' });
      return null;
    }
    const user = await auth.getUser(decoded.uid);
    const googleProvider = (user.providerData || []).find(p => p.providerId === 'google.com' && normalizeEmail(p.email) === email);
    if (!googleProvider) {
      res.status(403).json({ ok: false, message: 'Verify this same Gmail with Google first.' });
      return null;
    }
    return { uid: decoded.uid, email };
  } catch {
    res.status(401).json({ ok: false, message: 'Login session expired. Please login again.' });
    return null;
  }
}

function validAction(value) {
  return value === 'JOIN_MATCH' || value === 'WITHDRAW';
}

async function sendActionOtpEmail(email, otp, action) {
  const actionName = action === 'JOIN_MATCH' ? 'Join Match' : 'Withdraw';
  await transporter.sendMail({
    from: `"2FC E-SPORTS" <${gmailUser}>`,
    to: email,
    subject: `2FC E-SPORTS — ${actionName} Verification OTP`,
    text: `Your ${actionName} verification OTP is ${otp}.\n\nThis OTP is valid for 60 seconds and can be used only once. After 5 wrong attempts, it becomes invalid.`,
    html: `<div style="font-family:Arial,sans-serif;line-height:1.5"><h2>2FC E-SPORTS — ${actionName} Verification</h2><p>Your 6-digit OTP is:</p><div style="font-size:32px;font-weight:800;letter-spacing:8px">${otp}</div><p>This OTP is valid for <b>60 seconds</b>.</p><p>After 5 wrong attempts, the OTP becomes invalid.</p></div>`
  });
}

app.post('/api/action-otp/request', async (req, res) => {
  try {
    const identity = await requireGoogleIdentity(req, res);
    if (!identity) return;

    const action = String(req.body?.action || '');
    if (!validAction(action)) {
      return res.status(400).json({ ok: false, message: 'Invalid verification action.' });
    }

    const ref = db.collection('actionVerificationOtps').doc(`${identity.uid}_${action}`);
    const oldSnap = await ref.get();
    const old = oldSnap.exists ? oldSnap.data() : {};

    if (old.lastSentAt && now() - Number(old.lastSentAt) < RESEND_COOLDOWN_MS) {
      const wait = Math.ceil((RESEND_COOLDOWN_MS - (now() - Number(old.lastSentAt))) / 1000);
      return res.status(429).json({ ok: false, message: `Please wait ${wait} seconds before requesting another OTP.` });
    }

    const otp = randomOtp();
    await sendActionOtpEmail(identity.email, otp, action);

    await ref.set({
      uid: identity.uid,
      email: identity.email,
      action,
      otpHash: hash(otp),
      otpExpiresAt: now() + OTP_TTL_MS,
      lastSentAt: now(),
      attempts: 0
    });

    return res.json({ ok: true, message: 'Verification OTP sent to your registered Gmail.' });
  } catch (error) {
    console.error('Action OTP request error:', error);
    return res.status(500).json({ ok: false, message: 'Unable to send verification OTP right now.' });
  }
});

app.post('/api/action-otp/verify', async (req, res) => {
  try {
    const identity = await requireGoogleIdentity(req, res);
    if (!identity) return;

    const action = String(req.body?.action || '');
    const otp = String(req.body?.otp || '').trim();

    if (!validAction(action) || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({ ok: false, message: 'Enter the 6-digit OTP.' });
    }

    const ref = db.collection('actionVerificationOtps').doc(`${identity.uid}_${action}`);

    const result = await db.runTransaction(async tx => {
      const snap = await tx.get(ref);

      if (!snap.exists) {
        return { status: 400, message: 'OTP expired. Please request a new OTP.' };
      }

      const record = snap.data() || {};

      if (record.uid !== identity.uid || record.email !== identity.email || record.action !== action) {
        return { status: 403, message: 'Verification session does not match this account.' };
      }

      if (Number(record.otpExpiresAt) <= now()) {
        tx.delete(ref);
        return { status: 400, message: 'OTP expired. Please request a new OTP.' };
      }

      if (Number(record.attempts || 0) >= MAX_OTP_ATTEMPTS) {
        tx.delete(ref);
        return { status: 429, message: 'Too many wrong attempts. Please request a new OTP.' };
      }

      if (hash(otp) !== record.otpHash) {
        const attempts = Number(record.attempts || 0) + 1;

        if (attempts >= MAX_OTP_ATTEMPTS) {
          tx.delete(ref);
          return { status: 429, message: 'Too many wrong attempts. Please request a new OTP.' };
        }

        tx.update(ref, { attempts });
        return { status: 400, message: `Wrong OTP. ${MAX_OTP_ATTEMPTS - attempts} attempts remaining.` };
      }

      tx.update(ref, {
        otpHash: null,
        otpExpiresAt: 0,
        attempts: 0,
        verifiedAt: now()
      });

      return { status: 200 };
    });

    if (result.status !== 200) {
      return res.status(result.status).json({ ok: false, message: result.message });
    }

    return res.json({ ok: true, message: 'Gmail OTP verified successfully.' });
  } catch (error) {
    console.error('Action OTP verify error:', error);
    return res.status(500).json({ ok: false, message: 'Unable to verify OTP right now.' });
  }
});

app.post('/api/password-otp/request', async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);

    if (!validGmail(email)) {
      return res.status(400).json({ ok: false, message: 'Enter a valid registered Gmail.' });
    }

    const existing = otpStore.get(email);

    if (existing && existing.lastSentAt && now() - existing.lastSentAt < RESEND_COOLDOWN_MS) {
      const wait = Math.ceil((RESEND_COOLDOWN_MS - (now() - existing.lastSentAt)) / 1000);
      return res.status(429).json({
        ok: false,
        message: `Please wait ${wait} seconds before requesting another OTP.`
      });
    }

    // Verify that the account exists in Firebase Authentication.
    // Do not return the raw Firebase error to the client.
    try {
      await auth.getUserByEmail(email);
    } catch {
      return res.status(404).json({
        ok: false,
        message: 'No registered 2FC account was found for this Gmail.'
      });
    }

    const otp = randomOtp();

    await sendOtpEmail(email, otp);

    otpStore.set(email, {
      otpHash: hash(otp),
      otpExpiresAt: now() + OTP_TTL_MS,
      lastSentAt: now(),
      attempts: 0,
      resetTokenHash: null,
      resetExpiresAt: 0
    });

    return res.json({ ok: true, message: 'OTP sent to your registered Gmail.' });
  } catch (error) {
    console.error('OTP request error:', error);
    return res.status(500).json({ ok: false, message: 'Unable to send OTP right now.' });
  }
});

app.post('/api/password-otp/verify', async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const otp = String(req.body?.otp || '').trim();

    if (!validGmail(email) || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({ ok: false, message: 'Enter the 6-digit OTP.' });
    }

    const record = otpStore.get(email);

    if (!record) {
      return res.status(400).json({ ok: false, message: 'OTP expired. Please request a new OTP.' });
    }

    if (record.otpExpiresAt <= now()) {
      otpStore.delete(email);
      return res.status(400).json({ ok: false, message: 'OTP expired. Please request a new OTP.' });
    }

    if (record.attempts >= MAX_OTP_ATTEMPTS) {
      otpStore.delete(email);
      return res.status(429).json({ ok: false, message: 'Too many wrong attempts. Please request a new OTP.' });
    }

    if (hash(otp) !== record.otpHash) {
      record.attempts += 1;

      if (record.attempts >= MAX_OTP_ATTEMPTS) {
        otpStore.delete(email);
        return res.status(429).json({
          ok: false,
          message: 'Too many wrong attempts. Please request a new OTP.'
        });
      }

      return res.status(400).json({
        ok: false,
        message: `Wrong OTP. ${MAX_OTP_ATTEMPTS - record.attempts} attempts remaining.`
      });
    }

    // OTP becomes single-use after successful verification.
    const resetToken = randomToken();
    record.otpHash = null;
    record.otpExpiresAt = 0;
    record.attempts = 0;
    record.resetTokenHash = hash(resetToken);
    record.resetExpiresAt = now() + RESET_SESSION_TTL_MS;

    return res.json({
      ok: true,
      resetToken
    });
  } catch (error) {
    console.error('OTP verify error:', error);
    return res.status(500).json({ ok: false, message: 'Unable to verify OTP right now.' });
  }
});

app.post('/api/password-otp/reset', async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const resetToken = String(req.body?.resetToken || '');
    const newPassword = String(req.body?.newPassword || '');
    const confirmPassword = String(req.body?.confirmPassword || '');

    if (!validGmail(email) || !resetToken) {
      return res.status(400).json({ ok: false, message: 'Invalid reset session.' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ ok: false, message: 'Password must be at least 6 characters.' });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ ok: false, message: 'Passwords do not match.' });
    }

    const record = otpStore.get(email);

    if (
      !record ||
      !record.resetTokenHash ||
      record.resetExpiresAt <= now() ||
      hash(resetToken) !== record.resetTokenHash
    ) {
      return res.status(400).json({ ok: false, message: 'Reset session expired. Please start again.' });
    }

    const user = await auth.getUserByEmail(email);

    await auth.updateUser(user.uid, { password: newPassword });

    // Metadata only: never store the password or reset token.
    await db.collection('passwordChangeEvents').add({
      uid: user.uid,
      email,
      changedAt: admin.firestore.FieldValue.serverTimestamp(),
      method: '6-digit-email-otp'
    });

    // One-time reset session.
    otpStore.delete(email);

    return res.json({
      ok: true,
      message: 'Password changed successfully. You can now login.'
    });
  } catch (error) {
    console.error('Password reset error:', error);
    return res.status(500).json({ ok: false, message: 'Unable to change password right now.' });
  }
});

app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err);
  res.status(500).json({ ok: false, message: 'Internal server error.' });
});

app.listen(PORT, () => {
  console.log(`2FC E-SPORTS OTP backend running on port ${PORT}`);
});
