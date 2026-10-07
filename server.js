import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import nodemailer from 'nodemailer';
import admin from 'firebase-admin';
import crypto from 'node:crypto';

const app = express();

const PORT = Number(process.env.PORT || 3000);

// ===============================
// 2FC E-SPORTS OTP SECURITY
// ===============================

const OTP_TTL_MS = 5 * 60_000;          // OTP valid for 5 minutes
const RESEND_COOLDOWN_MS = 60_000;      // New OTP after 60 seconds
const RESET_SESSION_TTL_MS = 10 * 60_000;
const MAX_OTP_ATTEMPTS = 5;

// Basic request limits
const REQUEST_WINDOW_MS = 10 * 60_000;
const MAX_REQUESTS_PER_WINDOW = 10;

// ===============================
// HELPERS
// ===============================

function required(name) {
  const value = process.env[name];

  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }

  return value;
}

function parseAllowedOrigins() {
  const raw = process.env.ALLOWED_ORIGINS || '*';

  if (raw === '*') {
    return true;
  }

  return raw
    .split(',')
    .map(v => v.trim())
    .filter(Boolean);
}

function normalizeEmail(value) {
  return String(value || '')
    .trim()
    .toLowerCase();
}

function validGmail(email) {
  return /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@gmail\.com$/i.test(email);
}

function randomOtp() {
  return String(
    crypto.randomInt(0, 1_000_000)
  ).padStart(6, '0');
}

function hash(value) {
  return crypto
    .createHash('sha256')
    .update(value)
    .digest('hex');
}

function safeEqual(a, b) {
  if (!a || !b) return false;

  const aa = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');

  if (aa.length !== bb.length) {
    return false;
  }

  return crypto.timingSafeEqual(aa, bb);
}

function randomToken() {
  return crypto.randomBytes(32).toString('hex');
}

function now() {
  return Date.now();
}

// ===============================
// EXPRESS SECURITY
// ===============================

app.disable('x-powered-by');

app.use(cors({
  origin: parseAllowedOrigins(),
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
  maxAge: 86400
}));

app.use(express.json({
  limit: '20kb'
}));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=()'
  );

  next();
});

// ===============================
// FIREBASE ADMIN
// ===============================

if (!admin.apps.length) {
  const serviceAccountJson =
    required('FIREBASE_SERVICE_ACCOUNT_JSON');

  let serviceAccount;

  try {
    serviceAccount = JSON.parse(serviceAccountJson);
  } catch {
    throw new Error(
      'FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON.'
    );
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();
const auth = admin.auth();

// ===============================
// GMAIL
// ===============================

const gmailUser = required('GMAIL_USER');
const gmailAppPassword = required('GMAIL_APP_PASSWORD');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: gmailUser,
    pass: gmailAppPassword
  }
});

// ===============================
// MEMORY STORES
// ===============================

// email -> OTP/reset information
const otpStore = new Map();

// IP -> request information
const requestRateStore = new Map();

// ===============================
// RATE LIMIT
// ===============================

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];

  if (forwarded) {
    return String(forwarded)
      .split(',')[0]
      .trim();
  }

  return req.ip || 'unknown';
}

function checkRequestRate(req) {
  const ip = getClientIp(req);
  const current = now();

  let record = requestRateStore.get(ip);

  if (!record || current - record.startedAt >= REQUEST_WINDOW_MS) {
    record = {
      startedAt: current,
      count: 0
    };
  }

  record.count += 1;

  requestRateStore.set(ip, record);

  if (record.count > MAX_REQUESTS_PER_WINDOW) {
    return false;
  }

  return true;
}

// ===============================
// CLEANUP
// ===============================

function cleanupExpired() {
  const t = now();

  // OTP cleanup
  for (const [email, record] of otpStore) {
    const otpExpired =
      record.otpExpiresAt > 0 &&
      record.otpExpiresAt <= t;

    const resetExpired =
      !record.resetExpiresAt ||
      record.resetExpiresAt <= t;

    if (otpExpired && resetExpired) {
      otpStore.delete(email);
    }
  }

  // IP rate-limit cleanup
  for (const [ip, record] of requestRateStore) {
    if (t - record.startedAt >= REQUEST_WINDOW_MS) {
      requestRateStore.delete(ip);
    }
  }
}

setInterval(cleanupExpired, 60_000).unref();

// ===============================
// SEND OTP EMAIL
// ===============================

async function sendOtpEmail(email, otp) {
  await transporter.sendMail({
    from: `"2FC E-SPORTS" <${gmailUser}>`,
    to: email,
    subject: '2FC E-SPORTS — Password Reset OTP',

    text:
      `Your 2FC E-SPORTS password reset OTP is ${otp}.\n\n` +
      `This OTP is valid for 5 minutes.\n` +
      `After 5 wrong attempts, the OTP becomes invalid.\n\n` +
      `If you did not request this password reset, you can ignore this email.`,

    html: `
      <div style="
        font-family:Arial,sans-serif;
        line-height:1.5;
        max-width:600px;
        margin:auto;
        padding:20px;
      ">

        <h2>2FC E-SPORTS — Password Reset</h2>

        <p>Your 6-digit password reset OTP is:</p>

        <div style="
          font-size:32px;
          font-weight:800;
          letter-spacing:8px;
          margin:20px 0;
        ">
          ${otp}
        </div>

        <p>
          This OTP is valid for
          <b>5 minutes</b>.
        </p>

        <p>
          After 5 wrong attempts,
          the current OTP becomes invalid.
        </p>

        <p>
          If you did not request a password reset,
          you can safely ignore this email.
        </p>

        <hr>

        <p style="font-size:12px;color:#777">
          2FC E-SPORTS Security System
        </p>

      </div>
    `
  });
}

// ===============================
// HEALTH CHECK
// ===============================

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    service: '2FC E-SPORTS OTP backend'
  });
});

// ===============================
// REQUEST OTP
// ===============================

app.post('/api/password-otp/request', async (req, res) => {
  try {

    if (!checkRequestRate(req)) {
      return res.status(429).json({
        ok: false,
        message:
          'Too many requests. Please try again later.'
      });
    }

    const email = normalizeEmail(
      req.body?.email
    );

    if (!validGmail(email)) {
      return res.status(400).json({
        ok: false,
        message:
          'Enter a valid registered Gmail.'
      });
    }

    const existing = otpStore.get(email);

    // 60 second resend protection
    if (
      existing &&
      existing.lastSentAt &&
      now() - existing.lastSentAt <
        RESEND_COOLDOWN_MS
    ) {

      const wait = Math.ceil(
        (
          RESEND_COOLDOWN_MS -
          (now() - existing.lastSentAt)
        ) / 1000
      );

      return res.status(429).json({
        ok: false,
        message:
          `Please wait ${wait} seconds before requesting another OTP.`
      });
    }

    // Check Firebase Authentication account
    try {

      await auth.getUserByEmail(email);

    } catch {

      return res.status(404).json({
        ok: false,
        message:
          'No registered 2FC account was found for this Gmail.'
      });
    }

    const otp = randomOtp();

    // Send email BEFORE storing OTP
    await sendOtpEmail(email, otp);

    otpStore.set(email, {

      otpHash: hash(otp),

      // 5 minute validity
      otpExpiresAt:
        now() + OTP_TTL_MS,

      lastSentAt:
        now(),

      attempts: 0,

      resetTokenHash: null,

      resetExpiresAt: 0
    });

    return res.json({
      ok: true,
      message:
        'OTP sent to your registered Gmail.'
    });

  } catch (error) {

    console.error(
      'OTP request error:',
      error
    );

    return res.status(500).json({
      ok: false,
      message:
        'Unable to send OTP right now.'
    });
  }
});

// ===============================
// VERIFY OTP
// ===============================

app.post('/api/password-otp/verify', async (req, res) => {

  try {

    if (!checkRequestRate(req)) {
      return res.status(429).json({
        ok: false,
        message:
          'Too many requests. Please try again later.'
      });
    }

    const email = normalizeEmail(
      req.body?.email
    );

    const otp = String(
      req.body?.otp || ''
    ).trim();

    if (
      !validGmail(email) ||
      !/^\d{6}$/.test(otp)
    ) {

      return res.status(400).json({
        ok: false,
        message:
          'Enter the 6-digit OTP.'
      });
    }

    const record =
      otpStore.get(email);

    if (!record) {

      return res.status(400).json({
        ok: false,
        message:
          'OTP expired. Please request a new OTP.'
      });
    }

    // OTP expired
    if (
      !record.otpExpiresAt ||
      record.otpExpiresAt <= now()
    ) {

      otpStore.delete(email);

      return res.status(400).json({
        ok: false,
        message:
          'OTP expired. Please request a new OTP.'
      });
    }

    // Too many attempts
    if (
      record.attempts >=
      MAX_OTP_ATTEMPTS
    ) {

      otpStore.delete(email);

      return res.status(429).json({
        ok: false,
        message:
          'Too many wrong attempts. Please request a new OTP.'
      });
    }

    const suppliedHash =
      hash(otp);

    // Secure constant-time comparison
    if (
      !safeEqual(
        suppliedHash,
        record.otpHash
      )
    ) {

      record.attempts += 1;

      if (
        record.attempts >=
        MAX_OTP_ATTEMPTS
      ) {

        otpStore.delete(email);

        return res.status(429).json({
          ok: false,
          message:
            'Too many wrong attempts. Please request a new OTP.'
        });
      }

      return res.status(400).json({
        ok: false,
        message:
          `Wrong OTP. ${
            MAX_OTP_ATTEMPTS -
            record.attempts
          } attempts remaining.`
      });
    }

    // ===============================
    // OTP SUCCESS
    // ===============================

    const resetToken =
      randomToken();

    // Make OTP single-use
    record.otpHash = null;
    record.otpExpiresAt = 0;
    record.attempts = 0;

    // Temporary reset session
    record.resetTokenHash =
      hash(resetToken);

    record.resetExpiresAt =
      now() +
      RESET_SESSION_TTL_MS;

    return res.json({
      ok: true,
      resetToken
    });

  } catch (error) {

    console.error(
      'OTP verify error:',
      error
    );

    return res.status(500).json({
      ok: false,
      message:
        'Unable to verify OTP right now.'
    });
  }
});

// ===============================
// RESET PASSWORD
// ===============================

app.post('/api/password-otp/reset', async (req, res) => {

  try {

    if (!checkRequestRate(req)) {
      return res.status(429).json({
        ok: false,
        message:
          'Too many requests. Please try again later.'
      });
    }

    const email = normalizeEmail(
      req.body?.email
    );

    const resetToken = String(
      req.body?.resetToken || ''
    );

    const newPassword = String(
      req.body?.newPassword || ''
    );

    const confirmPassword = String(
      req.body?.confirmPassword || ''
    );

    if (
      !validGmail(email) ||
      !resetToken
    ) {

      return res.status(400).json({
        ok: false,
        message:
          'Invalid reset session.'
      });
    }

    if (
      newPassword.length < 6
    ) {

      return res.status(400).json({
        ok: false,
        message:
          'Password must be at least 6 characters.'
      });
    }

    if (
      newPassword !==
      confirmPassword
    ) {

      return res.status(400).json({
        ok: false,
        message:
          'Passwords do not match.'
      });
    }

    const record =
      otpStore.get(email);

    if (
      !record ||
      !record.resetTokenHash ||
      record.resetExpiresAt <= now() ||
      !safeEqual(
        hash(resetToken),
        record.resetTokenHash
      )
    ) {

      return res.status(400).json({
        ok: false,
        message:
          'Reset session expired. Please start again.'
      });
    }

    // Find Firebase user
    const user =
      await auth.getUserByEmail(email);

    // Change Firebase Authentication password
    await auth.updateUser(
      user.uid,
      {
        password: newPassword
      }
    );

    // Metadata ONLY.
    // Never store password or reset token.
    await db
      .collection('passwordChangeEvents')
      .add({

        uid: user.uid,

        email,

        changedAt:
          admin.firestore
            .FieldValue
            .serverTimestamp(),

        method:
          '6-digit-email-otp'
      });

    // Delete one-time reset session
    otpStore.delete(email);

    return res.json({
      ok: true,
      message:
        'Password changed successfully. You can now login.'
    });

  } catch (error) {

    console.error(
      'Password reset error:',
      error
    );

    return res.status(500).json({
      ok: false,
      message:
        'Unable to change password right now.'
    });
  }
});

// ===============================
// ERROR HANDLER
// ===============================

app.use(
  (err, req, res, next) => {

    console.error(
      'Unhandled server error:',
      err
    );

    res.status(500).json({
      ok: false,
      message:
        'Internal server error.'
    });
  }
);

// ===============================
// START SERVER
// ===============================

app.listen(
  PORT,
  () => {

    console.log(
      `2FC E-SPORTS OTP backend running on port ${PORT}`
    );

  }
);
