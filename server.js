import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import admin from 'firebase-admin';
import crypto from 'node:crypto';

const app = express();
const PORT = Number(process.env.PORT || 3000);

// ===============================
// 2FC E-SPORTS OTP SECURITY
// ===============================

const OTP_TTL_MS = 5 * 60_000;
const RESEND_COOLDOWN_MS = 60_000;
const RESET_SESSION_TTL_MS = 10 * 60_000;
const MAX_OTP_ATTEMPTS = 5;

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
  const raw =
    process.env.ALLOWED_ORIGINS ||
    process.env.ALLOWED_ORIGIN ||
    '*';

  if (raw === '*') return true;

  return raw
    .split(',')
    .map(value => value.trim())
    .filter(Boolean);
}

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

function safeEqual(a, b) {
  if (!a || !b) return false;

  const aa = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');

  if (aa.length !== bb.length) return false;

  return crypto.timingSafeEqual(aa, bb);
}

function randomToken() {
  return crypto.randomBytes(32).toString('hex');
}

function now() {
  return Date.now();
}

function parseSupportPins(value) {
  return [...new Set(
    String(value || '')
      .split(',')
      .map(pin => pin.trim())
      .filter(Boolean)
  )];
}

function validHttpUrl(value) {
  if (!value) return true;

  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

// ===============================
// EXPRESS SECURITY
// ===============================

app.disable('x-powered-by');

app.use(cors({
  origin: parseAllowedOrigins(),
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
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
    process.env.FIREBASE_SERVICE_ACCOUNT_JSON ||
    process.env.FIREBASE_SERVICE_ACCOUNT;

  if (!serviceAccountJson) {
    throw new Error(
      'Missing required environment variable: FIREBASE_SERVICE_ACCOUNT_JSON (or FIREBASE_SERVICE_ACCOUNT)'
    );
  }

  let serviceAccount;

  try {
    serviceAccount = JSON.parse(serviceAccountJson);
  } catch {
    throw new Error(
      'Firebase service account environment variable is not valid JSON.'
    );
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();
const auth = admin.auth();

// ===============================
// RESEND EMAIL API
// ===============================

const resendApiKey = required('RESEND_API_KEY');
const resendFrom = required('RESEND_FROM');

// ===============================
// MEMORY STORES
// ===============================

const otpStore = new Map();
const requestRateStore = new Map();

// ===============================
// RATE LIMIT
// ===============================

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];

  if (forwarded) {
    return String(forwarded).split(',')[0].trim();
  }

  return req.ip || 'unknown';
}

function checkRequestRate(req) {
  const ip = getClientIp(req);
  const current = now();

  let record = requestRateStore.get(ip);

  if (
    !record ||
    current - record.startedAt >= REQUEST_WINDOW_MS
  ) {
    record = {
      startedAt: current,
      count: 0
    };
  }

  record.count += 1;
  requestRateStore.set(ip, record);

  return record.count <= MAX_REQUESTS_PER_WINDOW;
}

// ===============================
// CLEANUP
// ===============================

function cleanupExpired() {
  const currentTime = now();

  for (const [email, record] of otpStore) {
    const otpExpired =
      record.otpExpiresAt > 0 &&
      record.otpExpiresAt <= currentTime;

    const resetExpired =
      !record.resetExpiresAt ||
      record.resetExpiresAt <= currentTime;

    if (otpExpired && resetExpired) {
      otpStore.delete(email);
    }
  }

  for (const [ip, record] of requestRateStore) {
    if (
      currentTime - record.startedAt >= REQUEST_WINDOW_MS
    ) {
      requestRateStore.delete(ip);
    }
  }
}

setInterval(cleanupExpired, 60_000).unref();

// ===============================
// SEND OTP EMAIL THROUGH RESEND
// ===============================

async function sendOtpEmail(email, otp) {
  const response = await fetch(
    'https://api.resend.com/emails',
    {
      method: 'POST',

      headers: {
        Authorization: `Bearer ${resendApiKey}`,
        'Content-Type': 'application/json'
      },

      body: JSON.stringify({
        from: resendFrom,
        to: [email],

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
            ">${otp}</div>
            <p>This OTP is valid for <b>5 minutes</b>.</p>
            <p>After 5 wrong attempts, the current OTP becomes invalid.</p>
            <p>If you did not request this password reset, you can safely ignore this email.</p>
            <hr>
            <p style="font-size:12px;color:#777">
              2FC E-SPORTS Security System
            </p>
          </div>
        `
      })
    }
  );

  const result = await response.json().catch(() => ({}));

  if (!response.ok) {
    console.error(
      'Resend API error:',
      response.status,
      result
    );

    throw new Error(
      result?.message ||
      `Resend API request failed with status ${response.status}`
    );
  }
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
// FIREBASE CLOUD MESSAGING PUSH SENDER
// SUPPORT PIN: MULTIPLE USERS
// ===============================

app.post('/api/push/send', async (req, res) => {
  try {
    const authHeader = String(req.headers.authorization || '');

    const idToken = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7).trim()
      : '';

    if (!idToken) {
      return res.status(401).json({
        ok: false,
        message: 'Admin authentication required.'
      });
    }

    const decoded = await auth.verifyIdToken(idToken);

    const adminSnap = await db
      .collection('admins')
      .doc(decoded.uid)
      .get();

    if (!adminSnap.exists || adminSnap.data()?.active !== true) {
      return res.status(403).json({
        ok: false,
        message: 'Active admin access required.'
      });
    }

    const title = String(req.body?.title || '')
      .trim()
      .slice(0, 100);

    const body = String(req.body?.message || '')
      .trim()
      .slice(0, 1500);

    const supportPins = parseSupportPins(req.body?.supportPin);

    const recipients = Array.isArray(req.body?.recipients)
      ? req.body.recipients
      : [];

    const targetUrl = String(req.body?.targetUrl || '').trim();

    if (
      !title ||
      !body ||
      supportPins.length > 100 ||
      recipients.length > 500 ||
      !validHttpUrl(targetUrl)
    ) {
      return res.status(400).json({
        ok: false,
        message: 'Invalid push notification details.'
      });
    }

    // Find users matching supplied Support PINs.
    // Empty PIN means use the recipient list supplied by Admin Panel.

    const matchedUsers = new Map();

    if (supportPins.length) {
      for (const pin of supportPins) {
        const [supportPinSnap, immutablePinSnap] = await Promise.all([
          db.collection('users')
            .where('supportPin', '==', pin)
            .get(),

          db.collection('users')
            .where('immutableSupportPin', '==', pin)
            .get()
        ]);

        for (const snap of supportPinSnap.docs) {
          matchedUsers.set(snap.id, snap);
        }

        for (const snap of immutablePinSnap.docs) {
          matchedUsers.set(snap.id, snap);
        }
      }
    }

    const uniqueRecipients = new Map();

    for (const item of recipients) {
      const email = normalizeEmail(item?.email);
      const notificationId = String(item?.notificationId || '').trim();

      if (email && notificationId) {
        uniqueRecipients.set(email, notificationId);
      }
    }

    if (!uniqueRecipients.size) {
      return res.status(400).json({
        ok: false,
        message: 'No valid notification recipients were supplied.'
      });
    }

    const recipientRows = [...uniqueRecipients.entries()];

    const userDocs = await Promise.all(
      recipientRows.map(([email]) =>
        db.collection('users').doc(email).get()
      )
    );

    const messages = [];
    const tokenRefs = [];

    for (let index = 0; index < userDocs.length; index++) {
      const snap = userDocs[index];

      const [email, notificationId] = recipientRows[index];

      if (!snap.exists) continue;

      const userData = snap.data() || {};

      // If PINs were supplied, only send to users matching those PINs.
      if (supportPins.length) {
        const matched = matchedUsers.get(snap.id);

        if (!matched) continue;

        const userPins = [
          String(userData.supportPin || '').trim(),
          String(userData.immutableSupportPin || '').trim()
        ].filter(Boolean);

        if (!userPins.some(pin => supportPins.includes(pin))) {
          continue;
        }
      }

      // Verify saved in-app notification belongs to this user.
      const notificationSnap = await db
        .collection('userNotifications')
        .doc(notificationId)
        .get();

      if (!notificationSnap.exists) continue;

      const notificationData = notificationSnap.data() || {};

      if (
        normalizeEmail(notificationData.recipientEmail) !== email
      ) {
        continue;
      }

      const token = String(userData.fcmToken || '').trim();

      if (!token) continue;

      const notificationUrl = targetUrl ||
        '/?notificationId=' + encodeURIComponent(notificationId);

      messages.push({
        token,

        data: {
          title,
          body,
          url: notificationUrl,
          targetUrl: targetUrl || '',
          notificationId,
          notificationType: '2fc-user-notification'
        },

        webpush: {
          headers: {
            TTL: '86400',
            Urgency: 'high'
          }
        }
      });

      tokenRefs.push(snap.ref);
    }

    if (!messages.length) {
      return res.json({
        ok: true,
        sent: 0,
        noDevice: recipientRows.length,
        message: 'No enabled devices found for the selected users.'
      });
    }

    const results = await Promise.allSettled(
      messages.map(message =>
        admin.messaging().send(message)
      )
    );

    const invalidCodes = new Set([
      'messaging/registration-token-not-registered',
      'messaging/invalid-registration-token'
    ]);

    const cleanup = [];

    let sent = 0;
    let failed = 0;

    results.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        sent += 1;
      } else {
        failed += 1;

        console.error(
          'Push delivery error:',
          result.reason?.code || result.reason?.message
        );

        if (invalidCodes.has(result.reason?.code)) {
          cleanup.push(
            tokenRefs[index].update({
              fcmToken: admin.firestore.FieldValue.delete(),
              fcmTokenUpdatedAt: admin.firestore.FieldValue.delete()
            })
          );
        }
      }
    });

    if (cleanup.length) {
      await Promise.allSettled(cleanup);
    }

    return res.json({
      ok: true,
      sent,
      failed,
      noDevice: recipientRows.length - messages.length
    });

  } catch (error) {
    console.error('FCM push send error:', error);

    const status = String(error?.code || '').startsWith('auth/')
      ? 401
      : 500;

    return res.status(status).json({
      ok: false,
      message: 'Could not send push notifications.'
    });
  }
});

// ===============================
// REQUEST OTP
// ===============================

app.post('/api/password-otp/request', async (req, res) => {
  try {
    if (!checkRequestRate(req)) {
      return res.status(429).json({
        ok: false,
        message: 'Too many requests. Please try again later.'
      });
    }

    const email = normalizeEmail(req.body?.email);

    if (!validGmail(email)) {
      return res.status(400).json({
        ok: false,
        message: 'Enter a valid registered Gmail.'
      });
    }

    const existing = otpStore.get(email);

    if (
      existing &&
      existing.lastSentAt &&
      now() - existing.lastSentAt < RESEND_COOLDOWN_MS
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

    try {
      await auth.getUserByEmail(email);
    } catch (error) {
      if (error?.code !== 'auth/user-not-found') throw error;

      const legacyUser = await db
        .collection('users')
        .doc(email)
        .get();

      if (!legacyUser.exists) {
        return res.status(404).json({
          ok: false,
          message: 'No registered 2FC account was found for this Gmail.'
        });
      }
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

    return res.json({
      ok: true,
      message: 'OTP sent to your registered Gmail.'
    });

  } catch (error) {
    console.error('OTP request error:', error);

    return res.status(500).json({
      ok: false,
      message: 'Unable to send OTP right now.'
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
        message: 'Too many requests. Please try again later.'
      });
    }

    const email = normalizeEmail(req.body?.email);
    const otp = String(req.body?.otp || '').trim();

    if (
      !validGmail(email) ||
      !/^\d{6}$/.test(otp)
    ) {
      return res.status(400).json({
        ok: false,
        message: 'Enter the 6-digit OTP.'
      });
    }

    const record = otpStore.get(email);

    if (!record) {
      return res.status(400).json({
        ok: false,
        message: 'OTP expired. Please request a new OTP.'
      });
    }

    if (
      !record.otpExpiresAt ||
      record.otpExpiresAt <= now()
    ) {
      otpStore.delete(email);

      return res.status(400).json({
        ok: false,
        message: 'OTP expired. Please request a new OTP.'
      });
    }

    if (record.attempts >= MAX_OTP_ATTEMPTS) {
      otpStore.delete(email);

      return res.status(429).json({
        ok: false,
        message: 'Too many wrong attempts. Please request a new OTP.'
      });
    }

    const suppliedHash = hash(otp);

    if (!safeEqual(suppliedHash, record.otpHash)) {
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
        message:
          `Wrong OTP. ${MAX_OTP_ATTEMPTS - record.attempts} attempts remaining.`
      });
    }

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

    return res.status(500).json({
      ok: false,
      message: 'Unable to verify OTP right now.'
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
        message: 'Too many requests. Please try again later.'
      });
    }

    const email = normalizeEmail(req.body?.email);
    const resetToken = String(req.body?.resetToken || '');
    const newPassword = String(req.body?.newPassword || '');
    const confirmPassword = String(req.body?.confirmPassword || '');

    if (!validGmail(email) || !resetToken) {
      return res.status(400).json({
        ok: false,
        message: 'Invalid reset session.'
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        ok: false,
        message: 'Password must be at least 6 characters.'
      });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        ok: false,
        message: 'Passwords do not match.'
      });
    }

    const record = otpStore.get(email);

    if (
      !record ||
      !record.resetTokenHash ||
      record.resetExpiresAt <= now() ||
      !safeEqual(hash(resetToken), record.resetTokenHash)
    ) {
      return res.status(400).json({
        ok: false,
        message: 'Reset session expired. Please start again.'
      });
    }

    let user;

    try {
      user = await auth.getUserByEmail(email);

      await auth.updateUser(user.uid, {
        password: newPassword
      });

    } catch (error) {
      if (error?.code !== 'auth/user-not-found') throw error;

      const legacyUser = await db
        .collection('users')
        .doc(email)
        .get();

      if (!legacyUser.exists) {
        return res.status(404).json({
          ok: false,
          message: 'No registered 2FC account was found for this Gmail.'
        });
      }

      user = await auth.createUser({
        email,
        password: newPassword
      });
    }

    const userProfileRef = db
      .collection('users')
      .doc(email);

    const userProfile = await userProfileRef.get();

    if (userProfile.exists) {
      await userProfileRef.update({
        password: admin.firestore.FieldValue.delete(),
        authUid: user.uid,
        passwordUpdatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }

    await db.collection('passwordChangeEvents').add({
      uid: user.uid,
      email,
      changedAt: admin.firestore.FieldValue.serverTimestamp(),
      method: '6-digit-email-otp'
    });

    otpStore.delete(email);

    return res.json({
      ok: true,
      message: 'Password changed successfully. You can now login.'
    });

  } catch (error) {
    console.error('Password reset error:', error);

    return res.status(500).json({
      ok: false,
      message: 'Unable to change password right now.'
    });
  }
});

// ===============================
// ERROR HANDLER
// ===============================

app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err);

  res.status(500).json({
    ok: false,
    message: 'Internal server error.'
  });
});

// ===============================
// START SERVER
// ===============================

app.listen(PORT, () => {
  console.log(
    `2FC E-SPORTS OTP backend running on port ${PORT}`
  );
});
