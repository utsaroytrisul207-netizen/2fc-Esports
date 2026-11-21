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
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

function parseAllowedOrigins() {
  const raw = process.env.ALLOWED_ORIGINS || process.env.ALLOWED_ORIGIN || '*';
  if (raw === '*') return true;
  return raw.split(',').map(value => value.trim()).filter(Boolean);
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
  const values = Array.isArray(value) ? value : String(value || '').split(',');
  return [...new Set(values.map(pin => String(pin).trim()).filter(Boolean))];
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

app.use(express.json({ limit: '20kb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
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
    throw new Error('Firebase service account environment variable is not valid JSON.');
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
  if (forwarded) return String(forwarded).split(',')[0].trim();
  return req.ip || 'unknown';
}

function checkRequestRate(req) {
  const ip = getClientIp(req);
  const current = now();

  let record = requestRateStore.get(ip);

  if (!record || current - record.startedAt >= REQUEST_WINDOW_MS) {
    record = { startedAt: current, count: 0 };
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
    if (currentTime - record.startedAt >= REQUEST_WINDOW_MS) {
      requestRateStore.delete(ip);
    }
  }
}

setInterval(cleanupExpired, 60_000).unref();

// ===============================
// SEND OTP EMAIL THROUGH RESEND
// ===============================
async function sendOtpEmail(email, otp) {
  const response = await fetch('https://api.resend.com/emails', {
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
        <div style="font-family:Arial,sans-serif;line-height:1.5;max-width:600px;margin:auto;padding:20px">
          <h2>2FC E-SPORTS — Password Reset</h2>
          <p>Your 6-digit password reset OTP is:</p>
          <div style="font-size:32px;font-weight:800;letter-spacing:8px;margin:20px 0">${otp}</div>
          <p>This OTP is valid for <b>5 minutes</b>.</p>
          <p>After 5 wrong attempts, the current OTP becomes invalid.</p>
          <p>If you did not request this password reset, you can safely ignore this email.</p>
          <hr>
          <p style="font-size:12px;color:#777">2FC E-SPORTS Security System</p>
        </div>`
    })
  });

  const result = await response.json().catch(() => ({}));

  if (!response.ok) {
    console.error('Resend API error:', response.status, result);
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
// Blank PIN = recipients selected by Admin Panel
// PIN = only matching recipients
// ===============================
app.post('/api/push/send', async (req, res) => {

  // DEBUG: PUSH REQUEST
  console.log('[PUSH] Request received:', {
    time: new Date().toISOString(),
    recipientCount: Array.isArray(req.body?.recipients)
      ? req.body.recipients.length
      : 0,
    hasTitle: !!req.body?.title,
    hasMessage: !!req.body?.message,
    hasSupportPin: !!(
      req.body?.supportPin ||
      req.body?.supportPins
    )
  });

  try {
    const authHeader = String(req.headers.authorization || '');

    const idToken = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7).trim()
      : '';

    if (!idToken) {
      console.warn('[PUSH] Rejected: Admin authentication missing.');

      return res.status(401).json({
        ok: false,
        message: 'Admin authentication required.'
      });
    }

    const decoded = await auth.verifyIdToken(idToken);

    console.log('[PUSH] Admin token verified:', decoded.uid);

    const adminSnap = await db
      .collection('admins')
      .doc(decoded.uid)
      .get();

    if (!adminSnap.exists || adminSnap.data()?.active !== true) {
      console.warn('[PUSH] Rejected: admin is missing or inactive.');

      return res.status(403).json({
        ok: false,
        message: 'Active admin access required.'
      });
    }

    const title = String(req.body?.title || '')
      .trim()
      .slice(0, 100);

    const messageBody = String(req.body?.message || '')
      .trim()
      .slice(0, 1500);

    const recipients = Array.isArray(req.body?.recipients)
      ? req.body.recipients
      : [];

    const supportPins = parseSupportPins(
      req.body?.supportPin ?? req.body?.supportPins
    );

    const targetUrl = String(req.body?.targetUrl || '').trim();

    if (
      !title ||
      !messageBody ||
      !recipients.length ||
      recipients.length > 500 ||
      supportPins.length > 100 ||
      !validHttpUrl(targetUrl)
    ) {
      console.warn('[PUSH] Rejected: invalid notification details.');

      return res.status(400).json({
        ok: false,
        message: 'Invalid push notification details.'
      });
    }

    // Deduplicate recipient email + notification ID pairs.
    const recipientMap = new Map();

    for (const item of recipients) {
      const email = normalizeEmail(item?.email);
      const notificationId = String(item?.notificationId || '').trim();

      if (email && notificationId) {
        recipientMap.set(email, notificationId);
      }
    }

    if (!recipientMap.size) {
      console.warn('[PUSH] Rejected: no valid recipient records.');

      return res.status(400).json({
        ok: false,
        message: 'No valid notification recipients were supplied.'
      });
    }

    // Load only requested user documents.
    const recipientRows = [...recipientMap.entries()];

    const userSnaps = await Promise.all(
      recipientRows.map(([email]) =>
        db.collection('users').doc(email).get()
      )
    );

    const selectedUsers = [];

    for (let i = 0; i < recipientRows.length; i += 1) {
      const [email, notificationId] = recipientRows[i];
      const userSnap = userSnaps[i];

      if (!userSnap.exists) continue;

      // Check Support PIN if supplied.
      if (supportPins.length) {
        const userData = userSnap.data() || {};

        const userPins = [
          userData.supportPin,
          userData.immutableSupportPin
        ]
          .map(value => String(value || '').trim())
          .filter(Boolean);

        if (!userPins.some(pin => supportPins.includes(pin))) {
          continue;
        }
      }

      selectedUsers.push({
        email,
        notificationId,
        userSnap
      });
    }

    console.log('[PUSH] Recipient selection:', {
      requested: recipientRows.length,
      selected: selectedUsers.length,
      supportPinFilter: supportPins.length > 0
    });

    if (!selectedUsers.length) {
      console.warn('[PUSH] No matching registered recipients.');

      return res.status(404).json({
        ok: false,
        message: supportPins.length
          ? 'No recipients matched the supplied Support PIN(s).'
          : 'No registered recipient accounts were found.'
      });
    }

    const messages = [];
    const tokenRefs = [];

    let invalidNotificationRecords = 0;

    for (const row of selectedUsers) {
      const notificationSnap = await db
        .collection('userNotifications')
        .doc(row.notificationId)
        .get();

      if (!notificationSnap.exists) {
        invalidNotificationRecords += 1;
        continue;
      }

      const notificationData = notificationSnap.data() || {};

      if (
        normalizeEmail(notificationData.recipientEmail) !== row.email
      ) {
        invalidNotificationRecords += 1;
        continue;
      }

      const userData = row.userSnap.data() || {};

      if (supportPins.length) {
        const savedPin = String(
          notificationData.recipientSupportPin || ''
        ).trim();

        const actualPins = [
          userData.supportPin,
          userData.immutableSupportPin
        ]
          .map(value => String(value || '').trim())
          .filter(Boolean);

        if (savedPin && !actualPins.includes(savedPin)) {
          invalidNotificationRecords += 1;
          continue;
        }
      }

      const token = String(userData.fcmToken || '').trim();

      if (!token) continue;

      const fallbackUrl =
        '/?notificationId=' +
        encodeURIComponent(row.notificationId);

      messages.push({
        token,

        data: {
          title,
          body: messageBody,
          url: targetUrl || fallbackUrl,
          targetUrl: targetUrl || '',
          notificationId: row.notificationId,
          notificationType: '2fc-user-notification'
        },

        webpush: {
          headers: {
            TTL: '86400',
            Urgency: 'high'
          }
        }
      });

      tokenRefs.push(row.userSnap.ref);
    }

    // DEBUG: TOKEN CHECK
    console.log('[PUSH] Prepared messages:', {
      selectedUsers: selectedUsers.length,
      messagesWithFcmToken: messages.length,
      invalidNotificationRecords
    });

    if (!messages.length) {
      console.warn('[PUSH] No FCM tokens available for selected users.');

      return res.json({
        ok: true,
        sent: 0,
        failed: 0,
        noDevice: selectedUsers.length,
        invalidRecords: invalidNotificationRecords,
        message: 'No enabled devices found for the selected users.'
      });
    }

    // SEND TO FIREBASE
    const results = await Promise.allSettled(
      messages.map(item => admin.messaging().send(item))
    );

    // DEBUG: FIREBASE RESPONSE
    console.log('[PUSH] Firebase send results:', {
      total: results.length,
      success: results.filter(
        result => result.status === 'fulfilled'
      ).length,
      failed: results.filter(
        result => result.status === 'rejected'
      ).length
    });

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

        console.log('[PUSH] FCM accepted message:', {
          index,
          messageId: result.value
        });

      } else {
        failed += 1;

        console.error('[PUSH] FCM individual send error:', {
          index,
          code: result.reason?.code,
          message: result.reason?.message
        });

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
      console.log('[PUSH] Invalid FCM tokens cleaned:', cleanup.length);
    }

    // DEBUG: FINAL SUMMARY
    console.log('[PUSH] Final summary:', {
      sent,
      failed,
      noDevice: selectedUsers.length - messages.length,
      invalidRecords: invalidNotificationRecords
    });

    return res.json({
      ok: true,
      sent,
      failed,
      noDevice: selectedUsers.length - messages.length,
      invalidRecords: invalidNotificationRecords
    });

  } catch (error) {
    console.error('[PUSH] FCM push send error:', {
      code: error?.code,
      message: error?.message,
      stack: error?.stack
    });

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
      existing?.lastSentAt &&
      now() - existing.lastSentAt < RESEND_COOLDOWN_MS
    ) {
      const wait = Math.ceil(
        (RESEND_COOLDOWN_MS - (now() - existing.lastSentAt)) / 1000
      );

      return res.status(429).json({
        ok: false,
        message: `Please wait ${wait} seconds before requesting another OTP.`
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

    if (!validGmail(email) || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({
        ok: false,
        message: 'Enter the 6-digit OTP.'
      });
    }

    const record = otpStore.get(email);

    if (
      !record ||
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

    if (!safeEqual(hash(otp), record.otpHash)) {
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

    const userProfileRef = db.collection('users').doc(email);
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
  console.log(`2FC E-SPORTS OTP backend running on port ${PORT}`);
});
