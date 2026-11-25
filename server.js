import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import admin from 'firebase-admin';
import crypto from 'node:crypto';

const app = express();
app.set('trust proxy', 1);
const PORT = Number(process.env.PORT || 3000);

const OTP_TTL_MS = 5 * 60_000;
const RESEND_COOLDOWN_MS = 60_000;
const RESET_SESSION_TTL_MS = 10 * 60_000;
const MAX_OTP_ATTEMPTS = 5;
const REQUEST_WINDOW_MS = 10 * 60_000;
const MAX_REQUESTS_PER_WINDOW = 10;

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

// EXPRESS SECURITY
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

// FIREBASE ADMIN
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

// OWNER / ADMIN AUTHORIZATION
const OWNER_UID = String(process.env.OWNER_UID || '').trim();

async function authenticateFirebaseUser(req, res, next) {
  try {
    const authHeader = String(req.headers.authorization || '');
    const idToken = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7).trim()
      : '';

    if (!idToken) {
      return res.status(401).json({
        ok: false,
        message: 'Firebase authentication required.'
      });
    }

    req.firebaseUser = await auth.verifyIdToken(idToken, true);
    return next();
  } catch (error) {
    console.warn('[AUTH] Firebase token rejected:', error?.code || error?.message);
    return res.status(401).json({
      ok: false,
      message: 'Invalid or expired authentication token.'
    });
  }
}

async function requireAdminOrOwner(req, res, next) {
  try {
    if (!OWNER_UID) {
      console.error('[AUTH] OWNER_UID is not configured. Admin access is disabled.');
      return res.status(503).json({
        ok: false,
        message: 'Server owner security is not configured.'
      });
    }

    const uid = String(req.firebaseUser?.uid || '');

    if (!uid) {
      return res.status(401).json({
        ok: false,
        message: 'Firebase authentication required.'
      });
    }

    if (uid === OWNER_UID) {
      req.authRole = 'owner';
      return next();
    }

    const adminSnap = await db.collection('admins').doc(uid).get();
    const adminData = adminSnap.exists ? (adminSnap.data() || {}) : {};

    if (
      !adminSnap.exists ||
      adminData.active !== true ||
      String(adminData.role || '').trim().toLowerCase() !== 'admin'
    ) {
      return res.status(403).json({
        ok: false,
        message: 'Active admin access required.'
      });
    }

    req.authRole = 'admin';
    return next();
  } catch (error) {
    console.error('[AUTH] Admin authorization error:', error);
    return res.status(500).json({
      ok: false,
      message: 'Could not verify admin permissions.'
    });
  }
}

async function requireOwner(req, res, next) {
  if (!OWNER_UID) {
    console.error('[AUTH] OWNER_UID is not configured. Owner access is disabled.');
    return res.status(503).json({
      ok: false,
      message: 'Server owner security is not configured.'
    });
  }

  if (String(req.firebaseUser?.uid || '') !== OWNER_UID) {
    return res.status(403).json({
      ok: false,
      message: 'Owner access only.'
    });
  }

  req.authRole = 'owner';
  return next();
}

// RESEND EMAIL API
const resendApiKey = required('RESEND_API_KEY');
const resendFrom = required('RESEND_FROM');

// MEMORY STORES
const otpStore = new Map();
const requestRateStore = new Map();

// RATE LIMIT
function getClientIp(req) {
  return String(req.ip || req.socket?.remoteAddress || 'unknown');
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

// CLEANUP
function cleanupExpired() {
  const currentTime = now();

  for (const [email, record] of otpStore) {
    const otpStillActive =
      Number(record.otpExpiresAt || 0) > currentTime;

    const resetStillActive =
      Number(record.resetExpiresAt || 0) > currentTime;

    if (!otpStillActive && !resetStillActive) {
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


// SEND OTP EMAIL THROUGH RESEND
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
        <div style="margin:0;padding:28px 12px;background:#f3f5fa;font-family:Arial,Helvetica,sans-serif;color:#202638;">
          <div style="max-width:560px;margin:0 auto;">

            <div style="padding:22px 24px;text-align:center;background:#17213b;border-radius:14px 14px 0 0;">
              <div style="font-size:25px;line-height:1.2;font-weight:800;letter-spacing:1px;color:#ffffff;">
                2FC E-SPORTS
              </div>
              <div style="margin-top:6px;font-size:12px;letter-spacing:2px;color:#c8d2ee;">
                ACCOUNT SECURITY
              </div>
            </div>

            <div style="padding:30px 26px;background:#ffffff;border:1px solid #e4e8f1;border-top:0;border-radius:0 0 14px 14px;">

              <h2 style="margin:0 0 10px;text-align:center;font-size:23px;line-height:1.35;color:#202a44;">
                Password Reset
              </h2>

              <p style="margin:0 0 24px;text-align:center;font-size:15px;line-height:1.6;color:#606b80;">
                Use the verification code below to reset your 2FC E-SPORTS password.
              </p>

              <div style="padding:22px 12px;text-align:center;background:#f3f1ff;border:1px solid #ded8ff;border-radius:12px;">

                <div style="margin-bottom:10px;font-size:12px;font-weight:700;letter-spacing:1.4px;color:#6553b8;">
                  YOUR 6-DIGIT OTP
                </div>

                <div style="font-size:34px;line-height:1.3;font-weight:800;letter-spacing:9px;color:#34276f;">
                  ${otp}
                </div>

              </div>

              <div style="margin:18px 0 0;padding:13px 16px;text-align:center;background:#eef5ff;border-radius:9px;color:#315b91;font-size:14px;line-height:1.5;">
                This OTP is valid for <strong>5 minutes</strong>.
              </div>

              <div style="margin-top:18px;padding:14px 16px;background:#fff8e9;border:1px solid #f3e1b8;border-radius:9px;color:#75551b;font-size:14px;line-height:1.6;">
                <strong>Security notice:</strong>
                After 5 wrong attempts, the current OTP becomes invalid.
              </div>

              <p style="margin:22px 0 0;font-size:14px;line-height:1.7;color:#606b80;">
                If you did not request this password reset, you can safely ignore this email.
              </p>

              <div style="height:1px;margin:24px 0 14px;background:#e7eaf1;"></div>

              <p style="margin:0;text-align:center;font-size:12px;line-height:1.6;color:#8790a2;">
                2FC E-SPORTS Security System
              </p>

            </div>

            <p style="margin:14px 0 0;text-align:center;font-size:11px;color:#9aa2b1;">
              This is an automated security email. Please do not reply.
            </p>

          </div>
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

// HEALTH CHECK
app.get('/health', (req, res) => {
  res.json({
    ok: true,
    service: '2FC E-SPORTS OTP backend'
  });
});

// AUTHENTICATED SESSION CHECKS
app.get(
  '/api/admin/session',
  authenticateFirebaseUser,
  requireAdminOrOwner,
  (req, res) => {
    return res.json({
      ok: true,
      uid: req.firebaseUser.uid,
      role: req.authRole
    });
  }
);

app.get(
  '/api/owner/security-check',
  authenticateFirebaseUser,
  requireOwner,
  (req, res) => {
    return res.json({
      ok: true,
      owner: true,
      uid: req.firebaseUser.uid
    });
  }
);

// FIREBASE CLOUD MESSAGING PUSH SENDER
app.post('/api/push/send', authenticateFirebaseUser, requireAdminOrOwner, async (req, res) => {

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
    console.log('[PUSH] Authorized sender:', req.firebaseUser.uid, req.authRole);

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

    const results = await Promise.allSettled(
      messages.map(item => admin.messaging().send(item))
    );

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

// REQUEST OTP
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

// VERIFY OTP
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

// RESET PASSWORD
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

// ERROR HANDLER
app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err);

  res.status(500).json({
    ok: false,
    message: 'Internal server error.'
  });
});

// START SERVER
app.listen(PORT, () => {
  console.log(`2FC E-SPORTS OTP backend running on port ${PORT}`);
});
