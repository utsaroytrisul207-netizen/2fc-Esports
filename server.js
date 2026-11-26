import 'dotenv/config';
import express from 'express';
import cors from 'cors';
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
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  next();
});

if (!admin.apps.length) {
  const raw = required('FIREBASE_SERVICE_ACCOUNT_JSON');
  let serviceAccount;
  try {
    serviceAccount = JSON.parse(raw);
  } catch {
    throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON.');
  }
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}

const db = admin.firestore();
const auth = admin.auth();
const resendApiKey = required('RESEND_API_KEY');
const resendFrom = required('RESEND_FROM');

async function sendEmail({ to, subject, text, html }) {
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${resendApiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: resendFrom,
      to: [to],
      subject,
      text,
      html
    })
  });

  if (!response.ok) {
    const details = await response.text().catch(() => '');
    throw new Error(`Resend email error (${response.status}): ${details || response.statusText}`);
  }
}

function normalizeEmail(v) {
  return String(v || '').trim().toLowerCase();
}

function validGmail(email) {
  return /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@gmail\.com$/i.test(email);
}

function validPhone(phone) {
  return /^\+?[0-9][0-9\s-]{7,18}$/.test(String(phone || '').trim());
}

function normalizePhone(phone) {
  return String(phone || '').trim().replace(/[\s-]/g, '');
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

async function sendOtpEmail(email, otp) {
  await sendEmail({
    to: email,
    subject: '2FC E-SPORTS — Password Reset OTP',
    text: `Your 2FC E-SPORTS password reset OTP is ${otp}.

This OTP is valid for 60 seconds. After 5 wrong attempts, the OTP becomes invalid.

If you did not request this, ignore this email.`,
    html: `<div style="font-family:Arial,sans-serif;line-height:1.5"><h2>2FC E-SPORTS — Password Reset</h2><p>Your 6-digit OTP is:</p><div style="font-size:32px;font-weight:800;letter-spacing:8px">${otp}</div><p>This OTP is valid for <b>60 seconds</b>.</p><p>After 5 wrong attempts, the current OTP becomes invalid.</p><p>If you did not request a password reset, ignore this email.</p></div>`
  });
}

async function sendAccountOtpEmail(email, otp, purpose) {
  const label = purpose === 'EMAIL' ? 'Email Change' : 'Phone Number Connection';
  await sendEmail({
    to: email,
    subject: `2FC E-SPORTS — ${label} OTP`,
    text: `Your ${label} OTP is ${otp}. It is valid for 60 seconds. This code was sent only to the current registered Gmail on your 2FC account. After an approved email change, future OTPs go to the new Gmail. No OTP/SMS is sent to any phone number.`,
    html: `<div style="font-family:Arial,sans-serif;line-height:1.5"><h2>2FC E-SPORTS — ${label}</h2><p>Your 6-digit OTP is:</p><div style="font-size:32px;font-weight:800;letter-spacing:8px">${otp}</div><p>Valid for <b>60 seconds</b>.</p><p>This OTP was sent only to your account's current registered Gmail. After an approved email change, future OTPs go to the new Gmail. No SMS or phone OTP is sent.</p></div>`
  });
}

async function sendActionOtpEmail(email, otp, action) {
  const actionName = action === 'JOIN_MATCH' ? 'Join Match' : 'Withdraw';
  await sendEmail({
    to: email,
    subject: `2FC E-SPORTS — ${actionName} Verification OTP`,
    text: `Your ${actionName} verification OTP is ${otp}. This OTP is valid for 60 seconds and can be used only once. After 5 wrong attempts, it becomes invalid.`,
    html: `<div style="font-family:Arial,sans-serif;line-height:1.5"><h2>2FC E-SPORTS — ${actionName} Verification</h2><p>Your 6-digit OTP is:</p><div style="font-size:32px;font-weight:800;letter-spacing:8px">${otp}</div><p>This OTP is valid for <b>60 seconds</b>.</p><p>After 5 wrong attempts, the OTP becomes invalid.</p></div>`
  });
}

async function readBearerIdentity(req, res) {
  const header = String(req.headers.authorization || '');
  const match = header.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    res.status(401).json({ ok: false, message: 'Please login again before verification.' });
    return null;
  }

  try {
    const decoded = await auth.verifyIdToken(match[1]);
    const user = await auth.getUser(decoded.uid);
    return { uid: decoded.uid, authUser: user, decoded };
  } catch {
    res.status(401).json({ ok: false, message: 'Login session expired. Please login again.' });
    return null;
  }
}

async function findProfileByUid(uid, authUser) {
  let snap = await db.collection('users').where('authUid', '==', uid).limit(1).get();

  if (snap.empty) {
    snap = await db.collection('users').where('googleUid', '==', uid).limit(1).get();
  }

  if (snap.empty && authUser?.email) {
    const direct = await db.collection('users').doc(normalizeEmail(authUser.email)).get();
    if (direct.exists) return direct;
  }

  return snap.empty ? null : snap.docs[0];
}

async function getAccountContext(uid, authUser) {
  const profileSnap = await findProfileByUid(uid, authUser);
  if (!profileSnap) throw new Error('2FC account profile was not found for this login.');

  const data = profileSnap.data() || {};
  const currentEmail = normalizeEmail(authUser?.email || data.email || profileSnap.id);

  if (!validGmail(currentEmail)) {
    throw new Error('The active registered Gmail is missing or invalid. Please contact support.');
  }

  return { profileRef: profileSnap.ref, data, currentEmail };
}

app.get('/health', (req, res) => {
  res.json({ ok: true, service: '2FC E-SPORTS OTP backend' });
});

// Account changes: OTP is sent to the CURRENT Firebase Auth Gmail.
// When an email change succeeds, the new Gmail becomes the only active OTP destination.
app.post('/api/account-otp/request', async (req, res) => {
  try {
    const identity = await readBearerIdentity(req, res);
    if (!identity) return;

    const purpose = String(req.body?.purpose || '').toUpperCase();
    const targetRaw = String(req.body?.target || '').trim();

    if (!['EMAIL', 'PHONE'].includes(purpose)) {
      return res.status(400).json({ ok: false, message: 'Invalid account change request.' });
    }

    if (purpose === 'EMAIL' && !validGmail(normalizeEmail(targetRaw))) {
      return res.status(400).json({ ok: false, message: 'Enter a valid Gmail address.' });
    }

    if (purpose === 'PHONE' && !validPhone(targetRaw)) {
      return res.status(400).json({ ok: false, message: 'Enter a valid phone number.' });
    }

    const ctx = await getAccountContext(identity.uid, identity.authUser);
    const target = purpose === 'EMAIL' ? normalizeEmail(targetRaw) : normalizePhone(targetRaw);

    if (purpose === 'EMAIL' && target === ctx.currentEmail) {
      return res.status(400).json({ ok: false, message: 'This is already your current Gmail address.' });
    }

    const ref = db.collection('accountChangeOtps').doc(`${identity.uid}_${purpose}`);
    const oldSnap = await ref.get();
    const old = oldSnap.exists ? oldSnap.data() : {};

    if (old.lastSentAt && now() - Number(old.lastSentAt) < RESEND_COOLDOWN_MS) {
      const wait = Math.ceil((RESEND_COOLDOWN_MS - (now() - Number(old.lastSentAt))) / 1000);
      return res.status(429).json({ ok: false, message: `Please wait ${wait} seconds before requesting another OTP.` });
    }

    if (purpose === 'EMAIL') {
      const existing = await db.collection('users').where('email', '==', target).limit(1).get();

      if (!existing.empty && existing.docs[0].ref.path !== ctx.profileRef.path) {
        return res.status(409).json({ ok: false, message: 'This Gmail is already used by another account.' });
      }

      const direct = await db.collection('users').doc(target).get();

      if (direct.exists && direct.ref.path !== ctx.profileRef.path) {
        return res.status(409).json({ ok: false, message: 'This Gmail is already used by another account.' });
      }

      try {
        const authExisting = await auth.getUserByEmail(target);
        if (authExisting.uid !== identity.uid) {
          return res.status(409).json({ ok: false, message: 'This Gmail is already used by another Firebase account.' });
        }
      } catch (error) {
        if (error.code !== 'auth/user-not-found') throw error;
      }
    } else {
      const existing = await db.collection('users').where('phone', '==', target).limit(1).get();

      if (!existing.empty && existing.docs[0].ref.path !== ctx.profileRef.path) {
        return res.status(409).json({ ok: false, message: 'This phone number is already used by another account.' });
      }
    }

    const otp = randomOtp();
    await sendAccountOtpEmail(ctx.currentEmail, otp, purpose);
    await ref.set({
      uid: identity.uid,
      profilePath: ctx.profileRef.path,
      currentEmail: ctx.currentEmail,
      purpose,
      target,
      otpHash: hash(otp),
      otpExpiresAt: now() + OTP_TTL_MS,
      lastSentAt: now(),
      attempts: 0
    });

    return res.json({
      ok: true,
      message: `OTP sent to your current registered Gmail: ${ctx.currentEmail}.`
    });
  } catch (error) {
    console.error('Account OTP request error:', error);
    return res.status(500).json({ ok: false, message: error.message || 'Unable to send OTP right now.' });
  }
});

app.post('/api/account-otp/verify', async (req, res) => {
  let authEmailChanged = false;
  let previousEmail = '';
  let identityUid = '';

  try {
    const identity = await readBearerIdentity(req, res);
    if (!identity) return;

    const purpose = String(req.body?.purpose || '').toUpperCase();
    const targetRaw = String(req.body?.target || '').trim();
    const otp = String(req.body?.otp || '').trim();

    if (!['EMAIL', 'PHONE'].includes(purpose) || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({ ok: false, message: 'Enter the 6-digit OTP.' });
    }

    const target = purpose === 'EMAIL' ? normalizeEmail(targetRaw) : normalizePhone(targetRaw);
    const ctx = await getAccountContext(identity.uid, identity.authUser);
    const ref = db.collection('accountChangeOtps').doc(`${identity.uid}_${purpose}`);

    const result = await db.runTransaction(async tx => {
      const snap = await tx.get(ref);

      if (!snap.exists) {
        return { status: 400, message: 'OTP expired. Please request a new OTP.' };
      }

      const record = snap.data() || {};

      if (
        record.uid !== identity.uid ||
        record.profilePath !== ctx.profileRef.path ||
        record.currentEmail !== ctx.currentEmail ||
        record.purpose !== purpose ||
        record.target !== target
      ) {
        return { status: 403, message: 'Verification session does not match this account or target.' };
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

      tx.delete(ref);
      return { status: 200 };
    });

    if (result.status !== 200) {
      return res.status(result.status).json({ ok: false, message: result.message });
    }

    if (purpose === 'EMAIL') {
      const existingProfile = await db.collection('users').doc(target).get();

      if (existingProfile.exists && existingProfile.ref.path !== ctx.profileRef.path) {
        return res.status(409).json({ ok: false, message: 'This Gmail is already used by another account.' });
      }

      try {
        const existingAuth = await auth.getUserByEmail(target);

        if (existingAuth.uid !== identity.uid) {
          return res.status(409).json({ ok: false, message: 'This Gmail is already used by another Firebase account.' });
        }
      } catch (error) {
        if (error.code !== 'auth/user-not-found') throw error;
      }

      previousEmail = ctx.currentEmail;
      identityUid = identity.uid;

      // Update Firebase Authentication first so the new Gmail + existing password can log in.
      await auth.updateUser(identity.uid, { email: target, emailVerified: false });
      authEmailChanged = true;

      const newProfileRef = db.collection('users').doc(target);
      const changeEventRef = db.collection('accountChangeEvents').doc();

      await db.runTransaction(async tx => {
        const oldSnap = await tx.get(ctx.profileRef);
        const newSnap = await tx.get(newProfileRef);

        if (!oldSnap.exists) {
          throw new Error('Account profile changed during email update. Please contact support.');
        }

        if (newSnap.exists && newProfileRef.path !== ctx.profileRef.path) {
          throw new Error('This Gmail is already used by another account.');
        }

        const latest = oldSnap.data() || {};
        const updated = {
          ...latest,
          email: target,
          originalEmail: target,
          immutableEmail: target,
          mailVerified: false,
          emailVerified: false,
          emailChangedAt: admin.firestore.FieldValue.serverTimestamp(),
          profileUpdatedAt: new Date().toISOString(),
          authUid: identity.uid
        };

        tx.set(newProfileRef, updated);
        tx.set(changeEventRef, {
          uid: identity.uid,
          type: 'EMAIL',
          oldValue: previousEmail,
          newValue: target,
          changedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        if (newProfileRef.path !== ctx.profileRef.path) {
          tx.delete(ctx.profileRef);
        }
      });

      return res.json({
        ok: true,
        message: 'Gmail changed successfully. Please log in again using the new Gmail and your existing password.',
        newEmail: target,
        reauthenticationRequired: true
      });
    }

    const existing = await db.collection('users').where('phone', '==', target).limit(1).get();

    if (!existing.empty && existing.docs[0].ref.path !== ctx.profileRef.path) {
      return res.status(409).json({ ok: false, message: 'This phone number is already used by another account.' });
    }

    const changeEventRef = db.collection('accountChangeEvents').doc();

    await db.runTransaction(async tx => {
      const profileSnap = await tx.get(ctx.profileRef);

      if (!profileSnap.exists) {
        throw new Error('Account profile was not found.');
      }

      const previousPhone = normalizePhone(profileSnap.data()?.phone || '');

      tx.set(ctx.profileRef, {
        phone: target,
        phoneVerified: true,
        phoneVerifiedAt: admin.firestore.FieldValue.serverTimestamp(),
        profileUpdatedAt: new Date().toISOString()
      }, { merge: true });

      tx.set(changeEventRef, {
        uid: identity.uid,
        type: 'PHONE',
        oldValue: previousPhone,
        newValue: target,
        changedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    return res.json({ ok: true, message: 'Phone number connected after OTP verification to your current Gmail.' });
  } catch (error) {
    if (authEmailChanged && previousEmail && identityUid) {
      try {
        await auth.updateUser(identityUid, { email: previousEmail, emailVerified: false });
      } catch (rollbackError) {
        console.error('Email update rollback failed:', rollbackError);
      }
    }

    console.error('Account OTP verify error:', error);
    return res.status(500).json({ ok: false, message: 'Unable to verify and save this change right now.' });
  }
});

// Join Match / Withdraw verification OTPs retained from the existing backend.
async function requireGoogleIdentity(req, res) {
  const identity = await readBearerIdentity(req, res);
  if (!identity) return null;

  const email = normalizeEmail(identity.decoded.email);

  if (!identity.decoded.email_verified || !validGmail(email)) {
    res.status(403).json({ ok: false, message: 'A verified Gmail account is required.' });
    return null;
  }

  const googleProvider = (identity.authUser.providerData || []).find(p => p.providerId === 'google.com');

  if (!googleProvider) {
    res.status(403).json({ ok: false, message: 'Link a Google account to this 2FC account first.' });
    return null;
  }

  return { uid: identity.uid, email };
}

function validAction(value) {
  return value === 'JOIN_MATCH' || value === 'WITHDRAW';
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

      tx.delete(ref);
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

// Password-reset OTPs are stored in Firestore so Render restarts / multiple instances
// do not lose codes between request, verify, and reset. Store only hashes, never OTPs.
function passwordResetRef(email) {
  return db.collection('passwordResetOtps').doc(hash(normalizeEmail(email)));
}

app.post('/api/password-otp/request', async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);

    if (!validGmail(email)) {
      return res.status(400).json({ ok: false, message: 'Enter a valid registered Gmail.' });
    }

    let user;

    try {
      user = await auth.getUserByEmail(email);
    } catch (error) {
      if (error.code === 'auth/user-not-found') {
        return res.status(404).json({ ok: false, message: 'No registered 2FC account was found for this Gmail.' });
      }
      throw error;
    }

    const ref = passwordResetRef(email);
    const previous = await ref.get();
    const previousData = previous.exists ? previous.data() : {};

    if (previousData.lastSentAt && now() - Number(previousData.lastSentAt) < RESEND_COOLDOWN_MS) {
      const wait = Math.ceil((RESEND_COOLDOWN_MS - (now() - Number(previousData.lastSentAt))) / 1000);
      return res.status(429).json({ ok: false, message: `Please wait ${wait} seconds before requesting another OTP.` });
    }

    const otp = randomOtp();
    const record = {
      uid: user.uid,
      email,
      otpHash: hash(otp),
      otpExpiresAt: now() + OTP_TTL_MS,
      lastSentAt: now(),
      attempts: 0,
      resetTokenHash: null,
      resetExpiresAt: 0,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    await ref.set(record);

    try {
      await sendOtpEmail(email, otp);
    } catch (mailError) {
      await ref.delete().catch(() => {});
      console.error('Password OTP email delivery error:', mailError);
      return res.status(502).json({
        ok: false,
        message: 'OTP email could not be sent. Check the mail server configuration and try again.'
      });
    }

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

    const ref = passwordResetRef(email);
    const resetToken = randomToken();

    const result = await db.runTransaction(async tx => {
      const snap = await tx.get(ref);

      if (!snap.exists) {
        return { status: 400, message: 'OTP expired. Please request a new OTP.' };
      }

      const record = snap.data() || {};

      if (record.email !== email || Number(record.otpExpiresAt || 0) <= now() || !record.otpHash) {
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
        resetTokenHash: hash(resetToken),
        resetExpiresAt: now() + RESET_SESSION_TTL_MS
      });

      return { status: 200 };
    });

    if (result.status !== 200) {
      return res.status(result.status).json({ ok: false, message: result.message });
    }

    return res.json({ ok: true, resetToken });
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

    const ref = passwordResetRef(email);
    const snap = await ref.get();
    const record = snap.exists ? snap.data() : null;

    if (!record?.resetTokenHash || Number(record.resetExpiresAt || 0) <= now() || hash(resetToken) !== record.resetTokenHash) {
      return res.status(400).json({ ok: false, message: 'Reset session expired. Please start again.' });
    }

    const user = await auth.getUserByEmail(email);
    await auth.updateUser(user.uid, { password: newPassword });

    await db.collection('passwordChangeEvents').add({
      uid: user.uid,
      email,
      changedAt: admin.firestore.FieldValue.serverTimestamp(),
      method: '6-digit-email-otp'
    });

    await ref.delete();
    return res.json({ ok: true, message: 'Password changed successfully. You can now login.' });
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
