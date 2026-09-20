const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { users, usersByEmail, pendingLogins, sessions, loginAttempts } = require('../lib/store');
const { createChallenge, verifyChallenge } = require('../lib/otp');
const { base32, totp, verifyTotp } = require('../lib/totp');
const { signJwt, verifyJwt } = require('../lib/jwt');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MOBILE_RE = /^\d{10}$/;

function passwordErrors(pw = '') {
  const errors = [];
  if (pw.length < 8) errors.push('At least 8 characters');
  if (!/[A-Z]/.test(pw)) errors.push('1 uppercase letter');
  if (!/[0-9]/.test(pw)) errors.push('1 number');
  if (!/[^A-Za-z0-9]/.test(pw)) errors.push('1 special character');
  return errors;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const given = crypto.scryptSync(password, salt, 64);
  return crypto.timingSafeEqual(given, Buffer.from(hash, 'hex'));
}

function maskMobile(countryCode, mobile) {
  return `${countryCode} ${mobile.slice(0, 5)} ${mobile.slice(5)}`;
}

function fail(res, status, error, extra = {}) {
  return res.status(status).json({ ok: false, error, ...extra });
}

app.post('/api/register', (req, res) => {
  const { fullName, email, countryCode = '+91', mobile, password, agreeTerms } = req.body || {};
  // JSON bodies can carry numbers/arrays; every text field must be a real string
  if (![fullName, email, countryCode, mobile, password].every((v) => typeof v === 'string')) {
    return fail(res, 400, 'VALIDATION_ERROR', { errors: { form: 'All fields must be text' } });
  }
  const errors = {};

  if (!fullName || fullName.trim().length < 2) errors.fullName = 'Enter your full name';
  if (!EMAIL_RE.test(email || '')) errors.email = 'Enter a valid email';
  if (!MOBILE_RE.test(mobile || '')) errors.mobile = 'Enter a 10-digit mobile number';
  const pwErrors = passwordErrors(password);
  if (pwErrors.length) errors.password = `Password must contain: ${pwErrors.join(', ')}`;
  if (!/^\+\d{1,4}$/.test(countryCode)) errors.countryCode = 'Enter a valid country code';
  if (agreeTerms !== true) errors.agreeTerms = 'You must agree to the Terms & Conditions';
  if (Object.keys(errors).length) return fail(res, 400, 'VALIDATION_ERROR', { errors });

  const normalizedEmail = email.toLowerCase();
  const existing = users.get(usersByEmail.get(normalizedEmail));
  if (existing?.mfaEnabled) {
    return fail(res, 409, 'EMAIL_EXISTS', { errors: { email: 'An account with this email already exists' } });
  }
  if (existing) users.delete(existing.id); // unfinished registration: start over

  const user = {
    id: crypto.randomUUID(),
    fullName: fullName.trim(),
    email: normalizedEmail,
    countryCode,
    mobile,
    passwordHash: hashPassword(password),
    emailVerified: false,
    mobileVerified: false,
    mfaEnabled: false,
  };
  users.set(user.id, user);
  usersByEmail.set(user.email, user.id);

  const { challengeId, expiresInSec } = createChallenge({
    userId: user.id, channel: 'email', to: user.email, purpose: 'register-email',
  });

  res.status(201).json({
    ok: true,
    userId: user.id,
    challengeId,
    expiresInSec,
    email: user.email,
    mobile: maskMobile(countryCode, mobile),
  });
});

app.post('/api/send-email-otp', (req, res) => {
  const user = users.get(req.body?.userId);
  if (!user) return fail(res, 404, 'USER_NOT_FOUND');
  const { challengeId, expiresInSec } = createChallenge({
    userId: user.id, channel: 'email', to: user.email, purpose: 'register-email',
  });
  res.json({ ok: true, challengeId, expiresInSec });
});

app.post('/api/verify-email-otp', (req, res) => {
  const { challengeId, code } = req.body || {};
  const result = verifyChallenge(challengeId, code, 'register-email');
  if (!result.ok) return fail(res, 400, result.error, { attemptsLeft: result.attemptsLeft });

  const user = users.get(result.challenge.userId);
  user.emailVerified = true;
  res.json({ ok: true, userId: user.id, next: 'sms' });
});

app.post('/api/send-sms-otp', (req, res) => {
  const user = users.get(req.body?.userId);
  if (!user) return fail(res, 404, 'USER_NOT_FOUND');
  if (!user.emailVerified) return fail(res, 400, 'EMAIL_NOT_VERIFIED');
  const { challengeId, expiresInSec } = createChallenge({
    userId: user.id, channel: 'sms', to: `${user.countryCode} ${user.mobile}`, purpose: 'register-sms',
  });
  res.json({ ok: true, challengeId, expiresInSec, mobile: maskMobile(user.countryCode, user.mobile) });
});

app.post('/api/verify-sms-otp', (req, res) => {
  const { challengeId, code } = req.body || {};
  const result = verifyChallenge(challengeId, code, 'register-sms');
  if (!result.ok) return fail(res, 400, result.error, { attemptsLeft: result.attemptsLeft });

  const user = users.get(result.challenge.userId);
  user.mobileVerified = true;
  user.mfaEnabled = true;
  res.json({ ok: true, userId: user.id, next: 'success' });
});

app.post('/api/mfa-setup', (req, res) => {
  const user = users.get(req.body?.userId);
  if (!user) return fail(res, 404, 'USER_NOT_FOUND');
  if (!user.mobileVerified) return fail(res, 400, 'MOBILE_NOT_VERIFIED');
  if (!user.totpSecret) user.totpSecret = crypto.randomBytes(10);
  const secret = base32(user.totpSecret);
  const uri = `otpauth://totp/SecureID:${encodeURIComponent(user.email)}?secret=${secret}&issuer=SecureID&digits=6&period=30`;
  console.log(`\n[SIMULATED AUTHENTICATOR]\nFor: ${user.email}\nCurrent code: ${totp(user.totpSecret)} (changes every 30s)\n`);
  res.json({ ok: true, secret, uri });
});

app.post('/api/verify-mfa', (req, res) => {
  const { userId, code } = req.body || {};
  const user = users.get(userId);
  if (!user || !user.totpSecret) return fail(res, 404, 'MFA_NOT_SET_UP');
  if (!verifyTotp(user.totpSecret, code)) {
    console.log(`[SIMULATED AUTHENTICATOR] Current code: ${totp(user.totpSecret)}`);
    return fail(res, 400, 'INVALID_OTP');
  }
  user.mfaMethod = 'app';
  user.mfaEnabled = true;
  res.json({ ok: true, userId: user.id, next: 'success' });
});

const MAX_LOGIN_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000;
const PENDING_LOGIN_MS = 10 * 60 * 1000;
const SESSION_MS = 8 * 60 * 60 * 1000;
const REMEMBER_MS = 30 * 24 * 60 * 60 * 1000;
const JWT_TTL_SEC = 15 * 60;
const SESSION_COOKIE = 'sid';

app.post('/api/login', (req, res) => {
  const { email, password, rememberMe } = req.body || {};
  if (typeof email !== 'string' || typeof password !== 'string') return fail(res, 400, 'VALIDATION_ERROR');
  const key = email.trim().toLowerCase();

  const attempt = loginAttempts.get(key) || { count: 0, lockedUntil: 0 };
  if (attempt.lockedUntil > Date.now()) {
    return fail(res, 423, 'ACCOUNT_LOCKED', { retryAfterSec: Math.ceil((attempt.lockedUntil - Date.now()) / 1000) });
  }
  attempt.lockedUntil = 0; 

  const user = users.get(usersByEmail.get(key));
  if (!user || !user.mfaEnabled || !verifyPassword(password, user.passwordHash)) {
    attempt.count += 1;
    if (attempt.count >= MAX_LOGIN_FAILS) { attempt.count = 0; attempt.lockedUntil = Date.now() + LOCK_MS; }
    loginAttempts.set(key, attempt);
    return fail(res, 401, 'INVALID_CREDENTIALS');
  }
  loginAttempts.delete(key);

  const loginId = crypto.randomUUID();
  pendingLogins.set(loginId, { userId: user.id, rememberMe: rememberMe === true, mfaFails: 0, expiresAt: Date.now() + PENDING_LOGIN_MS });
  const methods = ['email', 'sms'];
  if (user.totpSecret) methods.push('app');
  res.json({
    ok: true, mfaRequired: true, loginId, methods,
    email: user.email, mobile: maskMobile(user.countryCode, user.mobile),
  });
});

function getPendingLogin(loginId) {
  const pending = pendingLogins.get(loginId);
  if (!pending || pending.expiresAt < Date.now()) { pendingLogins.delete(loginId); return null; }
  return pending;
}

app.post('/api/send-login-otp', (req, res) => {
  const { loginId, method } = req.body || {};
  const pending = getPendingLogin(loginId);
  if (!pending) return fail(res, 401, 'LOGIN_EXPIRED');
  const user = users.get(pending.userId);
  if (!['email', 'sms', 'app'].includes(method)) return fail(res, 400, 'VALIDATION_ERROR');
  if (method === 'app' && !user.totpSecret) return fail(res, 400, 'METHOD_NOT_AVAILABLE');
  pending.method = method;
  if (method === 'app') {
    console.log(`[SIMULATED AUTHENTICATOR] Current code: ${totp(user.totpSecret)}`);
    return res.json({ ok: true, method, expiresInSec: 30 - (Math.floor(Date.now() / 1000) % 30) });
  }
  const to = method === 'email' ? user.email : `${user.countryCode} ${user.mobile}`;
  const { challengeId, expiresInSec } = createChallenge({ userId: user.id, channel: method, to, purpose: 'login' });
  res.json({ ok: true, method, challengeId, expiresInSec });
});

function setSessionCookie(req, res, sessionId, maxAgeMs) {
  const secure = req.secure || req.headers['x-forwarded-proto'] === 'https';
  const parts = [`${SESSION_COOKIE}=${sessionId}`, 'Path=/', 'HttpOnly', 'SameSite=Lax'];
  if (secure) parts.push('Secure');
  if (maxAgeMs) parts.push(`Max-Age=${Math.floor(maxAgeMs / 1000)}`);
  res.setHeader('Set-Cookie', parts.join('; '));
}

app.post('/api/verify-login-otp', (req, res) => {
  const { loginId, challengeId, code } = req.body || {};
  const pending = getPendingLogin(loginId);
  if (!pending || !pending.method) return fail(res, 401, 'LOGIN_EXPIRED');
  const user = users.get(pending.userId);

  const MAX_MFA_FAILS = 5;
  const mfaFail = (error, extra) => {
    pending.mfaFails += 1;
    if (pending.mfaFails >= MAX_MFA_FAILS) { pendingLogins.delete(loginId); return fail(res, 401, 'LOGIN_EXPIRED'); }
    return fail(res, 400, error, extra);
  };
  if (pending.method === 'app') {
    if (!verifyTotp(user.totpSecret, code)) return mfaFail('INVALID_OTP');
  } else {
    const result = verifyChallenge(challengeId, code, 'login');
    if (!result.ok) return mfaFail(result.error, { attemptsLeft: result.attemptsLeft });
    if (result.challenge.userId !== user.id) return mfaFail('WRONG_CHALLENGE');
  }

  pendingLogins.delete(loginId);
  const sessionId = crypto.randomBytes(32).toString('hex');
  const ttl = pending.rememberMe ? REMEMBER_MS : SESSION_MS;
  sessions.set(sessionId, { userId: user.id, expiresAt: Date.now() + ttl });
  setSessionCookie(req, res, sessionId, pending.rememberMe ? ttl : 0);
  res.json({ ok: true, next: 'dashboard' });
});

function readCookie(req, name) {
  const match = (req.headers.cookie || '').split(';').map((c) => c.trim()).find((c) => c.startsWith(`${name}=`));
  return match ? match.slice(name.length + 1) : null;
}

function requireSession(req, res, next) {
  const sessionId = readCookie(req, SESSION_COOKIE);
  const session = sessions.get(sessionId);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(sessionId);
    return fail(res, 401, 'NOT_AUTHENTICATED');
  }
  req.session = session;
  req.sessionId = sessionId;
  req.user = users.get(session.userId);
  next();
}

const publicUser = (u) => ({
  id: u.id, fullName: u.fullName, email: u.email, mobile: maskMobile(u.countryCode, u.mobile),
  mfaEnabled: u.mfaEnabled, mfaMethod: u.mfaMethod || 'sms',
});

app.get('/api/me', requireSession, (req, res) => {
  res.json({ ok: true, user: publicUser(req.user), session: { expiresAt: req.session.expiresAt } });
});

app.post('/api/logout', (req, res) => {
  sessions.delete(readCookie(req, SESSION_COOKIE));
  setSessionCookie(req, res, '', -1000); 
  res.json({ ok: true });
});

app.post('/api/token', requireSession, (req, res) => {
  const token = signJwt({ sub: req.user.id, email: req.user.email }, JWT_TTL_SEC);
  res.json({ ok: true, token, expiresInSec: JWT_TTL_SEC });
});

app.get('/api/protected', (req, res) => {
  const [scheme, token] = (req.headers.authorization || '').split(' ');
  const payload = scheme === 'Bearer' ? verifyJwt(token) : null;
  if (!payload) return fail(res, 401, 'INVALID_TOKEN');
  res.json({ ok: true, message: `Hello ${payload.email}, this data is protected by JWT.` });
});

app.use('/api', (req, res) => fail(res, 404, 'NOT_FOUND'));

app.use((err, req, res, next) => {
  const badJson = err.type === 'entity.parse.failed';
  fail(res, badJson ? 400 : 500, badJson ? 'BAD_JSON' : 'SERVER_ERROR');
});

module.exports = app;
