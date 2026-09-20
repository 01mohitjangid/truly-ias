const crypto = require('crypto');
const { challenges } = require('./store');

const OTP_TTL_MS = 165 * 1000; // 2:45 as shown on the screens
const MAX_ATTEMPTS = 3;

function hashOtp(otp, challengeId) {
  return crypto.createHmac('sha256', challengeId).update(otp).digest('hex');
}


function createChallenge({ userId, channel, to, purpose }) {
  for (const old of challenges.values()) {
    if (old.userId === userId && old.purpose === purpose) challenges.delete(old.challengeId);
  }
  const challengeId = crypto.randomUUID();
  const otp = String(crypto.randomInt(0, 1000000)).padStart(6, '0');

  challenges.set(challengeId, {
    challengeId,
    userId,
    channel,
    purpose,                 
    otpHash: hashOtp(otp, challengeId),
    expiresAt: Date.now() + OTP_TTL_MS,
    attempts: 0,
  });

  console.log(`\n[SIMULATED ${channel.toUpperCase()}]\nTo: ${to}\nOTP: ${otp}\n`);
  return { challengeId, expiresInSec: OTP_TTL_MS / 1000 };
}

function verifyChallenge(challengeId, code, purpose) {
  const ch = challenges.get(challengeId);
  if (!ch) return { ok: false, error: 'CHALLENGE_NOT_FOUND' };
  if (ch.purpose !== purpose) return { ok: false, error: 'WRONG_CHALLENGE' };
  if (Date.now() > ch.expiresAt) return { ok: false, error: 'OTP_EXPIRED' };
  if (ch.attempts >= MAX_ATTEMPTS) return { ok: false, error: 'MAX_ATTEMPTS' };

  const expected = Buffer.from(ch.otpHash);
  const given = Buffer.from(hashOtp(String(code || ''), challengeId));
  if (!crypto.timingSafeEqual(expected, given)) {
    ch.attempts += 1;
    const attemptsLeft = MAX_ATTEMPTS - ch.attempts;
    return { ok: false, error: attemptsLeft === 0 ? 'MAX_ATTEMPTS' : 'INVALID_OTP', attemptsLeft };
  }

  challenges.delete(challengeId);
  return { ok: true, challenge: ch };
}

module.exports = { createChallenge, verifyChallenge };
