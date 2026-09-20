const crypto = require('crypto');
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32(buf) {
  let bits = '', out = '';
  for (const b of buf) bits += b.toString(2).padStart(8, '0');
  for (let i = 0; i + 5 <= bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5), 2)];
  return out;
}

function totp(secret, step = Math.floor(Date.now() / 30000)) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac('sha1', secret).update(msg).digest();
  const offset = h[19] & 0xf;
  const code = (h.readUInt32BE(offset) & 0x7fffffff) % 1000000;
  return String(code).padStart(6, '0');
}

function verifyTotp(secret, code) {
  const now = Math.floor(Date.now() / 30000);
  return [-1, 0, 1].some((d) => totp(secret, now + d) === String(code));
}

module.exports = { base32, totp, verifyTotp };
