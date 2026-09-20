const RESEND_COOLDOWN = 25;
const TOTP_PERIOD = 30;

const OTP_UI = {
  email: { icon: '#i-mail', cls: '', title: 'Verify your email', sub: 'We have sent a 6-digit code to', help: "Didn't receive the code?", canResend: true },
  sms: { icon: '#i-phone', cls: 'green', title: 'Verify your mobile', sub: 'We have sent a 6-digit code to', help: "Didn't receive the code?", canResend: true },
  app: { icon: '#i-shield', cls: '', title: 'Enter the 6-digit code', sub: 'Enter the code from your authenticator app', help: "Can't access your app?", canResend: false },
};

const mmss = (s) => `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;

function createOtpScreen({ verify, resend, onSuccess, onShow }) {
  const $ = (sel) => document.querySelector(sel);
  const boxes = Array.from(document.querySelectorAll('#otpBoxes input'));
  let channel = 'email';
  let expiryTimer = null;
  let resendTimer = null;
  let verifying = false;

  const stop = () => { clearInterval(expiryTimer); clearInterval(resendTimer); };

  function setError(text, { boxed = false } = {}) {
    const el = $('#otpError');
    el.hidden = !text;
    el.textContent = text || '';
    el.classList.toggle('plain', !boxed);
    $('#otpBoxes').classList.toggle('error', !!text);
    $('#otpIcon').className = `icon-circle ${text ? 'red' : OTP_UI[channel].cls}`;
  }

  function setDisabled(disabled) {
    boxes.forEach((b) => { b.disabled = disabled; });
    $('#otpBoxes').classList.toggle('disabled', disabled);
  }

  function clearBoxes() {
    boxes.forEach((b) => { b.value = ''; b.classList.remove('bad'); });
    $('#otpBoxes').classList.remove('error');
    setDisabled(false);
  }

  function resendOnly() {
    stop();
    setDisabled(true);
    $('#otpExpiry').hidden = true;
    $('#resendLink').hidden = true;
    $('#resendBtn').hidden = false;
  }

  function showExpired() {
    clearBoxes();
    resendOnly();
    const wait = $('#resendWait');
    if (!wait) return setError('This code has expired.');
    setError('Code expired.');
    let cool = RESEND_COOLDOWN;
    const btn = $('#resendBtn');
    const tick = () => {
      wait.hidden = cool <= 0;
      btn.disabled = cool > 0;
      $('#resendWaitTimer').textContent = mmss(Math.max(cool, 0));
      if (cool-- <= 0) clearInterval(resendTimer);
    };
    tick();
    resendTimer = setInterval(tick, 1000);
  }
  function showMaxAttempts() { resendOnly(); setError('Maximum attempts reached. Please request a new code.', { boxed: true }); }

  function start(nextChannel, { target = '', expiresInSec, help, title, sub } = {}) {
    stop();
    const wait = $('#resendWait');
    if (wait) { wait.hidden = true; $('#resendBtn').disabled = false; }
    channel = nextChannel;
    const ui = OTP_UI[channel];

    $('#otpIcon use').setAttribute('href', ui.icon);
    $('#otpTitle').textContent = title || ui.title;
    $('#otpSub').textContent = sub || ui.sub;
    $('#otpTarget').textContent = target;
    $('#otpHelp').innerHTML = help || ui.help;

    clearBoxes();
    setError('');
    $('#resendBtn').hidden = true;
    $('#otpExpiry').hidden = false;
    $('#resendLink').hidden = !ui.canResend;

    let left = expiresInSec ?? (TOTP_PERIOD - (Math.floor(Date.now() / 1000) % TOTP_PERIOD));
    const tickExpiry = () => {
      $('#otpTimer').textContent = mmss(Math.max(left, 0));
      if (left-- > 0) return;
      if (channel === 'app') { left = TOTP_PERIOD; return; }
      clearInterval(expiryTimer);
      showExpired();
    };
    tickExpiry();
    if (left >= 0) expiryTimer = setInterval(tickExpiry, 1000);

    if (ui.canResend) {
      let cool = RESEND_COOLDOWN;
      const link = $('#resendLink');
      const tickResend = () => {
        link.disabled = cool > 0;
        link.textContent = cool > 0 ? `Resend code (${mmss(cool)})` : 'Resend code';
        if (cool-- <= 0) clearInterval(resendTimer);
      };
      tickResend();
      resendTimer = setInterval(tickResend, 1000);
    }

    onShow?.(channel);
    boxes[0].focus();
  }

  async function doResend() {
    const res = await resend(channel);
    if (!res.ok) { setError('Could not resend the code. Please try again.'); return; }
    start(channel, {
      target: $('#otpTarget').textContent, expiresInSec: res.expiresInSec, help: $('#otpHelp').innerHTML,
      title: $('#otpTitle').textContent, sub: $('#otpSub').textContent,
    });
  }
  $('#resendLink').addEventListener('click', doResend);
  $('#resendBtn').addEventListener('click', doResend);

  async function submit() {
    const code = boxes.map((b) => b.value).join('');
    if (code.length !== 6 || verifying) return;
    verifying = true;
    const res = await verify(code, channel);
    verifying = false;

    if (res.ok) { stop(); onSuccess(res, channel); return; }
    if (res.error === 'OTP_EXPIRED') return showExpired();
    if (res.error === 'MAX_ATTEMPTS') return showMaxAttempts();
    if (res.error === 'INVALID_OTP') {
      const n = res.attemptsLeft;
      setError(n === undefined
        ? 'Invalid code. Please try again.'
        : `Incorrect code. Please try again. You have ${n} attempt${n === 1 ? '' : 's'} left.`);
      boxes.at(-1).classList.add('bad');
      boxes.at(-1).focus();
      return;
    }
    if (res.error === 'NETWORK') return setError('Connection problem. Please check your network and try again.');
    if (res.error === 'LOGIN_EXPIRED') { resendOnly(); $('#resendBtn').hidden = true; return setError('Your login session expired. Please log in again.'); }
    resendOnly();
    setError('This code is no longer valid. Please request a new one.');
  }

  function resetFeedback() {
    $('#otpBoxes').classList.remove('error');
    boxes.forEach((b) => b.classList.remove('bad'));
    setError('');
  }

  boxes.forEach((box, i) => {
    box.addEventListener('focus', () => box.select());
    box.addEventListener('input', () => {
      box.value = box.value.replace(/\D/g, '').slice(-1);

      if ($('#otpBoxes').classList.contains('error')) boxes.forEach((b) => { if (b !== box) b.value = ''; });
      resetFeedback();
      if (box.value && i < boxes.length - 1) boxes[i + 1].focus();
      if (boxes.every((b) => b.value)) submit();
    });
    box.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !box.value && i > 0) boxes[i - 1].focus();
      if (e.key === 'ArrowLeft' && i > 0) { e.preventDefault(); boxes[i - 1].focus(); }
      if (e.key === 'ArrowRight' && i < boxes.length - 1) { e.preventDefault(); boxes[i + 1].focus(); }
    });
    box.addEventListener('paste', (e) => {
      e.preventDefault();
      resetFeedback();
      const digits = (e.clipboardData.getData('text') || '').replace(/\D/g, '').slice(0, 6).split('');
      boxes.forEach((b, j) => { b.value = digits[j] || ''; });
      boxes[Math.min(digits.length, 5)].focus();
      if (digits.length === 6) submit();
    });
  });

  return { start, stop, setError };
}

async function api(path, body, method = 'POST') {
  try {
    const res = await fetch(path, {
      method,
      headers: { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return await res.json();
  } catch {
    return { ok: false, error: 'NETWORK' };
  }
}
