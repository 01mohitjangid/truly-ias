const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const state = { userId: null, challengeId: null, email: '', mobile: '' };

const STEP_OF = { form: 1, 'otp-email': 2, 'otp-sms': 3, mfa: 4, qr: 4, 'otp-app': 4, success: 5 };
const TITLE_OF = {
  form: '1. Register - Details', 'otp-email': '2. Email Verification - OTP', 'otp-sms': '3. Mobile Verification - OTP',
  mfa: '4. Set Up MFA', qr: '5. Authenticator Setup', 'otp-app': '6. MFA Verification', success: '7. Registration Success',
};
let current = 'form';

function showScreen(name) {
  current = name;
  const base = name.startsWith('otp') ? 'otp' : name;
  $$('.screen').forEach((s) => { s.hidden = s.dataset.screen !== base; });

  $('#stepTitle').textContent = TITLE_OF[name];
  const step = STEP_OF[name];
  $$('#stepper li').forEach((li) => {
    const n = Number(li.dataset.step);
    li.classList.toggle('active', n === step);
    li.classList.toggle('done', n < step);
    if (n === step) li.setAttribute('aria-current', 'step'); else li.removeAttribute('aria-current');
  });
  $('#back').hidden = !(name.startsWith('otp') || name === 'qr');
  window.scrollTo(0, 0);
}

$('#back').addEventListener('click', () => {
  otp.stop();
  showScreen(current === 'qr' || current === 'otp-app' ? 'mfa' : 'form');
});

const form = $('#registerForm');
const pwInput = $('#password');
const RULES = {
  len: (p) => p.length >= 8,
  upper: (p) => /[A-Z]/.test(p),
  num: (p) => /[0-9]/.test(p),
  special: (p) => /[^A-Za-z0-9]/.test(p),
};

pwInput.addEventListener('input', () => {
  const p = pwInput.value;
  $$('#rules li').forEach((li) => li.classList.toggle('ok', RULES[li.dataset.rule](p)));
});

$('#togglePw').addEventListener('click', () => {
  const show = pwInput.type === 'password';
  pwInput.type = show ? 'text' : 'password';
  $('#togglePw use').setAttribute('href', show ? '#i-eye-off' : '#i-eye');
  $('#togglePw').setAttribute('aria-label', show ? 'Hide password' : 'Show password');
});

function setFieldError(name, message) {
  const input = form.elements[name];
  const field = input.closest('.field') || input.closest('.check');
  field.classList.toggle('invalid', !!message);
  let hint = field.querySelector('.hint');
  if (!message) {
    hint?.remove();
    input.removeAttribute('aria-invalid');
    input.removeAttribute('aria-describedby');
    return;
  }
  if (!hint) {
    hint = document.createElement('span');
    hint.className = 'hint';
    hint.id = `${name}-error`;
    field.append(hint);
  }
  hint.textContent = message;
  input.setAttribute('aria-invalid', 'true');
  input.setAttribute('aria-describedby', hint.id);
}

function showFormError(msg) {
  $('#formError').textContent = msg;
  $('#formError').hidden = false;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const data = Object.fromEntries(new FormData(form));
  data.agreeTerms = form.elements.agreeTerms.checked;
  ['fullName', 'email', 'mobile', 'password', 'agreeTerms'].forEach((n) => setFieldError(n, ''));
  $('#formError').hidden = true;

  const btn = $('#submitBtn');
  btn.disabled = true;
  btn.textContent = 'Creating account…';
  try {
    const res = await api('/api/register', data);
    if (!res.ok) {
      const entries = Object.entries(res.errors || {});
      entries.forEach(([name, msg]) => (form.elements[name] ? setFieldError(name, msg) : showFormError(msg)));
      if (!entries.length) showFormError('Something went wrong. Please check your connection and try again.');
      return;
    }
    Object.assign(state, { userId: res.userId, challengeId: res.challengeId, email: res.email, mobile: res.mobile });
    otp.start('email', { target: state.email, expiresInSec: res.expiresInSec });
  } finally {
    btn.disabled = false;
    btn.textContent = 'Create Account';
  }
});

const VERIFY_PATH = { email: '/api/verify-email-otp', sms: '/api/verify-sms-otp' };
const RESEND_PATH = { email: '/api/send-email-otp', sms: '/api/send-sms-otp' };

const otp = createOtpScreen({
  onShow: (channel) => showScreen(`otp-${channel}`),
  verify: (code, channel) => (channel === 'app'
    ? api('/api/verify-mfa', { userId: state.userId, code })
    : api(VERIFY_PATH[channel], { challengeId: state.challengeId, code })),
  resend: async (channel) => {
    const res = await api(RESEND_PATH[channel], { userId: state.userId });
    if (res.ok) state.challengeId = res.challengeId;
    return res;
  },
  onSuccess: async (res, channel) => {
    if (channel === 'email') {
      const sms = await api('/api/send-sms-otp', { userId: state.userId });
      if (!sms.ok) { otp.setError('Could not send the SMS code. Please try again.'); return; }
      state.challengeId = sms.challengeId;
      state.mobile = sms.mobile;
      otp.start('sms', {
        target: state.mobile, expiresInSec: sms.expiresInSec,
        help: 'Wrong number? <button class="link inline" type="button" id="changeNumber">Change</button>',
      });
      $('#changeNumber').addEventListener('click', () => { otp.stop(); showScreen('form'); });
    } else if (channel === 'sms') {
      showScreen('mfa');
    } else {
      showScreen('success');
    }
  },
});

$('#mfaContinue').addEventListener('click', async () => {
  const method = $('input[name="mfa"]:checked').value;
  if (method !== 'app') return showScreen('success');

  const btn = $('#mfaContinue');
  btn.disabled = true;
  const res = await api('/api/mfa-setup', { userId: state.userId });
  btn.disabled = false;
  if (!res.ok) { $('#mfaError').hidden = false; return; }
  $('#mfaError').hidden = true;

  $('#setupKey').textContent = res.secret.match(/.{1,4}/g).join(' ');
  $('#setupKey').hidden = true;
  QRCode.toCanvas($('#qrCanvas'), res.uri, { width: 180, margin: 1 });
  showScreen('qr');
});

$('#showKey').addEventListener('click', () => { $('#setupKey').hidden = false; });
$('#qrBack').addEventListener('click', () => showScreen('mfa'));
$('#qrContinue').addEventListener('click', () => otp.start('app'));

showScreen('form');
