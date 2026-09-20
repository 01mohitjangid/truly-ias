const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const state = { loginId: null, challengeId: null, method: 'email', email: '', mobile: '', methods: [] };
let current = 'login';

function showScreen(name) {
  current = name;
  $$('.screen').forEach((s) => { s.hidden = s.dataset.screen !== name; });
  $('#back').hidden = name === 'login';
  window.scrollTo(0, 0);
}

$('#back').addEventListener('click', () => {
  otp.stop();
  showScreen(current === 'otp' ? 'method' : 'login');
});

const form = $('#loginForm');
const pwInput = $('#password');

$('#togglePw').addEventListener('click', () => {
  const show = pwInput.type === 'password';
  pwInput.type = show ? 'text' : 'password';
  $('#togglePw use').setAttribute('href', show ? '#i-eye-off' : '#i-eye');
  $('#togglePw').setAttribute('aria-label', show ? 'Hide password' : 'Show password');
});

function setLoginError(msg) {
  $('#loginError').textContent = msg || '';
  $('#loginError').hidden = !msg;
  $$('#loginForm .field').forEach((f) => f.classList.toggle('invalid', !!msg));
  $('#loginIcon').classList.toggle('red', !!msg);
  form.elements.email.setAttribute('aria-invalid', msg ? 'true' : 'false');
  form.elements.password.setAttribute('aria-invalid', msg ? 'true' : 'false');
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = form.elements.email.value.trim();
  const password = form.elements.password.value;
  if (!email || !password) return setLoginError('Please enter your email and password.');
  setLoginError('');

  const btn = $('#loginBtn');
  btn.disabled = true;
  btn.textContent = 'Logging in…';
  try {
    const res = await api('/api/login', { email, password, rememberMe: form.elements.rememberMe.checked });
    if (res.error === 'ACCOUNT_LOCKED') {
      return setLoginError(`Too many failed attempts. Try again in ${Math.ceil(res.retryAfterSec / 60)} minute(s).`);
    }
    if (res.error === 'NETWORK') return setLoginError('Connection problem. Please check your network and try again.');
    if (!res.ok) return setLoginError('Invalid email or password. Please try again.');

    Object.assign(state, { loginId: res.loginId, email: res.email, mobile: res.mobile, methods: res.methods });
    $('#appOption').hidden = !res.methods.includes('app');
    showScreen('method');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Login';
  }
});

$('#forgot').addEventListener('click', (e) => {
  e.preventDefault();
  setLoginError('Password reset is not part of this demo. Please create a new account.');
});
$('#googleBtn').addEventListener('click', () => setLoginError('Google sign-in is not part of this demo. Please use your email and password.'));

const OTP_TEXT = {
  email: { title: 'Email Verification', sub: 'Enter the 6-digit code sent to', target: () => state.email },
  sms: { title: 'SMS Verification', sub: 'Enter the 6-digit code sent to', target: () => state.mobile },
  app: { title: 'Authenticator App', sub: 'Enter the 6-digit code from your authenticator app', target: () => '' },
};

async function sendLoginOtp(method) {
  const res = await api('/api/send-login-otp', { loginId: state.loginId, method });
  if (res.ok) { state.method = method; state.challengeId = res.challengeId || null; }
  return res;
}

$('#methodContinue').addEventListener('click', async () => {
  const method = $('input[name="method"]:checked').value;
  const btn = $('#methodContinue');
  btn.disabled = true;
  const res = await sendLoginOtp(method);
  btn.disabled = false;
  if (res.error === 'LOGIN_EXPIRED') { showScreen('login'); return setLoginError('Your login expired. Please log in again.'); }
  if (!res.ok) { $('#methodError').textContent = 'Could not send the code. Please try again.'; $('#methodError').hidden = false; return; }
  $('#methodError').hidden = true;
  const t = OTP_TEXT[method];
  showScreen('otp');
  otp.start(method, { target: t.target(), expiresInSec: res.expiresInSec, title: t.title, sub: t.sub });
});

const otp = createOtpScreen({
  verify: (code) => api('/api/verify-login-otp', { loginId: state.loginId, challengeId: state.challengeId, code }),
  resend: () => sendLoginOtp(state.method),
  onSuccess: () => { window.location.href = '/dashboard.html'; },
});

showScreen('login');
