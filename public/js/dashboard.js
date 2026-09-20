const $ = (sel) => document.querySelector(sel);

async function loadMe() {
  const res = await api('/api/me', undefined, 'GET');
  if (!res.ok) { window.location.replace('/login.html'); return; }
  const { user, session } = res;
  $('[data-k="fullName"]').textContent = user.fullName;
  $('[data-k="email"]').textContent = user.email;
  $('[data-k="mobile"]').textContent = user.mobile;
  $('[data-k="mfa"]').textContent = user.mfaEnabled ? `Enabled (${user.mfaMethod})` : 'Disabled';
  $('[data-k="expires"]').textContent = new Date(session.expiresAt).toLocaleString();
}

$('#logoutBtn').addEventListener('click', async () => {
  await api('/api/logout');
  window.location.replace('/login.html');
});

loadMe();
