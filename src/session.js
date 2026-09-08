export async function initializeSession() {
  const originalFetch = window.fetch.bind(window);
  const response = await originalFetch('/auth/me');
  if (!response.ok) { location.replace('/login'); throw new Error('Sign-in required'); }
  const { user } = await response.json();
  document.body.dataset.role = user.role;
  const account = document.querySelector('#account-name');
  if (account) account.textContent = user.username;
  const role = document.querySelector('#account-role');
  if (role) role.textContent = user.label;
  window.fetch = async (input, options = {}) => {
    const target = new URL(typeof input === 'string' ? input : input.url, location.href);
    if (target.origin === location.origin) {
      const headers = new Headers(options.headers || (input instanceof Request ? input.headers : undefined));
      headers.set('X-QCS-Request', '1');
      options = { ...options, headers };
    }
    const result = await originalFetch(input, options);
    if (target.origin === location.origin && result.status === 401) location.replace('/login');
    return result;
  };
  document.querySelector('#sign-out')?.addEventListener('click', async () => {
    const button = document.querySelector('#sign-out');
    button.disabled = true;
    try {
      const result = await fetch('/auth/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      if (!result.ok) throw new Error('Unable to sign out. Please try again.');
      sessionStorage.clear();
      location.replace('/login');
    } catch (error) { button.disabled = false; button.textContent = 'Retry sign out'; }
  });
  if (!user.approve) {
    const approval = document.querySelector('#approved');
    if (approval) { approval.checked = false; approval.disabled = true; }
  }
  if (!user.scan) {
    document.querySelectorAll('#chat-form textarea, #chat-form button, [data-prompt]').forEach((el) => { el.disabled = true; });
    const status = document.querySelector('#connection-status');
    if (status) status.textContent = 'Read-only access';
  }
  return user;
}
