const form = document.querySelector('#login-form');
const message = document.querySelector('#login-error');
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = form.querySelector('button[type=submit]');
  button.disabled = true; button.textContent = 'Signing in...'; message.textContent = '';
  try {
    const response = await fetch('/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-QCS-Request': '1' },
      body: JSON.stringify({ username: form.elements.username.value.trim(), password: form.elements.password.value }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.message || 'Unable to sign in.');
    form.elements.password.value = '';
    location.replace(payload.user.role === 'auditor' ? '/admin' : '/');
  } catch (error) { message.textContent = error.message; }
  finally { button.disabled = false; button.textContent = 'Sign in'; }
});
document.querySelector('#show-password').addEventListener('change', (event) => {
  form.elements.password.type = event.target.checked ? 'text' : 'password';
});
