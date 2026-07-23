const form = document.querySelector('#chat-form');
const promptInput = document.querySelector('#prompt');
const environmentInput = document.querySelector('#environment');
const severityInput = document.querySelector('#severity');
const approvedInput = document.querySelector('#approved');
const messages = document.querySelector('#messages');
const connectionStatus = document.querySelector('#connection-status');

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function addMessage(role, html) {
  const article = document.createElement('article');
  article.className = `message ${role}`;
  article.innerHTML = `
    <div class="avatar">${role === 'user' ? 'U' : 'A'}</div>
    <div class="bubble">${html}</div>
  `;
  messages.append(article);
  messages.scrollTop = messages.scrollHeight;
  return article;
}

function renderSteps(payload) {
  const route = payload.route?.join(' -> ') ?? 'No route returned';
  const steps = (payload.steps ?? [])
    .map((step, index) => {
      const data = step.data
        ? `<details><summary>JSON</summary><pre>${escapeHtml(JSON.stringify(step.data, null, 2))}</pre></details>`
        : '';

      return `
        <li>
          <span class="step-index">${index + 1}</span>
          <div>
            <strong>${escapeHtml(step.agent)}</strong>
            ${step.tool ? `<em>${escapeHtml(step.tool)}</em>` : ''}
            <p>${escapeHtml(step.summary)}</p>
            ${data}
          </div>
        </li>
      `;
    })
    .join('');

  return `
    <div class="agent-result">
      <div class="status ${escapeHtml(payload.status)}">
        <strong>${escapeHtml(payload.status)}</strong>
        <span>${escapeHtml(payload.message)}</span>
      </div>
      <p class="route">${escapeHtml(route)}</p>
      <ol class="timeline">${steps}</ol>
    </div>
  `;
}

async function sendPrompt() {
  const prompt = promptInput.value.trim();
  if (!prompt) return;

  addMessage('user', `<p>${escapeHtml(prompt)}</p>`);
  promptInput.value = '';
  promptInput.style.height = '';

  const pending = addMessage('assistant', '<p class="muted">Agents are running...</p>');
  connectionStatus.textContent = 'Running';

  try {
    const response = await fetch('/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        prompt,
        environment: environmentInput.value,
        severity: severityInput.value || undefined,
        approved: approvedInput.checked,
      }),
    });

    const payload = await response.json();
    pending.querySelector('.bubble').innerHTML = renderSteps(payload);
    connectionStatus.textContent = payload.status === 'success' ? 'Complete' : payload.status;
  } catch (error) {
    pending.querySelector('.bubble').innerHTML = `<p>Request failed: ${escapeHtml(error.message)}</p>`;
    connectionStatus.textContent = 'Error';
  }

  messages.scrollTop = messages.scrollHeight;
}

form.addEventListener('submit', (event) => {
  event.preventDefault();
  sendPrompt();
});

promptInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    sendPrompt();
  }
});

promptInput.addEventListener('input', () => {
  promptInput.style.height = 'auto';
  promptInput.style.height = `${promptInput.scrollHeight}px`;
});

document.querySelectorAll('[data-prompt]').forEach((button) => {
  button.addEventListener('click', () => {
    promptInput.value = button.dataset.prompt;
    promptInput.focus();
  });
});
