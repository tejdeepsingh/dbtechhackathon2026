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

function renderProgressShell() {
  return `
    <div class="live-run">
      <div class="status running">
        <strong>running</strong>
        <span>AVRC is working through the route.</span>
      </div>
      <ol class="progress-feed"></ol>
    </div>
  `;
}

function appendProgress(container, event) {
  const feed = container.querySelector('.progress-feed');
  if (!feed) return;

  const details = event.details
    ? `<details><summary>Details</summary><pre>${escapeHtml(JSON.stringify(event.details, null, 2))}</pre></details>`
    : '';
  const route = event.route ? `<p class="route">${escapeHtml(event.route.join(' -> '))}</p>` : '';

  feed.insertAdjacentHTML(
    'beforeend',
    `
      <li>
        <span class="dot ${escapeHtml(event.status ?? 'running')}"></span>
        <div>
          <strong>${escapeHtml(event.agent ?? 'agent')}</strong>
          ${event.tool ? `<em>${escapeHtml(event.tool)}.${escapeHtml(event.operation ?? 'run')}</em>` : ''}
          <p>${escapeHtml(event.message ?? event.status ?? 'Progress update')}</p>
          ${route}
          ${details}
        </div>
      </li>
    `,
  );

  messages.scrollTop = messages.scrollHeight;
}

function parseSseChunk(buffer, onEvent) {
  const events = buffer.split('\n\n');
  const remainder = events.pop() ?? '';

  for (const rawEvent of events) {
    const lines = rawEvent.split('\n');
    const eventName = lines.find((line) => line.startsWith('event:'))?.slice(6).trim() ?? 'message';
    const data = lines
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).trim())
      .join('\n');

    if (data) {
      onEvent(eventName, JSON.parse(data));
    }
  }

  return remainder;
}

async function sendPrompt() {
  const prompt = promptInput.value.trim();
  if (!prompt) return;

  addMessage('user', `<p>${escapeHtml(prompt)}</p>`);
  promptInput.value = '';
  promptInput.style.height = '';

  const pending = addMessage('assistant', renderProgressShell());
  const bubble = pending.querySelector('.bubble');
  connectionStatus.textContent = 'Running';

  try {
    const response = await fetch('/chat/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        prompt,
        environment: environmentInput.value,
        severity: severityInput.value || undefined,
        approved: approvedInput.checked,
      }),
    });

    if (!response.ok || !response.body) {
      throw new Error(`Request failed with HTTP ${response.status}`);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      buffer = parseSseChunk(buffer, (eventName, payload) => {
        if (eventName === 'final') {
          bubble.innerHTML = renderSteps(payload);
          connectionStatus.textContent = payload.status === 'success' ? 'Complete' : payload.status;
          return;
        }

        appendProgress(bubble, payload);
        connectionStatus.textContent = payload.status ?? 'Running';
      });
    }
  } catch (error) {
    bubble.innerHTML = `<p>Request failed: ${escapeHtml(error.message)}</p>`;
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
