const form = document.querySelector('#chat-form');
const promptInput = document.querySelector('#prompt');
const environmentInput = document.querySelector('#environment');
const severityInput = document.querySelector('#severity');
const approvedInput = document.querySelector('#approved');
const messages = document.querySelector('#messages');
const connectionStatus = document.querySelector('#connection-status');
const llmModelInput = document.querySelector('#llm-model');
const llmTimeoutInput = document.querySelector('#llm-timeout');
const llmStatus = document.querySelector('#llm-status');
const llmTestResult = document.querySelector('#llm-test-result');
const unloadAfterTestInput = document.querySelector('#llm-unload-after-test');
const refreshModelsButton = document.querySelector('#refresh-models');
const testLlmButton = document.querySelector('#test-llm');
const unloadLlmButton = document.querySelector('#unload-llm');
const sessionId = sessionStorage.getItem('avrcSessionId') || crypto.randomUUID();

sessionStorage.setItem('avrcSessionId', sessionId);

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

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return '';
  const units = ['B', 'KB', 'MB', 'GB'];
  let size = bytes;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(size >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function selectedLlmModel() {
  return llmModelInput.value || undefined;
}

function setLlmStatus(status, text) {
  llmStatus.textContent = text;
  llmStatus.className = `pill ${status}`;
}

async function loadModels() {
  setLlmStatus('running', 'checking');
  llmTestResult.textContent = 'Checking local Ollama models...';

  try {
    const response = await fetch('/llm/models');
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    const previous = llmModelInput.value || payload.configuredModel;

    llmModelInput.innerHTML = '';
    for (const model of payload.models) {
      const option = document.createElement('option');
      option.value = model.name;
      option.textContent = `${model.name}${model.loaded ? ' - loaded' : ''}${model.size ? ` (${formatBytes(model.size)})` : ''}`;
      llmModelInput.append(option);
    }

    if (!payload.models.length) {
      const option = document.createElement('option');
      option.value = payload.configuredModel;
      option.textContent = `${payload.configuredModel} - not found locally`;
      llmModelInput.append(option);
    }

    llmModelInput.value = [...llmModelInput.options].some((option) => option.value === previous)
      ? previous
      : payload.models[0]?.name ?? payload.configuredModel;

    setLlmStatus('success', 'ready');
    llmTestResult.textContent = `Connected to ${payload.baseUrl}. Idle unload setting: ${payload.keepAlive}.`;
  } catch (error) {
    setLlmStatus('error', 'offline');
    llmTestResult.textContent = `Ollama check failed: ${error.message}`;
  }
}

async function testLlm() {
  setLlmStatus('running', 'testing');
  llmTestResult.textContent = `Testing ${selectedLlmModel() ?? 'configured model'}...`;

  try {
    const response = await fetch('/llm/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: selectedLlmModel(),
        timeoutMs: Number(llmTimeoutInput.value),
        unloadAfter: unloadAfterTestInput.checked,
      }),
    });
    const payload = await response.json();
    if (!response.ok || payload.status !== 'ok') {
      throw new Error(payload.message ?? `HTTP ${response.status}`);
    }

    setLlmStatus('success', 'working');
    llmTestResult.textContent = `${payload.model} replied in ${payload.latencyMs}ms: ${payload.response}`;
  } catch (error) {
    setLlmStatus('error', 'failed');
    llmTestResult.textContent = `LLM test failed or timed out: ${error.message}`;
  }
}

async function unloadLlm() {
  setLlmStatus('running', 'unloading');
  llmTestResult.textContent = `Unloading ${selectedLlmModel() ?? 'configured model'}...`;

  try {
    const response = await fetch('/llm/unload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: selectedLlmModel() }),
    });
    const payload = await response.json();
    if (!response.ok || payload.status !== 'ok') {
      throw new Error(payload.message ?? `HTTP ${response.status}`);
    }

    setLlmStatus('success', 'unloaded');
    llmTestResult.textContent = payload.message;
  } catch (error) {
    setLlmStatus('error', 'failed');
    llmTestResult.textContent = `Unload failed: ${error.message}`;
  }
}

function friendlyStatusLabel(status) {
  const labels = {
    success: 'Complete',
    running: 'Working',
    accepted: 'Started',
    needs_info: 'Need details',
    needs_approval: 'Approval needed',
    blocked: 'Blocked',
    error: 'Error',
    'mock-fallback': 'Using fallback',
    'local-fallback': 'Saved locally',
    needs_configuration: 'Needs setup',
  };

  return labels[status] ?? status ?? 'Update';
}

function isMockedStatus(status) {
  return ['mock-fallback', 'local-fallback', 'needs_configuration'].includes(status);
}

function valueHasMockSource(value) {
  if (!value || typeof value !== 'object') return false;
  if (isMockedStatus(value.status) || isMockedStatus(value.source)) return true;
  return Object.values(value).some((item) => valueHasMockSource(item));
}

function isMockedEvent(event) {
  return isMockedStatus(event.status) || valueHasMockSource(event.details);
}

function isMockedResult(payload) {
  return (
    isMockedStatus(payload.status) ||
    (payload.steps ?? []).some((step) => isMockedStatus(step.status) || valueHasMockSource(step.data))
  );
}

function displayMessage(message, mocked) {
  return mocked ? `- ${message}` : message;
}

function friendlyMessageForEvent(event) {
  const tool = event.tool ?? '';
  const agent = event.agent ?? '';
  const status = event.status ?? '';

  if (event.type === 'clarification' || status === 'needs_info') {
    return event.message ?? 'I need a little more information before I start.';
  }
  if (status === 'needs_approval') {
    return 'This looks like a high-risk production change, so I need approval before continuing.';
  }
  if (status === 'blocked') {
    return 'I stopped this request because it triggered a safety policy.';
  }
  if (agent === 'chat_intake_agent' && status === 'running') {
    return 'Checking the application name and scan targets.';
  }
  if (agent === 'chat_intake_agent' && status === 'success') {
    return event.message ?? 'I have enough information now and I am starting the scan.';
  }
  if (agent === 'main_agent' && event.type === 'route') {
    return 'I selected the right scan path for this request.';
  }
  if (agent === 'main_agent' && status === 'running') {
    return 'Checking request safety and preparing the scan.';
  }
  if (agent === 'cve_intelligence_agent' && event.message?.toLowerCase().includes('deduplicated')) {
    return event.message.replace('scanner output', 'results');
  }
  if (tool.includes('trivy') || tool.includes('semgrep') || tool.includes('renovate')) {
    return status === 'running' ? 'Scanning the repository for vulnerable code and dependencies.' : 'Repository scan step finished.';
  }
  if (tool.includes('container') || tool.includes('copacetic')) {
    return status === 'running' ? 'Checking the container image for known vulnerabilities.' : 'Container image check finished.';
  }
  if (tool.includes('kubescape')) {
    return status === 'running' ? 'Checking deployed workload and Kubernetes posture.' : 'Kubernetes workload check finished.';
  }
  if (tool.includes('wazuh') || tool.includes('greenbone')) {
    return status === 'running' ? 'Checking on-prem and network exposure data.' : 'On-prem/network check finished.';
  }
  if (tool.includes('zap')) {
    return status === 'running' ? 'Running runtime web application checks.' : 'Runtime application check finished.';
  }
  if (tool.includes('cve_lookup')) {
    return status === 'running' ? 'Looking up CVE details and remediation guidance.' : 'CVE guidance lookup finished.';
  }
  if (tool.includes('remediation_decision')) {
    return status === 'running' ? 'Choosing the safest remediation strategy.' : 'Remediation strategy selected.';
  }
  if (tool.includes('git_ops')) {
    return status === 'running' ? 'Preparing the branch, commit, and pull request.' : 'Pull request payload is ready.';
  }
  if (tool.includes('verification')) {
    return status === 'running' ? 'Verifying that the proposed fix addresses the finding.' : 'Verification step finished.';
  }
  if (tool.includes('notification')) {
    return status === 'running' ? 'Preparing the notification and summary report.' : 'Notification and reporting step finished.';
  }
  if (tool.includes('audit')) {
    return status === 'running' ? 'Writing the audit trail.' : 'Audit trail updated.';
  }

  return event.message ?? 'Working on the request.';
}

function summarizeResult(payload) {
  if (payload.status === 'needs_info') {
    return displayMessage(payload.message, isMockedResult(payload));
  }
  if (payload.status === 'needs_approval') {
    return 'I paused before making changes because this requires approval.';
  }
  if (payload.status === 'blocked') {
    return payload.message ?? 'The request was blocked by policy.';
  }
  if (payload.status === 'error') {
    return payload.message ?? 'Something failed while processing the request.';
  }

  const dedupeStep = (payload.steps ?? []).find((step) => step.tool === 'dedupe_engine');
  const osvStep = (payload.steps ?? []).find((step) => step.tool === 'osv_lookup_tool');
  const prStep = (payload.steps ?? []).find((step) => step.tool === 'git_ops_tool');
  const uniqueCount = dedupeStep?.data?.summary?.uniqueCveCount;
  const duplicateCount = dedupeStep?.data?.summary?.duplicateCount;
  const advisories = osvStep?.data?.findings ?? osvStep?.data?.data?.findings ?? [];
  const advisoryNames = advisories
    .map((finding) => finding.cve ?? finding.id)
    .filter(Boolean)
    .slice(0, 3);
  const prStatus = prStep?.data?.status ?? prStep?.status;

  const parts = ['Scan completed.'];
  if (Number.isFinite(uniqueCount)) {
    parts.push(`I found ${uniqueCount} unique CVE record${uniqueCount === 1 ? '' : 's'}`);
    if (Number.isFinite(duplicateCount)) {
      parts.push(`after removing ${duplicateCount} duplicate${duplicateCount === 1 ? '' : 's'}`);
    }
    parts[parts.length - 1] += '.';
  }
  if (advisories.length) {
    parts.push(`OSV enriched ${advisories.length} advisory record${advisories.length === 1 ? '' : 's'}${advisoryNames.length ? ` including ${advisoryNames.join(', ')}` : ''}.`);
  }
  if (prStep) {
    parts.push(prStatus === 'needs_configuration'
      ? 'A pull request payload was generated, but Forgejo token/repo configuration is still needed before it can be opened.'
      : 'A pull request was prepared for the repo fix.');
  }

  return displayMessage(parts.join(' '), isMockedResult(payload));
}

function renderTechnicalDetails(payload) {
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
    <details class="technical-details">
      <summary>Technical details</summary>
      <p class="route">${escapeHtml(route)}</p>
      <ol class="timeline">${steps}</ol>
    </details>
  `;
}

function renderResult(payload) {
  return `
    <div class="agent-result">
      <div class="status ${escapeHtml(payload.status)}">
        <strong>${escapeHtml(friendlyStatusLabel(payload.status))}</strong>
      </div>
      <p>${escapeHtml(summarizeResult(payload))}</p>
      ${renderTechnicalDetails(payload)}
    </div>
  `;
}

function renderProgressShell() {
  return `
    <div class="live-run">
      <div class="status running">
        <strong>running</strong>
        <span>Working on your request...</span>
      </div>
      <ol class="progress-feed"></ol>
    </div>
  `;
}

function appendProgress(container, event) {
  const feed = container.querySelector('.progress-feed');
  if (!feed) return;

  const details = event.details
    ? `<details class="technical-details"><summary>Details</summary><pre>${escapeHtml(JSON.stringify(event.details, null, 2))}</pre></details>`
    : '';
  const route = event.route ? `<p class="route">${escapeHtml(event.route.join(' -> '))}</p>` : '';
  const message = displayMessage(friendlyMessageForEvent(event), isMockedEvent(event));

  feed.insertAdjacentHTML(
    'beforeend',
    `
      <li>
        <span class="dot ${escapeHtml(event.status ?? 'running')}"></span>
        <div>
          <p>${escapeHtml(message)}</p>
          <details class="technical-details inline-details">
            <summary>What happened</summary>
            <p>${escapeHtml(event.agent ?? 'agent')}${event.tool ? ` / ${event.tool}.${event.operation ?? 'run'}` : ''}</p>
            ${route}
          </details>
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
        sessionId,
        prompt,
        llmModel: selectedLlmModel(),
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
          bubble.innerHTML = renderResult(payload);
          connectionStatus.textContent = payload.status === 'success' ? 'Complete' : payload.status;
          // Dispatch to dashboard
          document.dispatchEvent(new CustomEvent('avrc:scan-complete', { detail: payload }));
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

refreshModelsButton.addEventListener('click', loadModels);
testLlmButton.addEventListener('click', testLlm);
unloadLlmButton.addEventListener('click', unloadLlm);

loadModels();

/* ---- Dashboard & HITL Logic ---- */
const dashboardBanner = document.querySelector('#dashboard-banner');
const dashboardReport = document.querySelector('#dashboard-report');
const hitlApprove = document.querySelector('#hitl-approve');
const hitlReject = document.querySelector('#hitl-reject');
const hitlRescan = document.querySelector('#hitl-rescan');

let lastScanPayload = null;
let lastScanContext = null;

function showDashboard(payload) {
  lastScanPayload = payload;
  dashboardBanner.classList.add('hidden');
  dashboardReport.classList.remove('hidden');

  const ctx = payload.context ?? {};
  lastScanContext = ctx;
  const app = ctx.inventoryApp ?? {};

  document.querySelector('#report-app-name').textContent = ctx.applicationName ?? app.app_name ?? 'Application';
  document.querySelector('#report-app-id').textContent = ctx.applicationId ?? '—';
  document.querySelector('#report-env').textContent = app.environment ?? ctx.environment ?? 'unknown';
  document.querySelector('#report-timestamp').textContent = new Date().toLocaleString();

  // Count vulnerabilities from steps
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  const allFindings = [];

  for (const step of (payload.steps ?? [])) {
    const data = step.data?.data ?? step.data ?? {};
    const findings = data.findings ?? data.vulnerabilities ?? data.alerts ?? data.results ?? [];
    if (Array.isArray(findings)) {
      for (const f of findings) {
        const sev = (f.severity ?? f.risk ?? '').toLowerCase();
        if (counts[sev] !== undefined) counts[sev]++;
        allFindings.push(f);
      }
    }
    // Summary objects from some tools
    if (data.summary && typeof data.summary === 'object') {
      for (const [k, v] of Object.entries(data.summary)) {
        if (counts[k] !== undefined && typeof v === 'number') counts[k] += v;
      }
    }
  }

  document.querySelector('#vuln-critical').textContent = counts.critical;
  document.querySelector('#vuln-high').textContent = counts.high;
  document.querySelector('#vuln-medium').textContent = counts.medium;
  document.querySelector('#vuln-low').textContent = counts.low;

  // Scan summary
  const route = payload.route ?? [];
  const steps = payload.steps ?? [];
  const tools = [...new Set(steps.map(s => s.tool).filter(Boolean))];
  const dedupeStep = steps.find(s => s.tool === 'dedupe_engine');
  const uniqueCves = dedupeStep?.data?.summary?.uniqueCveCount ?? allFindings.length;
  const dupes = dedupeStep?.data?.summary?.duplicateCount ?? 0;

  document.querySelector('#rpt-agents').textContent = route.length;
  document.querySelector('#rpt-tools').textContent = tools.length;
  document.querySelector('#rpt-unique-cves').textContent = uniqueCves;
  document.querySelector('#rpt-dupes').textContent = dupes;
  document.querySelector('#rpt-scopes').textContent = (ctx.scanScopes ?? []).join(', ') || '—';

  // Top findings
  const findingsList = document.querySelector('#report-findings');
  findingsList.innerHTML = '';
  const top = allFindings.slice(0, 8);
  if (top.length === 0) {
    findingsList.innerHTML = '<li style="color:#718096">No individual findings extracted</li>';
  }
  for (const f of top) {
    const sev = (f.severity ?? f.risk ?? 'medium').toLowerCase();
    const name = f.cve ?? f.id ?? f.name ?? f.package ?? '—';
    const pkg = f.package ?? f.component ?? '';
    const li = document.createElement('li');
    li.innerHTML = `<span class="sev-badge ${escapeHtml(sev)}">${escapeHtml(sev)}</span> <strong>${escapeHtml(name)}</strong> ${pkg ? `<span style="color:#718096">${escapeHtml(pkg)}</span>` : ''}`;
    findingsList.appendChild(li);
  }

  // HITL messaging
  const hitlMsg = document.querySelector('#hitl-message');
  const totalVuln = counts.critical + counts.high + counts.medium + counts.low;
  if (counts.critical > 0 || (ctx.environment === 'production' && counts.high > 0)) {
    hitlMsg.textContent = `⚠️ ${counts.critical} critical and ${counts.high} high severity findings detected${ctx.environment === 'production' ? ' in PRODUCTION' : ''}. Manual approval required before automated remediation proceeds.`;
  } else if (totalVuln > 0) {
    hitlMsg.textContent = `${totalVuln} vulnerabilities found. Review the findings above and approve to auto-create remediation PRs on Forgejo.`;
  } else {
    hitlMsg.textContent = 'Scan complete with no critical findings. You may still approve a follow-up remediation pass.';
  }
}

function hideDashboard() {
  dashboardBanner.classList.remove('hidden');
  dashboardReport.classList.add('hidden');
}

// Hook into the existing sendPrompt flow — intercept final results
const originalSendPrompt = sendPrompt;
// We'll use a MutationObserver approach instead — patch the rendering

// Override renderResult to also populate dashboard
const _origRenderResult = renderResult;
window._avrcLastPayload = null;

// Monkey-patch: intercept SSE final events. We listen for custom events on document.
document.addEventListener('avrc:scan-complete', (e) => {
  const payload = e.detail;
  if (payload.status === 'success' && payload.steps?.length > 0) {
    showDashboard(payload);
  }
});

// HITL button handlers
hitlApprove.addEventListener('click', async () => {
  hitlApprove.disabled = true;
  hitlApprove.textContent = '⏳ Remediating...';
  hitlReject.disabled = true;
  hitlRescan.disabled = true;

  // Collect findings from the last scan payload
  const findings = [];
  for (const step of (lastScanPayload?.steps ?? [])) {
    const data = step.data?.data ?? step.data ?? {};
    const items = data.findings ?? data.vulnerabilities ?? data.alerts ?? data.results ?? [];
    if (Array.isArray(items)) {
      for (const f of items) findings.push(f);
    }
  }

  // Show remediation progress in chat
  const pending = addMessage('assistant', renderProgressShell());
  const bubble = pending.querySelector('.bubble');
  const statusDiv = bubble.querySelector('.status strong');
  if (statusDiv) statusDiv.textContent = 'remediating';

  try {
    const response = await fetch('/chat/remediate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sessionId,
        context: lastScanContext,
        findings,
        scanSteps: lastScanPayload?.steps ?? [],
        llmModel: selectedLlmModel(),
      }),
    });

    if (!response.ok || !response.body) {
      throw new Error(`Remediation request failed with HTTP ${response.status}`);
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
          bubble.innerHTML = renderRemediationResult(payload);
          connectionStatus.textContent = 'Remediation Complete';
          // Update dashboard with PR info
          updateDashboardAfterRemediation(payload);
          return;
        }
        appendProgress(bubble, payload);
      });
    }
  } catch (error) {
    bubble.innerHTML = `<p>Remediation failed: ${escapeHtml(error.message)}</p>`;
    connectionStatus.textContent = 'Error';
  }

  hitlApprove.disabled = false;
  hitlApprove.textContent = '✓ Approve & Remediate';
  hitlReject.disabled = false;
  hitlRescan.disabled = false;
});

function renderRemediationResult(payload) {
  const pr = payload.pr ?? {};
  const fix = payload.fix ?? {};
  const prLink = pr.url ? `<a href="${escapeHtml(pr.url)}" target="_blank" rel="noopener">PR #${pr.number ?? '?'}</a>` : 'PR prepared';

  return `
    <div class="agent-result">
      <div class="status ${escapeHtml(payload.status ?? 'success')}">
        <strong>${payload.status === 'success' ? 'Remediation Complete' : escapeHtml(payload.status ?? 'Done')}</strong>
      </div>
      <p>${escapeHtml(payload.message ?? 'Remediation flow completed.')}</p>
      <div class="remediation-summary">
        <table class="report-table">
          <tbody>
            <tr><td>Pull Request</td><td>${prLink} — ${escapeHtml(pr.title ?? '')}</td></tr>
            <tr><td>Branch</td><td><code>${escapeHtml(pr.branch ?? '—')}</code></td></tr>
            <tr><td>Files Changed</td><td>${fix.filesChanged ?? 0}</td></tr>
            <tr><td>Fix Summary</td><td>${escapeHtml(fix.summary ?? '—')}</td></tr>
          </tbody>
        </table>
        ${fix.verificationCommands?.length ? `
          <details class="technical-details">
            <summary>Verification Commands</summary>
            <ul>${fix.verificationCommands.map(c => `<li><code>${escapeHtml(c)}</code></li>`).join('')}</ul>
          </details>` : ''}
        ${fix.riskNotes?.length ? `
          <details class="technical-details">
            <summary>Risk Notes</summary>
            <ul>${fix.riskNotes.map(n => `<li>${escapeHtml(n)}</li>`).join('')}</ul>
          </details>` : ''}
      </div>
    </div>
  `;
}

function updateDashboardAfterRemediation(payload) {
  const hitlPanel = document.querySelector('#hitl-panel');
  if (!hitlPanel) return;

  const pr = payload.pr ?? {};
  const status = payload.status === 'success' ? 'approved' : 'failed';

  hitlPanel.style.borderColor = status === 'approved' ? '#16a34a' : '#dc2626';
  hitlPanel.style.background = status === 'approved'
    ? 'linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%)'
    : 'linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%)';

  const header = hitlPanel.querySelector('.hitl-header');
  if (header) {
    header.innerHTML = `
      <span class="hitl-icon">${status === 'approved' ? '✅' : '❌'}</span>
      <div>
        <strong>${status === 'approved' ? 'Remediation Approved & Executed' : 'Remediation Failed'}</strong>
        <p>${escapeHtml(payload.message ?? '')}</p>
        ${pr.url ? `<p><a href="${escapeHtml(pr.url)}" target="_blank" rel="noopener">View Pull Request #${pr.number ?? '?'} on Forgejo →</a></p>` : ''}
      </div>
    `;
  }

  const actions = hitlPanel.querySelector('.hitl-actions');
  if (actions) {
    actions.innerHTML = `<button class="hitl-btn rescan" type="button" id="hitl-rescan-after">↻ Scan Again</button>`;
    actions.querySelector('#hitl-rescan-after')?.addEventListener('click', () => {
      if (lastScanContext?.applicationId) {
        promptInput.value = `Scan ${lastScanContext.applicationId}`;
        sendPrompt();
      }
    });
  }
}

hitlReject.addEventListener('click', () => {
  const msg = addMessage('assistant', '<div class="bubble"><p>Remediation rejected. No changes will be applied. You can re-scan or provide a different application.</p></div>');
  hideDashboard();
});

hitlRescan.addEventListener('click', () => {
  if (lastScanContext?.applicationId) {
    promptInput.value = `Scan ${lastScanContext.applicationId}`;
    sendPrompt();
  }
});
