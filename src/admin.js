const grid = document.querySelector('#endpoint-grid');
const searchInput = document.querySelector('#search');
const groupFilter = document.querySelector('#group-filter');
const refreshButton = document.querySelector('#refresh-all');

const statTotal = document.querySelector('#stat-total');
const statUp = document.querySelector('#stat-up');
const statWarn = document.querySelector('#stat-warn');
const statDown = document.querySelector('#stat-down');

const cardTemplate = document.querySelector('#endpoint-card-template');

let allEntries = [];

function safeJson(value) {
  if (value === undefined) return 'undefined';
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function stateClass(entry) {
  if (entry.ok) return 'healthy';
  if (entry.statusCode && entry.statusCode < 500) return 'degraded';
  return 'failed';
}

function updateStats(entries) {
  const healthy = entries.filter((entry) => entry.ok).length;
  const degraded = entries.filter((entry) => !entry.ok && entry.statusCode && entry.statusCode < 500).length;
  const failed = entries.filter((entry) => !entry.ok && (!entry.statusCode || entry.statusCode >= 500)).length;

  statTotal.textContent = entries.length;
  statUp.textContent = healthy;
  statWarn.textContent = degraded;
  statDown.textContent = failed;
}

function render(entries) {
  grid.innerHTML = '';
  updateStats(entries);

  if (!entries.length) {
    const empty = document.createElement('article');
    empty.className = 'empty';
    empty.textContent = 'No endpoints match your filter.';
    grid.append(empty);
    return;
  }

  for (const entry of entries) {
    const fragment = cardTemplate.content.cloneNode(true);
    const card = fragment.querySelector('.endpoint-card');
    const state = fragment.querySelector('.state');
    const name = fragment.querySelector('.name');
    const meta = fragment.querySelector('.meta');
    const url = fragment.querySelector('.url');
    const latency = fragment.querySelector('.latency');
    const code = fragment.querySelector('.status-code');
    const pre = fragment.querySelector('pre');

    const stateName = stateClass(entry);
    card.dataset.group = entry.group || 'services';

    state.className = `state ${stateName}`;
    state.textContent = stateName === 'healthy' ? 'Healthy' : (stateName === 'degraded' ? 'Degraded' : 'Failed');

    name.textContent = entry.name;
    meta.textContent = `${entry.groupLabel} · ${entry.path}`;
    url.textContent = entry.publicUrl;
    url.href = entry.publicUrl;
    latency.textContent = `${entry.latencyMs ?? '--'} ms`;
    code.textContent = `HTTP ${entry.statusCode ?? '--'}`;
    pre.textContent = safeJson(entry.preview ?? entry.error ?? { message: 'No response payload' });

    grid.append(fragment);
  }
}

function applyFilters() {
  const query = searchInput.value.trim().toLowerCase();
  const group = groupFilter.value;

  const filtered = allEntries.filter((entry) => {
    const inGroup = group === 'all' || entry.group === group;
    if (!inGroup) return false;

    if (!query) return true;
    const haystack = [entry.name, entry.path, entry.groupLabel, entry.publicUrl].join(' ').toLowerCase();
    return haystack.includes(query);
  });

  render(filtered);
}

async function loadEndpoints() {
  refreshButton.disabled = true;
  refreshButton.textContent = 'Refreshing...';

  try {
    const response = await fetch('/admin/api/endpoints?includeData=true');
    const payload = await response.json();
    if (!response.ok || payload.status !== 'ok') {
      throw new Error(payload.message || `HTTP ${response.status}`);
    }

    allEntries = payload.entries || [];
    applyFilters();
  } catch (error) {
    grid.innerHTML = `<article class="empty">Failed to load endpoint data: ${error.message}</article>`;
    statTotal.textContent = '0';
    statUp.textContent = '0';
    statWarn.textContent = '0';
    statDown.textContent = '0';
  } finally {
    refreshButton.disabled = false;
    refreshButton.textContent = 'Refresh All';
  }
}

searchInput.addEventListener('input', applyFilters);
groupFilter.addEventListener('change', applyFilters);
refreshButton.addEventListener('click', loadEndpoints);

loadEndpoints();
