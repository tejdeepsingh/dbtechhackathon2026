import { initializeSession } from './session.js';
const currentUser = await initializeSession();
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
  if (!allEntries.length) grid.textContent = 'Checking service connections...';
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
    const notice = document.createElement('article');
    notice.className = 'empty';
    notice.textContent = `Failed to load endpoint data: ${error.message}`;
    grid.replaceChildren(notice);
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

// Browsing the catalog never invokes a POST action.
const endpointMenu = document.querySelector('#endpoint-menu');
const catalogSearch = document.querySelector('#catalog-search');
const catalogCount = document.querySelector('#catalog-count');
let catalog = [];

function renderCatalog() {
  const query = catalogSearch.value.trim().toLowerCase();
  const entries = catalog.filter((entry) => [entry.name, entry.group, entry.path, entry.method, entry.url].join(' ').toLowerCase().includes(query));
  catalogCount.textContent = `${entries.length} / ${catalog.length} endpoints`;
  endpointMenu.replaceChildren();
  const groups = Map.groupBy ? Map.groupBy(entries, (entry) => entry.group) : entries.reduce((map, entry) => {
    if (!map.has(entry.group)) map.set(entry.group, []);
    map.get(entry.group).push(entry);
    return map;
  }, new Map());
  for (const [name, routes] of groups) {
    const group = document.createElement('details');
    group.className = 'endpoint-group';
    group.open = Boolean(query) || ['Workspace', 'Platform', 'Audit', 'Model controls', 'Investigations', 'Service connections'].includes(name);
    const heading = document.createElement('summary');
    heading.textContent = name;
    const count = document.createElement('span');
    count.textContent = routes.length;
    heading.append(count);
    group.append(heading);
    for (const entry of routes) {
      const direct = entry.method === 'GET' && !entry.internal && !entry.path.includes('{');
      const route = document.createElement(direct ? 'a' : 'button');
      route.className = 'endpoint-route';
      if (direct) {
        route.href = entry.url;
        if (entry.url !== '/' && entry.url !== '/admin') {
          route.target = '_blank';
          route.rel = 'noopener';
        }
      } else {
        route.type = 'button';
        route.setAttribute('aria-expanded', 'false');
      }
      const method = document.createElement('span');
      method.className = `method ${entry.method.toLowerCase()}`;
      method.textContent = entry.method;
      const title = document.createElement('span');
      title.className = 'route-name';
      title.textContent = entry.name;
      const path = document.createElement('small');
      path.textContent = entry.path;
      route.append(method, title, path);
      group.append(route);
      if (!direct) {
        const detail = document.createElement('div');
        detail.className = 'route-detail';
        detail.hidden = true;
        const address = document.createElement('code');
        address.textContent = `${entry.method} ${entry.url}`;
        const hint = document.createElement('p');
        hint.textContent = entry.group === 'Account' ? 'Use the sign-in page or the account controls in the header.' : entry.internal
          ? 'Internal service address. This route is accessed by the platform agents.'
          : entry.path.includes('{')
            ? 'Replace the file placeholder with a valid filename. Audit filenames are listed in Audit history.'
            : entry.group === 'Model controls'
              ? 'Use Configure run in the workspace to test or unload a model.'
              : 'Use the workspace to start an investigation or review and approve remediation.';
        detail.append(address, hint);
        group.append(detail);
        route.addEventListener('click', () => {
          detail.hidden = !detail.hidden;
          route.setAttribute('aria-expanded', String(!detail.hidden));
        });
      }
    }
    endpointMenu.append(group);
  }
  if (!entries.length) {
    const empty = document.createElement('p');
    empty.className = 'empty';
    empty.textContent = 'No matching endpoints. Try a tool name, route, GET, or POST.';
    endpointMenu.append(empty);
  }
}

async function loadCatalog() {
  try {
    const response = await fetch('/admin/api/endpoints?catalog=true');
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    catalog = payload.entries;
    renderCatalog();
  } catch (error) {
    endpointMenu.textContent = `Endpoint directory unavailable: ${error.message}`;
    const retry = document.createElement('button');
    retry.textContent = 'Retry directory';
    retry.addEventListener('click', loadCatalog);
    endpointMenu.append(retry);
    catalogCount.textContent = 'Unavailable';
  }
}
catalogSearch.addEventListener('input', renderCatalog);
loadCatalog();
