import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, extname, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { MainAgent } from './agents/main_agent.mjs';

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const config = JSON.parse(await readFile(resolve(rootDir, 'config', 'config.json'), 'utf-8'));
const mainAgent = new MainAgent({ config, rootDir });
const sessions = new Map();

// ---------------------------------------------------------------------------
// Application Inventory
// ---------------------------------------------------------------------------

function parseCsvLine(line) {
  const values = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') {
      if (inQuotes && line[i + 1] === '"') { current += '"'; i++; }
      else inQuotes = !inQuotes;
    } else if (c === ',' && !inQuotes) {
      values.push(current); current = '';
    } else {
      current += c;
    }
  }
  values.push(current);
  return values;
}

async function loadInventory() {
  const inventoryCandidates = [
    resolve(rootDir, 'data', 'fake-applications.csv'),
    resolve(rootDir, 'data', 'app-inventory.csv'),
  ];

  function parsePipelineProvider(rawValue) {
    if (!rawValue) return '';
    try {
      const parsed = JSON.parse(rawValue);
      return parsed.provider ?? '';
    } catch {
      return '';
    }
  }

  function normalizeInventoryRow(row) {
    return {
      app_id: row.app_id ?? row.appId ?? '',
      app_name: row.app_name ?? row.appName ?? '',
      environment: row.environment ?? '',
      criticality: row.criticality ?? row.severity ?? '',
      runtime: row.runtime ?? '',
      deployment_type: row.deployment_type ?? '',
      cloud_provider: row.cloud_provider ?? '',
      pipeline: row.pipeline ?? parsePipelineProvider(row.ciCdPipeline ?? ''),
      repo_url: row.repo_url ?? row.repo ?? '',
      container_image: row.container_image ?? row.image ?? '',
      ingress_url: row.ingress_url ?? '',
      deployed_host: row.deployed_host ?? '',
      deployed_namespace: row.deployed_namespace ?? '',
      branch: row.branch ?? 'main',
      installed_path: row.installed_path ?? row.installedPath ?? '',
      vulnerabilities: row.vulnerabilities ?? '',
      raw: row,
    };
  }

  try {
    for (const candidate of inventoryCandidates) {
      try {
        const raw = await readFile(candidate, 'utf-8');
        const lines = raw.split(/\r?\n/).filter(Boolean);
        if (lines.length < 2) continue;
        const headers = parseCsvLine(lines[0]);
        const rows = lines.slice(1).map((line) => {
          const values = parseCsvLine(line);
          const parsed = Object.fromEntries(headers.map((h, i) => [h.trim(), (values[i] ?? '').trim()]));
          return normalizeInventoryRow(parsed);
        });
        if (rows.length) {
          return { rows, source: candidate };
        }
      } catch {
        // Try the next candidate file.
      }
    }

    return { rows: [], source: null };
  } catch {
    console.warn('[inventory] Could not load inventory CSV — inventory lookup disabled.');
    return { rows: [], source: null };
  }
}

const inventoryState = await loadInventory();
const inventory = inventoryState.rows;
const inventorySource = inventoryState.source ? inventoryState.source.replace(/.*[\\/](data[\\/].*)$/, '$1') : 'none';
console.log(`[inventory] Loaded ${inventory.length} application(s) from ${inventorySource}`);

function normalizeName(s) {
  return String(s ?? '').toLowerCase().replace(/[-_\s.]/g, '');
}

function normalizeAppId(value) {
  const text = String(value ?? '').trim();
  const match = text.match(/\bapp-(\d{4,})\b/i);
  if (!match) return null;
  return `APP-${match[1]}`;
}

function findInventoryByAppId(appId) {
  const normalized = normalizeAppId(appId);
  if (!normalized) return null;
  return inventory.find((row) => normalizeAppId(row.app_id) === normalized) ?? null;
}

function matchInventoryApp(name, envHint) {
  if (!name) return null;
  const norm = normalizeName(name);
  // Exact app_id match
  let match = inventory.find((a) => normalizeName(a.app_id) === norm);
  if (match) return envHint ? (inventory.find((a) => normalizeName(a.app_id) === norm && a.environment === envHint) ?? match) : match;
  // Exact app_name match
  match = inventory.find((a) => normalizeName(a.app_name) === norm);
  if (match) return envHint ? (inventory.find((a) => normalizeName(a.app_name) === norm && a.environment === envHint) ?? match) : match;
  // Partial: inventory name contains query or vice-versa
  const candidates = inventory.filter(
    (a) => normalizeName(a.app_name).includes(norm) || norm.includes(normalizeName(a.app_name)),
  );
  if (!candidates.length) return null;
  // Prefer production hit when env not specified
  const preferred = candidates.find((a) => a.environment === (envHint ?? 'production')) ?? candidates[0];
  return preferred;
}

/**
 * Derive scan scopes and concrete targets from an inventory record.
 * Returns a partial session-context patch.
 */
function inventoryContextPatch(app) {
  if (!app) return null;
  const dt = app.deployment_type ?? '';
  const runtime = app.runtime ?? '';
  const scopes = new Set();

  // Repo is relevant whenever there is a repo URL
  if (app.repo_url) scopes.add('repo');

  // Container image present and not a bare-metal/serverless stub
  const hasImage = app.container_image && !app.container_image.startsWith('N/A');
  if (hasImage) scopes.add('image');

  // Infer scope hints from vulnerability source types in fake-applications.csv
  try {
    const vulnList = JSON.parse(app.vulnerabilities || '[]');
    if (Array.isArray(vulnList)) {
      for (const finding of vulnList) {
        const findingType = String(finding?.type ?? '').toLowerCase();
        if (findingType === 'repo') scopes.add('repo');
        if (findingType === 'image' || findingType === 'build_container') scopes.add('image');
        // Only add runtime scope from vulnerability types if we have a concrete URL
        if (findingType === 'runtime' && app.ingress_url && !app.ingress_url.startsWith('N/A')) scopes.add('runtime');
        if (findingType === 'path') scopes.add('on_prem');
      }
    }
  } catch {
    // Ignore malformed vulnerability JSON and continue with structural inference.
  }

  // Kubernetes / orchestrated container platforms
  if (
    dt.startsWith('kubernetes') ||
    dt.includes('openshift') ||
    dt.includes('tanzu') ||
    dt === 'aws-ecs-fargate' ||
    dt === 'azure-container-apps' ||
    dt === 'digitalocean-app-platform' ||
    dt === 'aws-outposts' ||
    dt === 'azure-arc-hybrid'
  ) {
    scopes.add('deployed_workload');
  }

  // On-prem / bare-metal / edge / VM
  if (
    dt === 'bare-metal' ||
    dt === 'vm-onprem' ||
    dt === 'vm-onprem-windows' ||
    dt === 'vm-vmware-vsphere' ||
    dt === 'mainframe-zos' ||
    dt === 'edge-iot' ||
    dt === 'nomad-onprem' ||
    dt === 'docker-compose-onprem' ||
    dt === 'aws-outposts' ||
    dt === 'azure-arc-hybrid'
  ) {
    scopes.add('on_prem');
  }

  // fake-applications.csv often carries host-like install paths
  if (app.installed_path && /^(\/srv|\/opt|\/dr|[A-Za-z]:[\\/])/i.test(app.installed_path)) {
    scopes.add('on_prem');
  }

  // Docker-compose (VM or on-prem) — image scope too
  if (dt.startsWith('docker-compose')) scopes.add('image');

  // Live runtime URL exists (skip static / batch / mainframe)
  const noRuntime = new Set(['static-s3-cloudfront', 'static-netlify', 'static-vercel', 'mainframe-zos', 'nomad-onprem']);
  if (
    app.ingress_url &&
    !app.ingress_url.startsWith('N/A') &&
    !noRuntime.has(dt)
  ) {
    scopes.add('runtime');
  }

  // Only infer runtime scope if we actually have a concrete URL — otherwise the user
  // would be asked to provide one, which is confusing when it's not known in inventory.

  // Concrete targets
  const repo = app.repo_url || null;
  const image = hasImage ? app.container_image : null;
  const runtimeUrl = (app.ingress_url && !app.ingress_url.startsWith('N/A') && !noRuntime.has(dt)) ? app.ingress_url : null;
  const namespace = app.deployed_namespace && app.deployed_namespace !== '""' ? app.deployed_namespace : null;
  const workloadTarget =
    scopes.has('deployed_workload') && app.deployed_host
      ? [app.deployed_host, namespace].filter(Boolean).join('/')
      : null;
  const onPremTargets =
    scopes.has('on_prem')
      ? [app.deployed_host || app.installed_path].filter(Boolean)
      : [];

  return {
    scanScopes: [...scopes],
    repo,
    image,
    runtimeUrl,
    workloadTarget,
    onPremTargets,
    baseBranch: app.branch || null,
    inventoryApp: app,
  };
}

const contentTypes = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
]);

const toolNames = config.tools.map((tool) => tool.name);

function json(res, statusCode, payload) {
  res.writeHead(statusCode, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function sse(res, event, payload) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
}

function getSession(sessionId) {
  const id = sessionId || randomUUID();
  if (!sessions.has(id)) {
    sessions.set(id, {
      id,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      messages: [],
      pendingMissing: [],
      context: {
        applicationId: null,
        applicationName: null,
        scanScopes: [],
        repo: null,
        image: null,
        runtimeUrl: null,
        workloadTarget: null,
        onPremTargets: [],
        baseBranch: null,
        target: null,
        confidence: {},
        lastInterpretation: null,
        invalidApplicationId: null,
        inventoryApp: null,       // populated when app matched in app-inventory.csv
      },
    });
  }

  return sessions.get(id);
}

function extractContextFromText(text) {
  const lower = text.toLowerCase();
  const scopes = new Set();

  const explicitAppMatch =
    text.match(/\b(?:application|app|service|project)\s+(?:name\s+is\s+|is\s+|called\s+|named\s+)["']?([a-zA-Z0-9_.:/-]{2,})["']?/i) ??
    text.match(/\b(?:application|app|service|project)\s*[:=]\s*["']?([a-zA-Z0-9_.:/-]{2,})["']?/i);
  const appIdMatch = text.match(/\bAPP-\d{4,}\b/i);
  const repoUrlMatch = text.match(/\b(?:https?:\/\/|git@)[^\s'"]+/i);
  const runtimeUrlMatch = text.match(/\bhttps?:\/\/[^\s'"]+/i);
  const imageMatch = text.match(/\b(?:image|container|docker)\s+(?:is\s+|name\s+is\s+)?["']?([a-z0-9][a-z0-9._/-]*(?::[a-zA-Z0-9._-]+)?)(?:["']|\s|$)/i);
  const branchMatch = text.match(/\b(?:branch|base branch)\s+(?:is\s+)?["']?([a-zA-Z0-9._/-]+)["']?/i);

  // Try matching known inventory app names directly in user text
  let inventoryNameMatch = null;
  if (!appIdMatch && !explicitAppMatch) {
    const matched = inventory.find((a) => a.app_name && lower.includes(a.app_name.toLowerCase()));
    if (matched) inventoryNameMatch = matched;
  }

  if (lower.includes('repo') || lower.includes('source') || lower.includes('dependency') || lower.includes('dependencies')) {
    scopes.add('repo');
  }
  if (lower.includes('image') || lower.includes('container') || lower.includes('docker')) {
    scopes.add('image');
  }
  if (lower.includes('kubernetes') || lower.includes('k8s') || lower.includes('cluster') || lower.includes('deployed')) {
    scopes.add('deployed_workload');
  }
  if (lower.includes('runtime') || lower.includes('dast') || lower.includes('endpoint') || lower.includes('zap')) {
    scopes.add('runtime');
  }
  if (lower.includes('on prem') || lower.includes('on-prem') || lower.includes('host') || lower.includes('vm')) {
    scopes.add('on_prem');
  }
  if (lower.includes('hybrid') || lower.includes('all') || lower.includes('everything')) {
    scopes.add('repo');
    scopes.add('image');
    scopes.add('deployed_workload');
    scopes.add('runtime');
    scopes.add('on_prem');
  }

  return {
    applicationId: normalizeAppId(appIdMatch?.[0] ?? explicitAppMatch?.[1] ?? inventoryNameMatch?.app_id ?? null),
    applicationName: cleanApplicationName(inventoryNameMatch?.app_name ?? explicitAppMatch?.[1] ?? appFromRepoUrl(repoUrlMatch?.[0]) ?? null),
    scanScopes: [...scopes],
    repo: repoUrlMatch?.[0] ?? null,
    image: imageMatch?.[1] ?? null,
    runtimeUrl: runtimeUrlMatch?.[0] && !repoUrlMatch?.[0]?.endsWith('.git') ? runtimeUrlMatch[0] : null,
    baseBranch: branchMatch?.[1] ?? null,
  };
}

function cleanApplicationName(value) {
  if (!value) return null;
  const cleaned = String(value).trim().replace(/[.,;:!?]+$/, '');
  const blocked = new Set([
    'repo',
    'repository',
    'source',
    'dependency',
    'dependencies',
    'image',
    'container',
    'docker',
    'runtime',
    'endpoint',
    'scan',
    'all',
    'hybrid',
  ]);
  return blocked.has(cleaned.toLowerCase()) ? null : cleaned;
}

function appFromRepoUrl(value) {
  if (!value) return null;
  try {
    const url = value.startsWith('git@')
      ? new URL(`ssh://${value.replace(':', '/')}`)
      : new URL(value);
    const parts = url.pathname.replace(/^\//, '').replace(/\.git$/, '').split('/').filter(Boolean);
    return parts.at(-1) ?? null;
  } catch {
    return null;
  }
}

function standaloneApplicationName(text) {
  const trimmed = cleanApplicationName(text);
  if (!trimmed) return null;
  if (trimmed.length > 80) return null;
  if (/\s/.test(trimmed) && !/^[a-zA-Z0-9_.:/-]+\s*$/i.test(trimmed)) return null;
  if (/^(yes|no|ok|okay|sure|scan|start|run)$/i.test(trimmed)) return null;
  return trimmed;
}

function followUpApplicationName(text) {
  const repoUrlMatch = text.match(/\b(?:https?:\/\/|git@)[^\s'"]+/i);
  const fromRepo = appFromRepoUrl(repoUrlMatch?.[0]);
  if (fromRepo) return fromRepo;

  const forMatch = text.match(/\bfor\s+["']?([a-zA-Z0-9_.:/-]{2,})["']?/i);
  if (forMatch?.[1]) return cleanApplicationName(forMatch[1]);

  const reduced = text
    .replace(/\b(repo|repository|source|dependency|dependencies|image|container|docker|kubernetes|k8s|cluster|deployed|runtime|dast|endpoint|on[- ]prem|hosts?|hybrid|all|scan|run|check|fix|cves?|vulnerabilities)\b/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  return standaloneApplicationName(reduced);
}

function parseJsonObject(content) {
  const trimmed = String(content ?? '').trim();
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const jsonText = fenced?.[1]?.trim() ?? trimmed;
  return JSON.parse(jsonText);
}

async function interpretUserContextWithLlm(session, request) {
  const recentMessages = session.messages.slice(-10).map((message) => ({
    role: message.role,
    content: message.content,
  }));

  // Build inventory hint — either the already-matched app or top candidates by name
  const appHint = session.context.inventoryApp ?? null;
  const candidateApps = appHint
    ? null
    : (() => {
        const text = (request.prompt ?? '').toLowerCase();
        return inventory
          .filter((a) => text.includes(normalizeName(a.app_name)) || text.includes(a.app_id.toLowerCase()))
          .slice(0, 5)
          .map((a) => ({
            app_id: a.app_id,
            app_name: a.app_name,
            environment: a.environment,
            deployment_type: a.deployment_type,
            runtime: a.runtime,
            repo_url: a.repo_url,
            container_image: a.container_image,
            deployed_host: a.deployed_host,
            cloud_provider: a.cloud_provider,
            pipeline: a.pipeline,
          }));
      })();

  const systemContent = [
    'You are Advanced Vanguard for Rapid Containment (AVRC) chat intake. Interpret the latest user reply against the full session context.',
    'Return only strict JSON. Do not ask a question here.',
    'Application identity must be deterministic: prefer APP-ID in the form APP-####.',
    'Extract fields when present or clearly implied. Preserve unknown fields as null or empty arrays.',
    'Valid scanScopes: repo, image, deployed_workload, runtime, on_prem.',
    'Minimum data: repo needs repo URL/path; image needs image reference; runtime needs URL; deployed_workload needs cluster/workload/namespace; on_prem needs host/IP list.',
    appHint
      ? `The application "${appHint.app_name}" (${appHint.app_id}) has already been matched in the inventory: deployment_type=${appHint.deployment_type}, runtime=${appHint.runtime}, cloud=${appHint.cloud_provider}, pipeline=${appHint.pipeline}. Use this to infer any scan scopes or targets not yet provided by the user.`
      : candidateApps?.length
        ? `Inventory candidates that may match the user message: ${JSON.stringify(candidateApps)}. If one matches, use its fields to enrich the context.`
        : 'No inventory match found yet; rely solely on what the user says.',
  ].join(' ');

  const content = await callOllama([
    { role: 'system', content: systemContent },
    {
      role: 'user',
      content: JSON.stringify(
        {
          currentContext: session.context,
          pendingMissing: session.pendingMissing ?? [],
          recentMessages,
          latestUserMessage: request.prompt,
          inventoryApp: appHint,
          responseShape: {
            applicationId: 'APP-####|null',
            applicationName: 'string|null',
            scanScopes: ['repo|image|deployed_workload|runtime|on_prem'],
            repo: 'repo url, local repo path, or owner/repo|null',
            image: 'container image reference|null',
            runtimeUrl: 'http url|null',
            workloadTarget: 'cluster/workload/namespace details|null',
            onPremTargets: ['host or ip'],
            baseBranch: 'string|null',
            target: 'best concrete scan target|null',
            confidence: {
              applicationId: '0-1',
              applicationName: '0-1',
              scanScopes: '0-1',
              targetData: '0-1',
            },
            meaning: 'short explanation of what the user meant',
          },
        },
        null,
        2,
      ),
    },
  ], { model: request.llmModel, timeoutMs: 15000 });

  return parseJsonObject(content);
}

function validScopes(scopes) {
  const allowed = new Set(['repo', 'image', 'deployed_workload', 'runtime', 'on_prem']);
  return Array.isArray(scopes) ? scopes.filter((scope) => allowed.has(scope)) : [];
}

function firstNonEmpty(...values) {
  return values.find((value) => typeof value === 'string' && value.trim())?.trim() ?? null;
}

function mergeArrayValues(existing = [], incoming = []) {
  return [...new Set([...(existing ?? []), ...(Array.isArray(incoming) ? incoming : []).filter(Boolean)])];
}

function applyContextPatch(session, patch) {
  if (!patch || typeof patch !== 'object') return;

  const appId = normalizeAppId(patch.applicationId);
  if (appId) {
    session.context.applicationId = appId;
    session.context.invalidApplicationId = null;
  }

  const appName = cleanApplicationName(patch.applicationName);
  if (appName) session.context.applicationName = appName;

  session.context.scanScopes = mergeArrayValues(session.context.scanScopes, validScopes(patch.scanScopes));

  session.context.repo = firstNonEmpty(patch.repo, session.context.repo);
  session.context.image = firstNonEmpty(patch.image, session.context.image);
  session.context.runtimeUrl = firstNonEmpty(patch.runtimeUrl, session.context.runtimeUrl);
  session.context.workloadTarget = firstNonEmpty(patch.workloadTarget, session.context.workloadTarget);
  session.context.baseBranch = firstNonEmpty(patch.baseBranch, session.context.baseBranch);
  session.context.target = firstNonEmpty(patch.target, session.context.target);
  session.context.onPremTargets = mergeArrayValues(session.context.onPremTargets, patch.onPremTargets);

  if (patch.inventoryApp && !session.context.inventoryApp) {
    session.context.inventoryApp = patch.inventoryApp;
  }

  if (patch.confidence && typeof patch.confidence === 'object') {
    session.context.confidence = {
      ...(session.context.confidence ?? {}),
      ...patch.confidence,
    };
  }
  if (patch.meaning) {
    session.context.lastInterpretation = patch.meaning;
  }
}

/**
 * If an app was just resolved (by name or LLM), look it up in the inventory
 * and backfill any context fields not yet set from user input.
 */
function applyInventoryEnrichment(session) {
  const appId = normalizeAppId(session.context.applicationId);

  // If no APP-ID yet but we have a name, try matching by name in inventory
  if (!appId && session.context.applicationName) {
    const matched = matchInventoryApp(session.context.applicationName, session.context.environment);
    if (matched) {
      session.context.applicationId = matched.app_id;
      // Re-enter with the resolved app_id
      return applyInventoryEnrichment(session);
    }
    return;
  }

  if (!appId) return;

  const app = findInventoryByAppId(appId);
  if (!app) {
    session.context.invalidApplicationId = appId;
    session.context.inventoryApp = null;
    return;
  }

  session.context.invalidApplicationId = null;
  const patch = inventoryContextPatch(app);
  if (!patch) return;

  // Deterministic mode: once APP-ID is known, operational context is sourced from inventory.
  session.context.inventoryApp = app;
  session.context.applicationName = app.app_name;
  session.context.scanScopes = validScopes(patch.scanScopes);
  session.context.repo = patch.repo;
  session.context.image = patch.image;
  session.context.runtimeUrl = patch.runtimeUrl;
  session.context.workloadTarget = patch.workloadTarget;
  session.context.baseBranch = patch.baseBranch;
  session.context.onPremTargets = patch.onPremTargets;
}

async function mergeSessionContext(session, request) {
  const extracted = extractContextFromText(request.prompt ?? '');
  const selectedScopes = Array.isArray(request.scanScopes) ? request.scanScopes.filter(Boolean) : [];
  const previousMissing = new Set(session.pendingMissing ?? []);
  const deterministicPatch = {
    ...extracted,
    scanScopes: [...new Set([...extracted.scanScopes, ...selectedScopes])],
  };
  const llmPatch = await interpretUserContextWithLlm(session, request).catch((error) => ({
    meaning: `LLM interpretation failed: ${error instanceof Error ? error.message : 'unknown error'}`,
  }));

  if (request.applicationId) {
    session.context.applicationId = normalizeAppId(request.applicationId);
  } else if (request.applicationName && normalizeAppId(request.applicationName)) {
    session.context.applicationId = normalizeAppId(request.applicationName);
  } else if (extracted.applicationId) {
    session.context.applicationId = extracted.applicationId;
  }

  if (request.applicationName && !session.context.applicationName) {
    session.context.applicationName = cleanApplicationName(request.applicationName);
  } else if (extracted.applicationName) {
    session.context.applicationName = extracted.applicationName;
  } else if (!session.context.applicationName && previousMissing.has('applicationName')) {
    session.context.applicationName = followUpApplicationName(request.prompt);
  } else if (!session.context.applicationName && !extracted.scanScopes.length && !selectedScopes.length) {
    session.context.applicationName = standaloneApplicationName(request.prompt);
  }

  applyContextPatch(session, deterministicPatch);
  applyContextPatch(session, llmPatch);

  // Inventory enrichment: runs after name is resolved by either path above
  applyInventoryEnrichment(session);

  session.updatedAt = new Date().toISOString();
}

function missingContext(session) {
  const missing = [];
  if (!session.context.applicationId) {
    missing.push('applicationId');
    return missing;
  }
  if (session.context.invalidApplicationId) {
    missing.push('invalidApplicationId');
    return missing;
  }
  if (!session.context.inventoryApp) {
    missing.push('applicationId');
    return missing;
  }

  if (!session.context.scanScopes?.length) missing.push('scanScopes');

  const scopes = new Set(session.context.scanScopes ?? []);
  // For each scope, only ask if the target wasn't already filled by inventory
  if (scopes.has('repo') && !session.context.repo) missing.push('repo');
  if (scopes.has('image') && !session.context.image) missing.push('image');
  if (scopes.has('runtime') && !session.context.runtimeUrl) missing.push('runtimeUrl');
  if (scopes.has('deployed_workload') && !session.context.workloadTarget) missing.push('workloadTarget');
  if (scopes.has('on_prem') && !session.context.onPremTargets?.length) missing.push('onPremTargets');

  return missing;
}

function fallbackClarification(session, missing) {
  if (missing.includes('invalidApplicationId')) {
    return `I couldn't find "${session.context.invalidApplicationId}" in our application inventory. Could you double-check the APP-ID? Valid IDs look like APP-00001 through APP-01000. You can also try an application name like "payments-service".`;
  }
  if (missing.includes('applicationId')) {
    return 'Which application would you like me to scan? Please provide an APP-ID (e.g. APP-00042) or an application name. I\'ll automatically pull the repo, image, runtime, and deployment details from inventory.';
  }
  if (missing.includes('scanScopes')) return 'I found the application but couldn\'t determine what to scan. The inventory entry may be incomplete. Could you tell me what you\'d like scanned — repository code, container image, runtime endpoint, or deployed workload?';
  return 'I have most of the details. Could you clarify the remaining scan target?';
}

function rememberMissingContext(session) {
  const missing = missingContext(session);
  session.pendingMissing = missing;
  session.updatedAt = new Date().toISOString();
  return missing;
}

function clearPendingContext(session) {
  session.pendingMissing = [];
  session.updatedAt = new Date().toISOString();
}

function llmBaseUrlCandidates() {
  const configured = config.llm?.baseUrl ?? 'http://localhost:11434';
  const candidates = [configured];

  if (configured.includes('host.docker.internal')) {
    candidates.push(configured.replace('host.docker.internal', 'localhost'));
  }
  if (configured.includes('localhost')) {
    candidates.push(configured.replace('localhost', 'host.docker.internal'));
  }

  return [...new Set(candidates)];
}

function selectedModel(model) {
  return model || config.llm?.model || 'qwen2.5-coder:7b';
}

function llmKeepAlive(override) {
  return override ?? config.llm?.keepAlive ?? '30s';
}

async function fetchOllama(path, { method = 'GET', body: requestBody, timeoutMs } = {}) {
  let lastError = null;

  for (const baseUrl of llmBaseUrlCandidates()) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs ?? config.llm?.timeoutMs ?? 30000);

    try {
      const response = await fetch(`${baseUrl}${path}`, {
        method,
        headers: { 'content-type': 'application/json' },
        body: requestBody ? JSON.stringify(requestBody) : undefined,
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`Ollama HTTP ${response.status}`);
      }

      const text = await response.text();
      const data = text ? JSON.parse(text) : {};
      return { baseUrl, data };
    } catch (error) {
      lastError = error;
    } finally {
      clearTimeout(timeout);
    }
  }

  throw lastError ?? new Error('Ollama call failed');
}

async function callOllama(messages, { model, timeoutMs, keepAlive } = {}) {
  const payload = {
    model: selectedModel(model),
    stream: false,
    keep_alive: llmKeepAlive(keepAlive),
    options: {
      temperature: config.llm?.temperature ?? 0.2,
      num_ctx: config.llm?.contextLength ?? 32768,
    },
    messages,
  };

  const { data } = await fetchOllama(config.llm?.chatEndpoint ?? '/api/chat', {
    method: 'POST',
    body: payload,
    timeoutMs,
  });

  return data.message?.content?.trim() ?? '';
}

async function listOllamaModels() {
  const [{ baseUrl, data: tags }, psResult] = await Promise.all([
    fetchOllama('/api/tags', { timeoutMs: 10000 }),
    fetchOllama('/api/ps', { timeoutMs: 10000 }).catch(() => null),
  ]);
  const loadedModels = new Set((psResult?.data?.models ?? []).map((model) => model.name || model.model));
  const models = (tags.models ?? []).map((model) => ({
    name: model.name || model.model,
    size: model.size,
    modifiedAt: model.modified_at,
    details: model.details,
    loaded: loadedModels.has(model.name || model.model),
  }));

  return {
    status: 'ok',
    provider: config.llm?.provider ?? 'ollama',
    baseUrl,
    configuredModel: selectedModel(),
    keepAlive: llmKeepAlive(),
    timeoutMs: config.llm?.timeoutMs ?? 30000,
    models,
  };
}

async function unloadOllamaModel(model) {
  const { baseUrl, data } = await fetchOllama(config.llm?.chatEndpoint ?? '/api/chat', {
    method: 'POST',
    body: {
      model: selectedModel(model),
      messages: [],
      stream: false,
      keep_alive: 0,
    },
    timeoutMs: 10000,
  });

  return {
    status: 'ok',
    provider: config.llm?.provider ?? 'ollama',
    baseUrl,
    model: selectedModel(model),
    doneReason: data.done_reason,
    message: data.done_reason === 'unload' ? 'Model unloaded from Ollama memory.' : 'Unload request sent.',
  };
}

async function testOllamaModel({ model, prompt, timeoutMs, unloadAfter } = {}) {
  const started = Date.now();
  const testPrompt = prompt || config.llm?.testPrompt || 'Reply with exactly: AVRC_LLM_OK';
  const content = await callOllama(
    [
      {
        role: 'system',
        content: 'You are a health-check endpoint. Reply briefly and do not call tools.',
      },
      {
        role: 'user',
        content: testPrompt,
      },
    ],
    {
      model,
      timeoutMs: Number(timeoutMs) || config.llm?.timeoutMs || 30000,
      keepAlive: unloadAfter ? 0 : llmKeepAlive(),
    },
  );

  const result = {
    status: 'ok',
    provider: config.llm?.provider ?? 'ollama',
    model: selectedModel(model),
    timeoutMs: Number(timeoutMs) || config.llm?.timeoutMs || 30000,
    keepAlive: unloadAfter ? 0 : llmKeepAlive(),
    latencyMs: Date.now() - started,
    response: content,
  };

  if (unloadAfter) {
    result.unload = await unloadOllamaModel(model).catch((error) => ({
      status: 'error',
      message: error instanceof Error ? error.message : 'Unload failed',
    }));
  }

  return result;
}

async function buildClarification(session, missing, model) {
  const fallback = fallbackClarification(session, missing);

  try {
    const recentMessages = session.messages.slice(-8).map((message) => `${message.role}: ${message.content}`).join('\n');
    const invApp = session.context.inventoryApp;
    const inventoryNote = invApp
      ? `The application "${invApp.app_name}" (${invApp.app_id}) was matched in the inventory: ` +
        `deployment_type=${invApp.deployment_type}, runtime=${invApp.runtime}, cloud=${invApp.cloud_provider}, ` +
        `pipeline=${invApp.pipeline}, criticality=${invApp.criticality}, data_classification=${invApp.data_classification}. ` +
        `Use this context when asking about missing fields — for example, mention known deployment specifics.`
      : `No inventory match yet. If applicationName is missing, offer to list known applications or ask the user to name one.`;

    const question = await callOllama([
      {
        role: 'system',
        content:
          'You are AVRC (Advanced Vanguard for Rapid Containment) intake. Ask one concise question to collect only the missing scan context. Use the known context and do not repeat already collected information. Valid scan scopes: repo, image, deployed workload, runtime endpoint, on-prem hosts, all hybrid targets. Do not start scanning. ' +
          inventoryNote,
      },
      {
        role: 'user',
        content: `Known context: ${JSON.stringify(session.context)}\nMissing: ${missing.join(', ')}\nRecent chat:\n${recentMessages}\nAsk the next question.`,
      },
    ], { model });

    return question || fallback;
  } catch {
    return fallback;
  }
}

function scopePrompt(scopes) {
  const words = {
    repo: 'repo/source/dependency',
    image: 'container image',
    deployed_workload: 'deployed workload/Kubernetes',
    runtime: 'runtime/DAST endpoint',
    on_prem: 'on-prem hosts',
  };

  return scopes.map((scope) => words[scope] ?? scope).join(', ');
}

function concreteTargetForContext(context) {
  const scopes = context.scanScopes ?? [];
  if (scopes.includes('repo') && context.repo) return context.repo;
  if (scopes.includes('image') && context.image) return context.image;
  if (scopes.includes('runtime') && context.runtimeUrl) return context.runtimeUrl;
  if (scopes.includes('deployed_workload') && context.workloadTarget) return context.workloadTarget;
  if (scopes.includes('on_prem') && context.onPremTargets?.length) return context.onPremTargets.join(',');
  return context.target;
}

function enrichRequestFromContext(request, session) {
  const target = concreteTargetForContext(session.context);
  return {
    ...request,
    sessionId: session.id,
    applicationId: session.context.applicationId,
    applicationName: session.context.inventoryApp?.app_name ?? session.context.applicationName,
    scanScopes: session.context.scanScopes,
    repo: session.context.repo,
    repository: session.context.repo,
    image: session.context.image,
    runtimeUrl: session.context.runtimeUrl,
    workloadTarget: session.context.workloadTarget,
    onPremTargets: session.context.onPremTargets,
    baseBranch: session.context.baseBranch ?? request.baseBranch,
    target: target ?? request.target,
    llmModel: request.llmModel,
    prompt: `${request.prompt}\nApp ID: ${session.context.applicationId ?? 'not provided'}\nApplication: ${session.context.inventoryApp?.app_name ?? session.context.applicationName}\nDeployment: ${session.context.inventoryApp?.deployment_type ?? 'unknown'}\nCI/CD: ${session.context.inventoryApp?.pipeline ?? 'unknown'}\nScan scopes: ${scopePrompt(session.context.scanScopes)}\nTarget: ${target ?? 'not specified'}`,
  };
}

async function body(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks).toString('utf-8');
  return raw ? JSON.parse(raw) : {};
}

async function staticFile(res, filePath) {
  const content = await readFile(filePath);
  res.writeHead(200, {
    'content-type': contentTypes.get(extname(filePath)) ?? 'application/octet-stream',
  });
  res.end(content);
}

async function handle(req, res) {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);

  if (req.method === 'GET' && url.pathname === '/') {
    await staticFile(res, resolve(rootDir, 'src', 'index.html'));
    return;
  }

  if (req.method === 'GET' && url.pathname.startsWith('/static/')) {
    await staticFile(res, resolve(rootDir, 'src', url.pathname.replace('/static/', '')));
    return;
  }

  if (req.method === 'GET' && url.pathname === '/health') {
    json(res, 200, { status: 'ok', app: config.app.name });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/agents') {
    json(res, 200, { agents: config.agents });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/tools') {
    json(res, 200, { tools: toolNames });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/llm/models') {
    json(res, 200, await listOllamaModels());
    return;
  }

  if (req.method === 'POST' && url.pathname === '/llm/test') {
    json(res, 200, await testOllamaModel(await body(req)));
    return;
  }

  if (req.method === 'POST' && url.pathname === '/llm/unload') {
    const request = await body(req);
    json(res, 200, await unloadOllamaModel(request.model));
    return;
  }

  if (req.method === 'POST' && url.pathname === '/chat') {
    const request = await body(req);
    if (!request.prompt) {
      json(res, 400, { status: 'error', message: 'prompt is required' });
      return;
    }
    const session = getSession(request.sessionId);
    session.messages.push({ role: 'user', content: request.prompt, timestamp: new Date().toISOString() });
    await mergeSessionContext(session, request);

    const missing = rememberMissingContext(session);
    if (missing.length) {
      const question = await buildClarification(session, missing, request.llmModel);
      session.messages.push({ role: 'assistant', content: question, timestamp: new Date().toISOString() });
      json(res, 200, {
        status: 'needs_info',
        sessionId: session.id,
        context: session.context,
        missing,
        questions: [question],
        route: ['chat_intake_agent'],
        steps: [],
        message: question,
      });
      return;
    }

    clearPendingContext(session);
    const enrichedRequest = enrichRequestFromContext(request, session);
    const result = await mainAgent.handle(enrichedRequest);
    session.messages.push({ role: 'assistant', content: result.message, result, timestamp: new Date().toISOString() });
    json(res, 200, { ...result, sessionId: session.id, context: session.context });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/chat/stream') {
    const request = await body(req);
    if (!request.prompt) {
      json(res, 400, { status: 'error', message: 'prompt is required' });
      return;
    }

    res.writeHead(200, {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    });

    sse(res, 'progress', {
      type: 'progress',
      agent: 'server',
      status: 'accepted',
      message: 'Streaming AVRC agent progress (Advanced Vanguard for Rapid Containment).',
      timestamp: new Date().toISOString(),
    });

    const session = getSession(request.sessionId);
    session.messages.push({ role: 'user', content: request.prompt, timestamp: new Date().toISOString() });
    await mergeSessionContext(session, request);

    sse(res, 'progress', {
      type: 'progress',
      agent: 'chat_intake_agent',
      status: 'running',
      message: 'Interpreting your reply with the current chat context.',
      timestamp: new Date().toISOString(),
      details: { sessionId: session.id, context: session.context },
    });

    const missing = rememberMissingContext(session);
    if (missing.length) {
      const question = await buildClarification(session, missing, request.llmModel);
      const result = {
        status: 'needs_info',
        sessionId: session.id,
        context: session.context,
        missing,
        questions: [question],
        route: ['chat_intake_agent'],
        steps: [
          {
            agent: 'chat_intake_agent',
            status: 'needs_info',
            summary: question,
            data: { missing, context: session.context },
          },
        ],
        message: question,
      };
      session.messages.push({ role: 'assistant', content: question, timestamp: new Date().toISOString() });
      sse(res, 'clarification', {
        type: 'clarification',
        agent: 'chat_intake_agent',
        status: 'needs_info',
        message: question,
        timestamp: new Date().toISOString(),
        details: { missing, context: session.context },
      });
      sse(res, 'final', result);
      res.end();
      return;
    }

    clearPendingContext(session);
    const enrichedRequest = enrichRequestFromContext(request, session);

    sse(res, 'progress', {
      type: 'progress',
      agent: 'chat_intake_agent',
      status: 'success',
      message: `Context ready for ${session.context.applicationName}; starting AVRC scan for ${scopePrompt(session.context.scanScopes)}.`,
      timestamp: new Date().toISOString(),
      details: { sessionId: session.id, context: session.context },
    });

    const result = await mainAgent.handle(enrichedRequest, {
      onProgress: (event) => sse(res, event.type ?? 'progress', event),
    });

    session.messages.push({ role: 'assistant', content: result.message, result, timestamp: new Date().toISOString() });
    sse(res, 'final', { ...result, sessionId: session.id, context: session.context });
    res.end();
    return;
  }

  // ---- HITL Remediation Endpoint ----
  if (req.method === 'POST' && url.pathname === '/chat/remediate') {
    const request = await body(req);
    const sessionId = request.sessionId ?? randomUUID();
    const session = getSession(sessionId);

    res.writeHead(200, {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    });

    const emit = (event) => sse(res, event.type ?? 'progress', event);

    // Build context from request or session
    const ctx = request.context ?? session.context ?? {};
    const appName = ctx.applicationName ?? ctx.inventoryApp?.app_name ?? 'application';
    const appId = ctx.applicationId ?? '';
    const repo = ctx.repo ?? ctx.inventoryApp?.repo_url ?? null;
    const baseBranch = ctx.baseBranch ?? 'main';
    const findings = request.findings ?? [];
    const scanSteps = request.scanSteps ?? [];

    emit({
      type: 'progress',
      agent: 'remediation_agent',
      status: 'running',
      message: `Starting LLM-based remediation for ${appName} (${appId}).`,
      timestamp: new Date().toISOString(),
    });

    // Step 1: Prepare CVE data from findings
    const cveData = {
      uniqueCves: findings.filter((f) => f.cve || f.id).map((f) => ({
        cve: f.cve ?? f.id ?? 'unknown',
        severity: f.severity ?? f.risk ?? 'medium',
        package: f.package ?? f.component ?? '',
        fixedVersion: f.fixedVersion ?? f.to ?? '',
        path: f.path ?? '',
      })),
      summary: {
        uniqueCveCount: findings.filter((f) => f.cve || f.id).length,
        critical: findings.filter((f) => (f.severity ?? '').toLowerCase() === 'critical').length,
        high: findings.filter((f) => (f.severity ?? '').toLowerCase() === 'high').length,
        medium: findings.filter((f) => (f.severity ?? '').toLowerCase() === 'medium').length,
        low: findings.filter((f) => (f.severity ?? '').toLowerCase() === 'low').length,
      },
    };

    emit({
      type: 'progress',
      agent: 'remediation_agent',
      status: 'running',
      message: `Identified ${cveData.uniqueCves.length} CVEs to remediate. Calling LLM to generate fix plan.`,
      timestamp: new Date().toISOString(),
    });

    // Step 2: Generate LLM-based fix
    const remediationRequest = {
      applicationName: appName,
      applicationId: appId,
      repo,
      baseBranch,
      llmModel: request.llmModel,
      scanScopes: ctx.scanScopes ?? ['repo'],
    };

    const routePlan = {
      kind: 'repo',
      scanSteps: [{ tool: 'trivy_scan_tool' }, { tool: 'semgrep_scan_tool' }],
    };

    const remediationData = {
      strategy: 'immediate-patch',
      actions: cveData.uniqueCves.slice(0, 5).map((cve) => ({
        action: 'upgrade',
        package: cve.package,
        targetVersion: cve.fixedVersion,
        cve: cve.cve,
      })),
    };

    let fix;
    try {
      fix = await mainAgent.generateRepoFixWithLlm(remediationRequest, cveData, remediationData, emit);
    } catch (err) {
      fix = { status: 'success', data: mainAgent.fallbackRepoFix(remediationRequest, cveData, remediationData) };
    }

    emit({
      type: 'progress',
      agent: 'remediation_agent',
      status: 'success',
      message: `LLM generated fix plan: "${fix.data?.title ?? 'Remediation fix'}" with ${fix.data?.filesToChange?.length ?? 0} file changes.`,
      timestamp: new Date().toISOString(),
      details: {
        title: fix.data?.title,
        branch: fix.data?.branchName,
        filesCount: fix.data?.filesToChange?.length ?? 0,
      },
    });

    // Step 3: SBOM check and inclusion
    let fixWithSbom = fix;
    if (repo) {
      try {
        fixWithSbom = await mainAgent.ensureSbomIncludedIfMissing(remediationRequest, fix, routePlan, { data: cveData }, emit);
      } catch {
        fixWithSbom = fix;
      }
    }

    // Step 4: Build PR payload and push to Forgejo
    emit({
      type: 'progress',
      agent: 'git_ops_agent',
      tool: 'git_ops_tool',
      status: 'running',
      message: 'Creating branch, committing fixes, and opening pull request on Forgejo.',
      timestamp: new Date().toISOString(),
    });

    const prPayload = mainAgent.buildPullRequestPayload(remediationRequest, fixWithSbom.data ?? fix.data, cveData);
    const prResult = await mainAgent.executeTool('git_ops_tool', 'openPullRequest', prPayload, emit);

    const prUrl = prResult.data?.html_url ?? prResult.data?.url ?? null;
    const prNumber = prResult.data?.number ?? null;

    emit({
      type: 'progress',
      agent: 'git_ops_agent',
      tool: 'git_ops_tool',
      status: prResult.status === 'success' ? 'success' : prResult.status,
      message: prResult.status === 'success'
        ? `Pull request #${prNumber ?? '?'} created successfully on Forgejo.`
        : `PR creation result: ${prResult.status}. ${prResult.data?.error ?? ''}`,
      timestamp: new Date().toISOString(),
      details: { prUrl, prNumber, prTitle: prPayload.prTitle },
    });

    // Step 5: Audit log
    await mainAgent.executeTool('audit_logger_tool', 'writeAuditEvent', {
      action: 'hitl_remediation_approved',
      applicationId: appId,
      applicationName: appName,
      cveCount: cveData.uniqueCves.length,
      prNumber,
      prUrl,
      approvedAt: new Date().toISOString(),
    }, emit);

    // Final result
    const finalResult = {
      status: prResult.status === 'success' ? 'success' : prResult.status,
      message: prResult.status === 'success'
        ? `Remediation complete. PR #${prNumber ?? '?'} opened for ${appName} with ${fixWithSbom.data?.filesToChange?.length ?? 0} file changes.`
        : `Remediation attempted but PR creation returned: ${prResult.status}.`,
      route: ['remediation_agent', 'git_ops_agent', 'audit_logger_tool'],
      pr: { url: prUrl, number: prNumber, title: prPayload.prTitle, branch: prPayload.newBranch },
      fix: {
        title: fix.data?.title,
        summary: fix.data?.summary,
        filesChanged: fix.data?.filesToChange?.length ?? 0,
        verificationCommands: fix.data?.verificationCommands ?? [],
        riskNotes: fix.data?.riskNotes ?? [],
      },
      context: ctx,
    };

    session.messages.push({ role: 'assistant', content: finalResult.message, result: finalResult, timestamp: new Date().toISOString() });
    sse(res, 'final', { ...finalResult, sessionId });
    res.end();
    return;
  }

  json(res, 404, { status: 'error', message: 'Not found' });
}

createServer((req, res) => {
  handle(req, res).catch((error) => {
    json(res, 500, {
      status: 'error',
      message: error instanceof Error ? error.message : 'Unknown server error',
    });
  });
}).listen(config.app.port, () => {
  console.log(`${config.app.name} listening on http://localhost:${config.app.port}`);
});
