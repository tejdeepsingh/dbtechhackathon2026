import { createServer } from 'node:http';

const port = Number(process.env.PORT ?? 8080);
const osvBaseUrl = (process.env.OSV_API_BASE ?? 'https://api.osv.dev').replace(/\/$/, '');
const defaultTimeoutMs = Number(process.env.OSV_TIMEOUT_MS ?? 30000);

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks).toString('utf-8');
  return raw ? JSON.parse(raw) : {};
}

function unwrap(body) {
  return body?.params ?? body ?? {};
}

async function osvRequest(path, payload, timeoutMs = defaultTimeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(`${osvBaseUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    const text = await response.text();
    const data = text ? JSON.parse(text) : {};

    if (!response.ok) {
      const error = new Error(`OSV HTTP ${response.status}`);
      error.status = response.status;
      error.data = data;
      throw error;
    }

    return data;
  } finally {
    clearTimeout(timeout);
  }
}

async function osvGet(path, timeoutMs = defaultTimeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(`${osvBaseUrl}${path}`, {
      headers: { accept: 'application/json' },
      signal: controller.signal,
    });
    const text = await response.text();
    const data = text ? JSON.parse(text) : {};

    if (!response.ok) {
      const error = new Error(`OSV HTTP ${response.status}`);
      error.status = response.status;
      error.data = data;
      throw error;
    }

    return data;
  } finally {
    clearTimeout(timeout);
  }
}

function purlFor(params) {
  if (params.purl) return params.purl;

  const pkg = params.package ?? params.packageName ?? params.component;
  const version = params.version ?? params.installedVersion ?? params.installed_version;
  const ecosystem = ecosystemFor(params.ecosystem, pkg);

  if (!pkg || !version || !ecosystem) return null;
  const purlType = {
    npm: 'npm',
    PyPI: 'pypi',
    Maven: 'maven',
    Go: 'golang',
    NuGet: 'nuget',
  }[ecosystem];

  return purlType ? `pkg:${purlType}/${encodeURIComponent(pkg)}@${encodeURIComponent(version)}` : null;
}

function ecosystemFor(value, pkg) {
  if (value) return value;
  const name = String(pkg ?? '');
  if (name.includes(':') || name.includes('.')) return 'Maven';
  if (name.startsWith('github.com/')) return 'Go';
  if (/^[A-Z]/.test(name)) return 'PyPI';
  return null;
}

function normalizeVuln(vuln) {
  const severity = vuln.severity?.[0]?.score ?? vuln.database_specific?.severity ?? 'unknown';
  return {
    id: vuln.id,
    cve: vuln.aliases?.find((alias) => /^CVE-\d{4}-\d{4,}$/i.test(alias)) ?? vuln.id,
    aliases: vuln.aliases ?? [],
    summary: vuln.summary ?? '',
    details: vuln.details ?? '',
    severity,
    modified: vuln.modified,
    published: vuln.published,
    references: (vuln.references ?? []).map((reference) => ({
      type: reference.type,
      url: reference.url,
    })),
    affected: (vuln.affected ?? []).map((affected) => ({
      package: affected.package,
      ranges: affected.ranges,
      versions: affected.versions,
      ecosystemSpecific: affected.ecosystem_specific,
      databaseSpecific: affected.database_specific,
    })),
  };
}

async function lookup(params) {
  const cve = params.cve ?? params.id ?? params.vulnerabilityId;
  if (cve && /^CVE-\d{4}-\d{4,}$/i.test(String(cve))) {
    const data = await osvGet(`/v1/vulns/${encodeURIComponent(String(cve).toUpperCase())}`);
    return enrichedResponse(params, [data]);
  }

  const purl = purlFor(params);
  if (purl) {
    const data = await osvRequest('/v1/query', { package: { purl } });
    return enrichedResponse(params, data.vulns ?? []);
  }

  return {
    status: 'needs_input',
    tool: 'osv_lookup_tool',
    message: 'Provide a CVE alias or package/version for OSV lookup.',
    received: params,
    findings: [],
    data: { findings: [] },
  };
}

async function scan(params) {
  const findings = params.findings ?? params.uniqueCves ?? params.vulnerabilities ?? [];
  if (!Array.isArray(findings) || findings.length === 0) {
    return lookup(params);
  }

  const results = [];
  for (const finding of findings.slice(0, 100)) {
    results.push(await lookup({ ...finding, severity: finding.severity ?? params.severity }));
  }

  const enrichedFindings = results.flatMap((result) => result.findings ?? []);
  return {
    status: 'success',
    tool: 'osv_lookup_tool',
    scanner: 'osv.dev',
    totalFindings: enrichedFindings.length,
    findings: enrichedFindings,
    results,
    data: {
      findings: enrichedFindings,
      results,
    },
  };
}

function enrichedResponse(params, vulns) {
  const normalized = vulns.map(normalizeVuln);
  return {
    status: 'success',
    tool: 'osv_lookup_tool',
    scanner: 'osv.dev',
    query: params,
    totalFindings: normalized.length,
    findings: normalized,
    data: {
      findings: normalized,
    },
  };
}

createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);

  try {
    if (req.method === 'GET' && url.pathname === '/health') {
      sendJson(res, 200, {
        status: 'ok',
        tool: 'osv_lookup_tool',
        provider: 'osv.dev',
        osvBaseUrl,
      });
      return;
    }

    if (req.method !== 'POST') {
      sendJson(res, 404, { status: 'error', message: 'Route not found' });
      return;
    }

    const params = unwrap(await readBody(req));
    if (url.pathname === '/osv/lookup') {
      sendJson(res, 200, await lookup(params));
      return;
    }
    if (url.pathname === '/osv/scan') {
      sendJson(res, 200, await scan(params));
      return;
    }

    sendJson(res, 404, { status: 'error', message: 'Route not found' });
  } catch (error) {
    sendJson(res, 500, {
      status: 'error',
      tool: 'osv_lookup_tool',
      provider: 'osv.dev',
      message: error.message,
      details: error.data,
    });
  }
}).listen(port, () => {
  console.log(`osv_lookup_tool listening on 0.0.0.0:${port}, OSV=${osvBaseUrl}`);
});
