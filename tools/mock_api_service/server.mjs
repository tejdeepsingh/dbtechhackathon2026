import { createServer } from 'node:http';

const port = Number(process.env.PORT ?? 8080);
const toolName = process.env.TOOL_NAME ?? 'mock_tool';

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

/* ---------- Contextual mock response generators ---------- */

function hash(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}

function pickN(arr, seed, n) {
  const out = [];
  for (let i = 0; i < n; i++) out.push(arr[(seed + i) % arr.length]);
  return out;
}

const cvePool = [
  { cve: 'CVE-2024-32002', severity: 'critical', package: 'git', fixedVersion: '2.45.1' },
  { cve: 'CVE-2024-3094', severity: 'critical', package: 'xz-utils', fixedVersion: '5.6.1-2' },
  { cve: 'CVE-2023-44487', severity: 'high', package: 'nghttp2', fixedVersion: '1.58.0' },
  { cve: 'CVE-2023-38545', severity: 'high', package: 'curl', fixedVersion: '8.4.0' },
  { cve: 'CVE-2024-21626', severity: 'high', package: 'runc', fixedVersion: '1.1.12' },
  { cve: 'CVE-2023-45853', severity: 'medium', package: 'zlib', fixedVersion: '1.3.1' },
  { cve: 'CVE-2024-0567', severity: 'medium', package: 'gnutls', fixedVersion: '3.8.3' },
  { cve: 'CVE-2023-5363', severity: 'medium', package: 'openssl', fixedVersion: '3.1.5' },
  { cve: 'CVE-2023-52425', severity: 'low', package: 'expat', fixedVersion: '2.6.0' },
  { cve: 'CVE-2024-22365', severity: 'low', package: 'pam', fixedVersion: '1.5.3-6' },
];

const runtimeCves = {
  java: [
    { cve: 'CVE-2024-20918', severity: 'high', package: 'spring-boot-starter-web', fixedVersion: '3.2.2' },
    { cve: 'CVE-2023-34055', severity: 'medium', package: 'spring-web', fixedVersion: '6.1.1' },
  ],
  nodejs: [
    { cve: 'CVE-2024-22019', severity: 'high', package: 'undici', fixedVersion: '6.6.1' },
    { cve: 'CVE-2023-46809', severity: 'medium', package: 'node', fixedVersion: '18.19.1' },
  ],
  python: [
    { cve: 'CVE-2024-0450', severity: 'medium', package: 'cpython', fixedVersion: '3.12.2' },
    { cve: 'CVE-2023-43804', severity: 'high', package: 'urllib3', fixedVersion: '2.0.7' },
  ],
  go: [
    { cve: 'CVE-2024-24790', severity: 'critical', package: 'stdlib', fixedVersion: '1.22.4' },
    { cve: 'CVE-2023-45283', severity: 'medium', package: 'path/filepath', fixedVersion: '1.21.6' },
  ],
  dotnet: [
    { cve: 'CVE-2024-21319', severity: 'high', package: 'Microsoft.Identity.Web', fixedVersion: '2.16.1' },
    { cve: 'CVE-2024-0057', severity: 'medium', package: 'System.Security.Cryptography', fixedVersion: '8.0.1' },
  ],
};

function detectRuntime(params) {
  const text = JSON.stringify(params).toLowerCase();
  if (text.includes('java') || text.includes('spring')) return 'java';
  if (text.includes('node') || text.includes('express') || text.includes('npm')) return 'nodejs';
  if (text.includes('python') || text.includes('fastapi') || text.includes('pip')) return 'python';
  if (text.includes('go') || text.includes('golang')) return 'go';
  if (text.includes('dotnet') || text.includes('.net') || text.includes('nuget')) return 'dotnet';
  return null;
}

function generateFindings(params) {
  const seed = hash(JSON.stringify(params));
  const runtime = detectRuntime(params);
  const base = pickN(cvePool, seed, 2 + (seed % 3));
  const extra = runtime && runtimeCves[runtime] ? runtimeCves[runtime] : [];
  return [...extra, ...base].slice(0, 5);
}

function defectdojoResponse(body) {
  const params = body.params ?? body;
  const appId = params.applicationId ?? params.appId ?? 'APP-00001';
  return {
    status: 'success',
    tool: toolName,
    data: {
      product: { id: hash(appId) % 900 + 100, name: appId, environment: params.environment ?? 'development' },
      findings: generateFindings(params).map((f, i) => ({
        id: 1000 + i,
        title: `${f.package} ${f.cve}`,
        severity: f.severity,
        cve: f.cve,
        component: f.package,
        status: 'active',
      })),
      totalFindings: generateFindings(params).length,
    },
  };
}

function containerScanResponse(body) {
  const params = body.params ?? body;
  const image = params.image ?? params.target ?? 'app:latest';
  return {
    status: 'success',
    tool: toolName,
    data: {
      image,
      scanTimestamp: new Date().toISOString(),
      vulnerabilities: generateFindings({ ...params, image }).map((f) => ({
        ...f,
        layer: 'RUN apt-get install',
        installedVersion: '0.0.0',
      })),
      summary: { critical: 1, high: 2, medium: 1, low: 1 },
    },
  };
}

function dependencyPatchResponse(body) {
  const params = body.params ?? body;
  return {
    status: 'success',
    tool: toolName,
    data: {
      repo: params.repo ?? params.target ?? 'unknown/repo',
      patchedDependencies: generateFindings(params).map((f) => ({
        package: f.package,
        from: '0.0.0',
        to: f.fixedVersion,
        cve: f.cve,
      })),
      prReady: true,
    },
  };
}

function osPkgUpgradeResponse(body) {
  const params = body.params ?? body;
  return {
    status: 'success',
    tool: toolName,
    data: {
      host: params.target ?? params.host ?? 'server-01',
      upgradedPackages: generateFindings(params).slice(0, 3).map((f) => ({
        package: f.package,
        from: '0.0.0',
        to: f.fixedVersion,
        cve: f.cve,
        severity: f.severity,
      })),
      rebootRequired: false,
    },
  };
}

function dastScanResponse(body) {
  const params = body.params ?? body;
  const target = params.runtimeUrl ?? params.target ?? 'http://localhost:8080';
  return {
    status: 'success',
    tool: toolName,
    data: {
      target,
      scanDuration: '12s',
      alerts: [
        { risk: 'high', name: 'SQL Injection', url: `${target}/api/search`, confidence: 'medium' },
        { risk: 'medium', name: 'Missing CSP Header', url: target, confidence: 'high' },
        { risk: 'low', name: 'Cookie Without Secure Flag', url: target, confidence: 'high' },
      ],
      summary: { high: 1, medium: 1, low: 1, informational: 0 },
    },
  };
}

function cveLookupResponse(body) {
  const params = body.params ?? body;
  const cves = params.cves ?? params.cveIds ?? [params.cve ?? 'CVE-2024-32002'];
  return {
    status: 'success',
    tool: toolName,
    data: {
      results: (Array.isArray(cves) ? cves : [cves]).map((cve) => ({
        id: cve,
        severity: 'high',
        description: `Remote code execution vulnerability in affected component.`,
        references: [`https://nvd.nist.gov/vuln/detail/${cve}`],
        fixAvailable: true,
        patchGuidance: `Upgrade affected package to the latest patched version.`,
      })),
    },
  };
}

function remediationDecisionResponse(body) {
  const params = body.params ?? body;
  const findings = generateFindings(params);
  return {
    status: 'success',
    tool: toolName,
    data: {
      strategy: params.environment === 'production' ? 'staged-rollout' : 'immediate-patch',
      confidence: 0.92,
      actions: findings.slice(0, 3).map((f) => ({
        action: 'upgrade',
        package: f.package,
        targetVersion: f.fixedVersion,
        cve: f.cve,
        risk: 'low',
      })),
      approvalRequired: params.environment === 'production',
    },
  };
}

function auditLogResponse(body) {
  const params = body.params ?? body;
  return {
    status: 'success',
    tool: toolName,
    data: {
      eventId: `audit-${Date.now()}-${(Math.random() * 1000) | 0}`,
      timestamp: new Date().toISOString(),
      action: params.action ?? 'scan_completed',
      applicationId: params.applicationId ?? 'unknown',
      recorded: true,
    },
  };
}

function pipelineLintResponse(body) {
  const params = body.params ?? body;
  return {
    status: 'success',
    tool: toolName,
    data: {
      pipeline: params.pipeline ?? params.target ?? 'CI/CD pipeline',
      issues: [
        { severity: 'high', rule: 'no-plain-text-secrets', message: 'Possible secret in environment variable', line: 42 },
        { severity: 'medium', rule: 'pin-action-versions', message: 'Action uses mutable tag instead of SHA', line: 15 },
      ],
      passed: false,
    },
  };
}

function verificationScanResponse(body) {
  const params = body.params ?? body;
  return {
    status: 'success',
    tool: toolName,
    data: {
      verified: true,
      target: params.repo ?? params.target ?? 'unknown',
      originalCves: (params.cves ?? ['CVE-2024-32002']).slice(0, 3),
      remainingAfterFix: 0,
      message: 'All patched vulnerabilities verified as resolved.',
    },
  };
}

function notificationResponse(body) {
  const params = body.params ?? body;
  return {
    status: 'success',
    tool: toolName,
    data: {
      channel: params.channel ?? 'slack',
      recipient: params.recipient ?? '#security-alerts',
      sent: true,
      messagePreview: `AVRC scan completed for ${params.applicationId ?? 'application'}: remediation PR ready for review.`,
    },
  };
}

function reportGeneratorResponse(body) {
  const params = body.params ?? body;
  return {
    status: 'success',
    tool: toolName,
    data: {
      reportId: `rpt-${Date.now()}`,
      format: params.format ?? 'html',
      applicationId: params.applicationId ?? 'unknown',
      summary: {
        totalFindings: 5,
        critical: 1,
        high: 2,
        medium: 1,
        low: 1,
        remediationRate: '80%',
      },
      downloadUrl: `/reports/rpt-${Date.now()}.html`,
    },
  };
}

function kubescapeScanResponse(body) {
  const params = body.params ?? body;
  return {
    status: 'success',
    tool: toolName,
    data: {
      cluster: params.cluster ?? params.target ?? 'default',
      namespace: params.namespace ?? 'default',
      controls: [
        { id: 'C-0034', name: 'Automatic mapping of SA', status: 'failed', severity: 'high' },
        { id: 'C-0017', name: 'Immutable container filesystem', status: 'failed', severity: 'medium' },
        { id: 'C-0055', name: 'Linux hardening', status: 'passed', severity: 'medium' },
      ],
      complianceScore: 72,
    },
  };
}

function wazuhResponse(body) {
  const params = body.params ?? body;
  return {
    status: 'success',
    tool: toolName,
    data: {
      agent: params.target ?? params.host ?? 'on-prem-server-01',
      alerts: [
        { level: 12, rule: 'Rootkit detection', description: 'Hidden process found' },
        { level: 7, rule: 'File integrity', description: '/etc/passwd modified' },
      ],
      vulnerabilities: generateFindings(params).slice(0, 3),
    },
  };
}

function greenboneScanResponse(body) {
  const params = body.params ?? body;
  return {
    status: 'success',
    tool: toolName,
    data: {
      target: params.target ?? params.host ?? '10.0.0.0/24',
      scanDuration: '45s',
      results: [
        { severity: 'high', nvt: 'SSL/TLS: Certificate Expired', host: '10.0.0.5', port: 443 },
        { severity: 'medium', nvt: 'SSH Weak Algorithms', host: '10.0.0.12', port: 22 },
      ],
      hostsScanned: 8,
    },
  };
}

function copaceticPatchResponse(body) {
  const params = body.params ?? body;
  return {
    status: 'success',
    tool: toolName,
    data: {
      image: params.image ?? params.target ?? 'app:latest',
      patchedImage: `${params.image ?? 'app'}:patched`,
      patchedVulnerabilities: generateFindings(params).slice(0, 2).map((f) => f.cve),
      sizeIncrease: '2.1 MB',
    },
  };
}

function nvdLookupResponse(body) {
  const params = body.params ?? body;
  const cveId = params.cve ?? params.cveId ?? 'CVE-2024-32002';
  return {
    status: 'success',
    tool: toolName,
    data: {
      cve: cveId,
      cvssV3: { baseScore: 8.1, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H' },
      published: '2024-05-14',
      description: 'Recursive clone vulnerability allowing arbitrary code execution.',
      references: [`https://nvd.nist.gov/vuln/detail/${cveId}`],
      cpe: ['cpe:2.3:a:git-scm:git:*:*:*:*:*:*:*:*'],
    },
  };
}

function openrewriteResponse(body) {
  const params = body.params ?? body;
  return {
    status: 'success',
    tool: toolName,
    data: {
      repo: params.repo ?? params.target ?? 'unknown/repo',
      recipesApplied: ['org.openrewrite.java.spring.boot3.UpgradeSpringBoot_3_2', 'org.openrewrite.java.dependencies.UpgradeDependencyVersion'],
      filesModified: ['pom.xml', 'build.gradle'],
      linesChanged: 14,
    },
  };
}

/* ---------- Tool router ---------- */

const toolResponders = {
  defectdojo_api_tool: defectdojoResponse,
  pipeline_lint_tool: pipelineLintResponse,
  container_scan_tool: containerScanResponse,
  dependency_patch_tool: dependencyPatchResponse,
  os_pkg_upgrade_tool: osPkgUpgradeResponse,
  dynamic_software_scan_tool: dastScanResponse,
  remediation_decision_tool: remediationDecisionResponse,
  audit_logger_tool: auditLogResponse,
  cve_lookup_tool: cveLookupResponse,
  verification_scan_tool: verificationScanResponse,
  notification_tool: notificationResponse,
  report_generator_tool: reportGeneratorResponse,
  copacetic_patch_tool: copaceticPatchResponse,
  kubescape_scan_tool: kubescapeScanResponse,
  wazuh_vulnerability_tool: wazuhResponse,
  greenbone_scan_tool: greenboneScanResponse,
  zap_dast_tool: dastScanResponse,
  nvd_lookup_tool: nvdLookupResponse,
  openrewrite_remediation_tool: openrewriteResponse,
};

createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);

  if (req.method === 'GET' && url.pathname === '/health') {
    sendJson(res, 200, { status: 'ok', tool: toolName });
    return;
  }

  if (req.method === 'POST') {
    const body = await readBody(req);
    const responder = toolResponders[toolName];
    if (responder) {
      sendJson(res, 200, responder(body));
    } else {
      sendJson(res, 200, {
        status: 'success',
        tool: toolName,
        path: url.pathname,
        data: { mock: true, findings: generateFindings(body.params ?? body) },
      });
    }
    return;
  }

  sendJson(res, 404, { status: 'error', tool: toolName, message: 'Route not found' });
}).listen(port, () => {
  console.log(`${toolName} listening on 0.0.0.0:${port}`);
});
