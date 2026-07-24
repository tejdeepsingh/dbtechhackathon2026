import { spawn } from 'node:child_process';
import { createServer } from 'node:http';

const port = Number(process.env.PORT ?? 8080);
const endpoint = (process.env.RENOVATE_ENDPOINT ?? 'http://forgejo:3000/api/v1').replace(/\/$/, '');
const defaultPlatform = process.env.RENOVATE_PLATFORM ?? 'forgejo';
const defaultTimeoutMs = Number(process.env.RENOVATE_TIMEOUT_MS ?? 300000);
const defaultToken = process.env.FORGEJO_TOKEN ?? process.env.RENOVATE_TOKEN ?? '';
const defaultRepo = process.env.FORGEJO_REPO ?? process.env.RENOVATE_REPOSITORY ?? '';

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

function repoFor(params) {
  return params.repoPath ?? params.projectPath ?? params.repository ?? params.repo ?? params.target ?? defaultRepo;
}

function normalizeRepo(value) {
  if (!value) return '';
  const text = String(value).trim().replace(/\.git$/, '');
  try {
    const url = new URL(text);
    return url.pathname.replace(/^\//, '').replace(/\.git$/, '');
  } catch {
    return text.replace(/^https?:\/\/localhost:3001\//, '').replace(/^https?:\/\/forgejo:3000\//, '').replace(/^\//, '');
  }
}

function tokenFor(params) {
  return params.renovateToken ?? params.forgejoToken ?? params.token ?? defaultToken;
}

function redact(value, token) {
  return token ? String(value).replaceAll(token, '***') : value;
}

function gitUrlRewriteEnv(token) {
  const env = {
    GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: 'url.http://forgejo:3000/.insteadOf',
    GIT_CONFIG_VALUE_0: 'http://localhost:3001/',
  };

  if (token) {
    env.GIT_CONFIG_COUNT = '2';
    env.GIT_CONFIG_KEY_1 = `url.http://${token}@forgejo:3000/.insteadOf`;
    env.GIT_CONFIG_VALUE_1 = `http://${token}@localhost:3001/`;
  }

  return env;
}

function runRenovate(repo, params, { apply = false } = {}) {
  const token = tokenFor(params);
  const timeoutMs = Number(params.timeoutMs ?? defaultTimeoutMs);
  const dryRun = apply ? null : (params.dryRun ?? process.env.RENOVATE_DRY_RUN ?? 'full');
  const args = [
    repo,
    `--platform=${params.platform ?? defaultPlatform}`,
    `--endpoint=${params.endpoint ?? endpoint}`,
    '--onboarding=false',
    '--require-config=optional',
    '--dependency-dashboard=false',
  ];

  if (dryRun) {
    args.push(`--dry-run=${dryRun}`);
  }

  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn('renovate', args, {
      env: {
        ...process.env,
        LOG_LEVEL: params.logLevel ?? 'info',
        RENOVATE_TOKEN: token,
        RENOVATE_USERNAME: params.username ?? process.env.RENOVATE_USERNAME ?? 'avrc-bot',
        RENOVATE_GIT_AUTHOR: process.env.RENOVATE_GIT_AUTHOR ?? 'AVRC Bot <avrc-bot@example.local>',
        ...gitUrlRewriteEnv(token),
      },
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
    }, timeoutMs);

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({
        code,
        signal,
        durationMs: Date.now() - started,
        stdout: redact(stdout.slice(-20000), token),
        stderr: redact(stderr.slice(-20000), token),
        timedOut: signal === 'SIGTERM',
      });
    });
  });
}

function summarizeOutput(output) {
  const text = `${output.stdout}\n${output.stderr}`;
  return {
    packageFiles: [...text.matchAll(/packageFiles with updates|managerBranch/g)].length,
    branches: [...text.matchAll(/branchName|branch=/g)].length,
    containsDryRun: /dry-run|DRY-RUN/i.test(text),
    warnings: text.split(/\r?\n/).filter((line) => /\bwarn\b|warning/i.test(line)).slice(-10),
  };
}

async function renovate(params, apply = false) {
  const repo = normalizeRepo(repoFor(params));
  if (!repo) {
    return {
      status: 'needs_input',
      tool: 'renovate_fix_tool',
      message: 'Provide repo, repository, target, or FORGEJO_REPO.',
      data: { findings: [] },
    };
  }
  if (!tokenFor(params)) {
    return {
      status: 'needs_configuration',
      tool: 'renovate_fix_tool',
      message: 'FORGEJO_TOKEN or request token is required for real Renovate against Forgejo.',
      repo,
      dryRun: !apply,
      data: { findings: [] },
    };
  }

  const output = await runRenovate(repo, params, { apply });
  const success = output.code === 0;
  return {
    status: success ? 'success' : 'error',
    tool: 'renovate_fix_tool',
    scanner: 'renovate',
    repo,
    mode: apply ? 'apply' : 'dry-run',
    renovate: output,
    summary: summarizeOutput(output),
    findings: [],
    data: {
      findings: [],
      repo,
      mode: apply ? 'apply' : 'dry-run',
      summary: summarizeOutput(output),
      renovate: output,
    },
  };
}

createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);

  try {
    if (req.method === 'GET' && url.pathname === '/health') {
      sendJson(res, 200, {
        status: 'ok',
        tool: 'renovate_fix_tool',
        scanner: 'renovate',
        platform: defaultPlatform,
        endpoint,
      });
      return;
    }

    if (req.method !== 'POST') {
      sendJson(res, 404, { status: 'error', message: 'Route not found' });
      return;
    }

    const params = unwrap(await readBody(req));
    if (url.pathname === '/renovate/scan') {
      sendJson(res, 200, await renovate(params, false));
      return;
    }
    if (url.pathname === '/renovate/remediate') {
      sendJson(res, 200, await renovate(params, Boolean(params.apply || params.approvedApply)));
      return;
    }

    sendJson(res, 404, { status: 'error', message: 'Route not found' });
  } catch (error) {
    sendJson(res, 500, {
      status: 'error',
      tool: 'renovate_fix_tool',
      scanner: 'renovate',
      message: error.message,
    });
  }
}).listen(port, () => {
  console.log(`renovate_fix_tool listening on 0.0.0.0:${port}, endpoint=${endpoint}`);
});
