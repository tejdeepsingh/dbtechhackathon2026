import { Buffer } from 'node:buffer';
import { createServer } from 'node:http';

const port = Number(process.env.PORT ?? 8080);
const forgeBaseUrl = (process.env.FORGEJO_BASE_URL ?? 'http://forgejo:3000').replace(/\/$/, '');
const defaultToken = process.env.FORGEJO_TOKEN ?? process.env.GIT_TOKEN ?? '';
const defaultRepo = process.env.FORGEJO_REPO ?? process.env.GIT_REPO ?? '';
const defaultAuthorName = process.env.GIT_AUTHOR_NAME ?? 'AVRC Bot';
const defaultAuthorEmail = process.env.GIT_AUTHOR_EMAIL ?? 'avrc-bot@example.local';

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
  if (!raw) return {};
  return JSON.parse(raw);
}

function unwrap(body) {
  return body?.params ?? body ?? {};
}

function tokenFor(params) {
  return params.forgejoToken ?? params.giteaToken ?? params.token ?? defaultToken;
}

function repoFor(params) {
  return (
    params.repoPath ??
    params.projectPath ??
    params.forgejoRepo ??
    params.giteaRepo ??
    params.repo ??
    defaultRepo
  );
}

function parseRepoPath(repo) {
  if (!repo) return '';
  try {
    const url = new URL(repo);
    return url.pathname.replace(/^\//, '').replace(/\.git$/, '');
  } catch {
    return String(repo).replace(/\.git$/, '');
  }
}

function splitRepo(repo) {
  const clean = parseRepoPath(repo).replace(/^\//, '');
  const [owner, ...nameParts] = clean.split('/');
  return { owner, repo: nameParts.join('/') };
}

function assertRepoParts(owner, repo) {
  if (!owner || !repo) {
    const error = new Error('Forgejo repo must be in owner/repository format.');
    error.status = 400;
    error.data = { expected: 'owner/repository' };
    throw error;
  }
}

function missingConfig(params) {
  const missing = [];
  if (!tokenFor(params)) missing.push('FORGEJO_TOKEN or request token');
  if (!repoFor(params)) missing.push('FORGEJO_REPO or request repoPath/projectPath');
  return missing;
}

async function forgeRequest(path, { method = 'GET', token, body } = {}) {
  const response = await fetch(`${forgeBaseUrl}/api/v1${path}`, {
    method,
    headers: {
      accept: 'application/json',
      authorization: `token ${token}`,
      'content-type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let data = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      // Forgejo sometimes returns non-JSON (empty, HTML, or bare values)
      data = { raw: text.substring(0, 500) };
    }
  }

  if (!response.ok) {
    const error = new Error(`Forgejo API ${response.status}: ${data.message ?? text.substring(0, 100)}`);
    error.status = response.status;
    error.data = data;
    throw error;
  }

  return data;
}

async function createBranch(params) {
  const missing = missingConfig(params);
  const branch = params.newBranch ?? params.branch;
  const ref = params.baseBranch ?? params.ref ?? 'main';

  if (missing.length) {
    return dryRun('createBranch', params, missing);
  }

  const { owner, repo } = splitRepo(repoFor(params));
  assertRepoParts(owner, repo);
  try {
    const result = await forgeRequest(`/repos/${owner}/${repo}/branches`, {
      method: 'POST',
      token: tokenFor(params),
      body: {
        new_branch_name: branch,
        old_branch_name: ref,
      },
    });
    return { status: 'success', provider: 'forgejo', branch: result.name ?? branch };
  } catch (error) {
    if ([409, 422].includes(error.status)) {
      return { status: 'success', provider: 'forgejo', branch, alreadyExists: true };
    }
    throw error;
  }
}

function normalizeChanges(params) {
  const changes = params.changes ?? params.filesToChange ?? [];
  if (changes.length > 0) {
    return changes
      .map((change) => {
        const path = change.path ?? change.filePath;
        if (!path) return null;

        const content =
          change.content ??
          change.newContent ??
          [
            `# AVRC suggested remediation for ${path}`,
            '',
            change.rationale ? `Rationale: ${change.rationale}` : null,
            change.suggestedPatch ? `Suggested patch: ${change.suggestedPatch}` : null,
          ]
            .filter(Boolean)
            .join('\n');

        return { ...change, path, content };
      })
      .filter(Boolean);
  }

  return [
    {
      path: 'AVRC_REMEDIATION_PLAN.md',
      action: 'create',
      content: [
        '# AVRC Remediation Plan',
        '',
        params.prBody ?? params.summary ?? 'Generated remediation request.',
        '',
        'Review the CVE summary and apply the recommended dependency or configuration updates.',
      ].join('\n'),
    },
  ];
}

async function getFileSha({ owner, repo, filePath, branch, token }) {
  try {
    const data = await forgeRequest(`/repos/${owner}/${repo}/contents/${filePath.split('/').map(encodeURIComponent).join('/')}?ref=${encodeURIComponent(branch)}`, {
      token,
    });
    return data.sha;
  } catch (error) {
    if (error.status === 404) return null;
    throw error;
  }
}

async function upsertFile({ owner, repo, branch, token, change, message, params }) {
  const sha = await getFileSha({ owner, repo, filePath: change.path, branch, token });
  const method = sha ? 'PUT' : 'POST';
  const body = {
    branch,
    content: Buffer.from(change.content, 'utf-8').toString('base64'),
    message,
    author: {
      name: params.authorName ?? defaultAuthorName,
      email: params.authorEmail ?? defaultAuthorEmail,
    },
    committer: {
      name: params.authorName ?? defaultAuthorName,
      email: params.authorEmail ?? defaultAuthorEmail,
    },
  };

  if (sha) {
    body.sha = sha;
  }

  return forgeRequest(`/repos/${owner}/${repo}/contents/${change.path.split('/').map(encodeURIComponent).join('/')}`, {
    method,
    token,
    body,
  });
}

async function commitPatch(params) {
  const missing = missingConfig(params);
  const branch = params.newBranch ?? params.branch;

  if (missing.length) {
    return dryRun('commitPatch', params, missing);
  }

  const { owner, repo } = splitRepo(repoFor(params));
  assertRepoParts(owner, repo);
  const token = tokenFor(params);
  const message = params.commitMessage ?? params.prTitle ?? 'AVRC remediation changes';
  const results = [];

  for (const change of normalizeChanges(params)) {
    results.push(await upsertFile({ owner, repo, branch, token, change, message, params }));
  }

  return {
    status: 'success',
    provider: 'forgejo',
    repo: `${owner}/${repo}`,
    branch,
    filesChanged: results.length,
    commits: results.map((result) => result.commit?.sha).filter(Boolean),
  };
}

async function checkFileExists(params) {
  const missing = missingConfig(params);

  if (missing.length) {
    return dryRun('checkFileExists', params, missing);
  }

  const { owner, repo } = splitRepo(repoFor(params));
  assertRepoParts(owner, repo);

  const token = tokenFor(params);
  const branch = params.baseBranch ?? params.branch ?? 'main';
  const paths = Array.isArray(params.filePaths)
    ? params.filePaths
    : params.filePath
      ? [params.filePath]
      : [];

  if (!paths.length) {
    const error = new Error('Provide filePath or filePaths.');
    error.status = 400;
    throw error;
  }

  for (const filePath of paths) {
    const sha = await getFileSha({ owner, repo, filePath, branch, token });
    if (sha) {
      return {
        status: 'success',
        provider: 'forgejo',
        repo: `${owner}/${repo}`,
        branch,
        exists: true,
        path: filePath,
        sha,
      };
    }
  }

  return {
    status: 'success',
    provider: 'forgejo',
    repo: `${owner}/${repo}`,
    branch,
    exists: false,
    checkedPaths: paths,
  };
}

async function openPullRequest(params) {
  const missing = missingConfig(params);

  if (missing.length) {
    return dryRun('openPullRequest', params, missing);
  }

  const newBranch = params.newBranch ?? `avrc/remediate-${Date.now()}`;
  const baseBranch = params.baseBranch ?? 'main';
  await createBranch({ ...params, newBranch, baseBranch });
  const commitResult = await commitPatch({ ...params, newBranch, branch: newBranch });

  const { owner, repo } = splitRepo(repoFor(params));
  assertRepoParts(owner, repo);
  const pull = await forgeRequest(`/repos/${owner}/${repo}/pulls`, {
    method: 'POST',
    token: tokenFor(params),
    body: {
      base: baseBranch,
      head: newBranch,
      title: params.prTitle ?? params.title ?? 'AVRC remediation',
      body: params.prBody ?? params.description ?? 'Generated by AVRC.',
    },
  });

  return {
    status: 'success',
    provider: 'forgejo',
    repo: `${owner}/${repo}`,
    commit: commitResult,
    pullRequest: {
      number: pull.number,
      id: pull.id,
      url: pull.html_url,
      state: pull.state,
    },
  };
}

function dryRun(operation, params, missing) {
  return {
    status: 'needs_configuration',
    provider: 'forgejo',
    operation,
    baseUrl: forgeBaseUrl,
    missing,
    dryRun: true,
    message: 'Forgejo configuration is missing. Returning dry-run GitOps payload.',
    request: params,
  };
}

createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);

  try {
    if (req.method === 'GET' && url.pathname === '/health') {
      sendJson(res, 200, {
        status: 'ok',
        tool: 'git_ops_tool',
        provider: 'forgejo',
        forgeBaseUrl,
      });
      return;
    }

    if (req.method !== 'POST') {
      sendJson(res, 404, { status: 'error', message: 'Route not found' });
      return;
    }

    const params = unwrap(await readBody(req));
    if (url.pathname === '/git/branch') {
      sendJson(res, 200, await createBranch(params));
      return;
    }
    if (url.pathname === '/git/commit') {
      sendJson(res, 200, await commitPatch(params));
      return;
    }
    if (url.pathname === '/git/file-exists') {
      sendJson(res, 200, await checkFileExists(params));
      return;
    }
    if (url.pathname === '/git/pull-request') {
      sendJson(res, 200, await openPullRequest(params));
      return;
    }

    sendJson(res, 404, { status: 'error', message: 'Route not found' });
  } catch (error) {
    sendJson(res, 500, {
      status: 'error',
      provider: 'forgejo',
      message: error.message,
      details: error.data,
    });
  }
}).listen(port, () => {
  console.log(`git_ops_tool listening on 0.0.0.0:${port}, Forgejo=${forgeBaseUrl}`);
});
