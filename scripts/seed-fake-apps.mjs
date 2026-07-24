import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = resolve(fileURLToPath(new URL('..', import.meta.url)));
const dataDir = resolve(rootDir, 'data');
const outputDir = resolve(rootDir, 'output', 'fake-repos');

const environments = ['development', 'qa', 'staging', 'production', 'dr', 'on-prem', 'hybrid'];
const runtimes = ['nodejs18', 'java17-spring', 'python3.11-fastapi', 'go1.22', 'dotnet8', 'nginx-static'];
const businessUnits = ['payments', 'loans', 'cards', 'risk', 'core-banking', 'analytics', 'identity', 'treasury'];
const severities = ['critical', 'high', 'medium', 'low'];
const installRoots = {
  development: '/srv/dev',
  qa: '/srv/qa',
  staging: '/opt/staging',
  production: '/opt/apps',
  dr: '/dr/apps',
  'on-prem': 'D:\\Apps',
  hybrid: '/hybrid/apps',
};

const vulnerabilityCatalog = [
  {
    type: 'repo',
    cve: 'CVE-2021-44228',
    severity: 'critical',
    component: 'log4j-core',
    installedVersion: '2.14.1',
    fixedVersion: '2.17.1',
    path: 'pom.xml',
    remediation: 'Upgrade log4j-core to 2.17.1 or later.',
  },
  {
    type: 'repo',
    cve: 'CVE-2019-10744',
    severity: 'high',
    component: 'lodash',
    installedVersion: '4.17.11',
    fixedVersion: '4.17.21',
    path: 'package.json',
    remediation: 'Upgrade lodash to 4.17.21.',
  },
  {
    type: 'repo',
    cve: 'CVE-2022-31129',
    severity: 'high',
    component: 'moment',
    installedVersion: '2.19.3',
    fixedVersion: '2.29.4',
    path: 'package.json',
    remediation: 'Upgrade moment to 2.29.4 or remove it.',
  },
  {
    type: 'repo',
    cve: 'CVE-2020-28493',
    severity: 'medium',
    component: 'jinja2',
    installedVersion: '2.10',
    fixedVersion: '2.11.3',
    path: 'requirements.txt',
    remediation: 'Upgrade Jinja2 to a patched version.',
  },
  {
    type: 'image',
    cve: 'CVE-2023-45853',
    severity: 'critical',
    component: 'zlib',
    installedVersion: '1.2.11',
    fixedVersion: '1.3',
    path: 'Dockerfile',
    remediation: 'Rebuild on a patched base image.',
  },
  {
    type: 'runtime',
    cve: 'CVE-2021-41773',
    severity: 'high',
    component: 'apache-httpd',
    installedVersion: '2.4.49',
    fixedVersion: '2.4.51',
    path: '/usr/sbin/httpd',
    remediation: 'Patch Apache httpd and block path traversal.',
  },
  {
    type: 'path',
    cve: 'CVE-2023-29489',
    severity: 'medium',
    component: 'cPanel path exposure',
    installedVersion: '11.108',
    fixedVersion: '11.109',
    path: '/var/cpanel',
    remediation: 'Patch cPanel and restrict exposed paths.',
  },
  {
    type: 'build_container',
    cve: 'CVE-2022-24765',
    severity: 'high',
    component: 'git',
    installedVersion: '2.34.1',
    fixedVersion: '2.35.2',
    path: '.forgejo/workflows/build.yml',
    remediation: 'Use a patched CI image with newer git.',
  },
];

const forgejoActions = [
  'actions/checkout@v4',
  'actions/setup-node@v4',
  'actions/setup-java@v4',
  'actions/setup-python@v5',
  'docker/build-push-action@v6',
  'aquasecurity/trivy-action@master',
];

function parseArgs() {
  const args = new Map();
  const raw = process.argv.slice(2);
  for (let index = 0; index < raw.length; index += 1) {
    const arg = raw[index];
    if (!arg.startsWith('--')) continue;
    const key = arg.slice(2);
    const next = raw[index + 1];
    if (!next || next.startsWith('--')) {
      args.set(key, true);
    } else {
      args.set(key, next);
      index += 1;
    }
  }
  return args;
}

async function loadEnv() {
  try {
    const raw = await readFile(resolve(rootDir, '.env'), 'utf-8');
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) continue;
      const [key, ...valueParts] = trimmed.split('=');
      process.env[key] ??= valueParts.join('=').trim();
    }
  } catch {
    // .env is optional; regular environment variables can provide the same values.
  }
}

function pick(list, index, offset = 0) {
  return list[(index + offset) % list.length];
}

function appName(index) {
  const unit = pick(businessUnits, index);
  const suffix = String(index + 1).padStart(4, '0');
  return `${unit}-service-${suffix}`;
}

function repoNameFor(app) {
  return `avrc-${app.appName}`;
}

function cloneUrls(baseUrl, owner, repoName) {
  const cleanBase = baseUrl.replace(/\/$/, '');
  return {
    webUrl: `${cleanBase}/${owner}/${repoName}`,
    cloneUrl: `${cleanBase}/${owner}/${repoName}.git`,
  };
}

function generateVulnerabilities(index, runtime, environment) {
  const count = 3 + (index % 4);
  const vulns = [];
  for (let offset = 0; offset < count; offset += 1) {
    const vuln = { ...pick(vulnerabilityCatalog, index, offset) };
    if (runtime.startsWith('java') && offset === 0) {
      Object.assign(vuln, vulnerabilityCatalog[0]);
    }
    if (runtime.startsWith('node') && offset === 0) {
      Object.assign(vuln, vulnerabilityCatalog[1]);
    }
    if (environment === 'production' && offset === 0) {
      vuln.severity = 'critical';
    }
    vulns.push(vuln);
  }
  return vulns;
}

function generateApplication(index, owner, baseUrl) {
  const environment = pick(environments, index);
  const runtime = pick(runtimes, index, 2);
  const app = {
    appId: `APP-${String(index + 1).padStart(5, '0')}`,
    appName: appName(index),
    businessUnit: pick(businessUnits, index),
    environment,
    runtime,
    severity: pick(severities, index, environment === 'production' ? 0 : 1),
    installedPath: `${installRoots[environment]}/${appName(index)}`,
    jarFiles: runtime.startsWith('java')
      ? [`${appName(index)}-api.jar`, 'log4j-core-2.14.1.jar', 'jackson-databind-2.9.9.jar']
      : [],
    ciCdPipeline: {
      provider: 'forgejo-actions',
      workflowPath: '.forgejo/workflows/build.yml',
      runnerImage: pick(['node:18-bullseye', 'maven:3.8.1-openjdk-11', 'python:3.9-slim', 'golang:1.18'], index),
      buildContainer: `localhost:5000/build/${appName(index)}:ci-${index + 1}`,
    },
    forgejoActions: pickActionSet(index),
    image: `localhost:5000/avrc/${appName(index)}:${pick(['1.0.0', '1.2.3', '2024.04', 'latest'], index)}`,
    imageBase: pick(['node:14-buster', 'openjdk:8-jdk', 'python:3.8-slim-buster', 'golang:1.17-buster', 'nginx:1.21'], index),
    vulnerabilities: generateVulnerabilities(index, runtime, environment),
  };
  const repoName = repoNameFor(app);
  app.repository = {
    provider: 'forgejo',
    owner,
    name: repoName,
    defaultBranch: 'main',
    ...cloneUrls(baseUrl, owner, repoName),
  };
  return app;
}

function pickActionSet(index) {
  const first = forgejoActions[index % forgejoActions.length];
  const second = forgejoActions[(index + 2) % forgejoActions.length];
  return [...new Set(['actions/checkout@v4', first, second, 'aquasecurity/trivy-action@master'])];
}

function repoFilesFor(app) {
  const files = {
    'README.md': [
      `# ${app.appName}`,
      '',
      'Fake vulnerable application generated for AVRC testing.',
      '',
      `Environment: ${app.environment}`,
      `Runtime: ${app.runtime}`,
      `Installed path: ${app.installedPath}`,
    ].join('\n'),
    'Dockerfile': dockerfileFor(app),
    '.forgejo/workflows/build.yml': workflowFor(app),
    'avrc-application.json': JSON.stringify(app, null, 2),
  };

  if (app.runtime.startsWith('node')) {
    files['package.json'] = JSON.stringify({
      name: app.appName,
      version: '1.0.0',
      private: true,
      scripts: {
        start: 'node src/index.js',
        test: 'node --check src/index.js',
      },
      dependencies: {
        express: '4.16.0',
        lodash: '4.17.11',
        moment: '2.19.3',
      },
    }, null, 2);
    files['src/index.js'] = "const express = require('express');\nconst app = express();\napp.get('/health', (_req, res) => res.json({ ok: true }));\napp.listen(process.env.PORT || 8080);\n";
  } else if (app.runtime.startsWith('java')) {
    files['pom.xml'] = pomFor(app);
    files['src/main/java/com/avrc/App.java'] = 'package com.avrc;\npublic class App { public static void main(String[] args) { System.out.println("AVRC fake app"); } }\n';
  } else if (app.runtime.startsWith('python')) {
    files['requirements.txt'] = 'fastapi==0.65.0\nuvicorn==0.13.4\nJinja2==2.10\nPyYAML==5.3.1\n';
    files['app/main.py'] = "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/health')\ndef health():\n    return {'ok': True}\n";
  } else if (app.runtime.startsWith('go')) {
    files['go.mod'] = `module forgejo.local/${app.repository.owner}/${app.repository.name}\n\ngo 1.17\n\nrequire github.com/gin-gonic/gin v1.6.3\n`;
    files['main.go'] = 'package main\nimport "fmt"\nfunc main() { fmt.Println("AVRC fake app") }\n';
  } else if (app.runtime.startsWith('dotnet')) {
    files[`${app.appName}.csproj`] = '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net6.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>\n';
    files['Program.cs'] = 'var builder = WebApplication.CreateBuilder(args);\nvar app = builder.Build();\napp.MapGet("/health", () => "ok");\napp.Run();\n';
  } else {
    files['public/index.html'] = `<h1>${app.appName}</h1>\n`;
    files['nginx.conf'] = 'server { listen 8080; root /usr/share/nginx/html; }\n';
  }

  return files;
}

function dockerfileFor(app) {
  return [
    `FROM ${app.imageBase}`,
    'WORKDIR /app',
    'COPY . .',
    'RUN echo "fake vulnerable build image for AVRC"',
    'CMD ["sh", "-c", "sleep 3600"]',
  ].join('\n');
}

function workflowFor(app) {
  return [
    'name: build',
    'on: [push, pull_request]',
    'jobs:',
    '  build:',
    '    runs-on: ubuntu-latest',
    `    container: ${app.ciCdPipeline.runnerImage}`,
    '    steps:',
    ...app.forgejoActions.map((action) => `      - uses: ${action}`),
    '      - name: Build',
    '        run: |',
    '          echo "building fake app"',
    '          echo "vulnerable CI image is intentional test data"',
  ].join('\n');
}

function pomFor(app) {
  return [
    '<project xmlns="http://maven.apache.org/POM/4.0.0">',
    '  <modelVersion>4.0.0</modelVersion>',
    '  <groupId>com.avrc.fake</groupId>',
    `  <artifactId>${app.appName}</artifactId>`,
    '  <version>1.0.0</version>',
    '  <dependencies>',
    '    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>',
    '    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.9.9</version></dependency>',
    '  </dependencies>',
    '</project>',
  ].join('\n');
}

function csvEscape(value) {
  const text = Array.isArray(value) || typeof value === 'object' ? JSON.stringify(value) : String(value ?? '');
  return `"${text.replaceAll('"', '""')}"`;
}

async function writeInventory(apps) {
  await mkdir(dataDir, { recursive: true });
  await writeFile(resolve(dataDir, 'fake-applications.json'), JSON.stringify(apps, null, 2), 'utf-8');
  const headers = [
    'appId',
    'appName',
    'environment',
    'severity',
    'runtime',
    'installedPath',
    'jarFiles',
    'ciCdPipeline',
    'forgejoActions',
    'repo',
    'image',
    'vulnerabilities',
  ];
  const rows = apps.map((app) => [
    app.appId,
    app.appName,
    app.environment,
    app.severity,
    app.runtime,
    app.installedPath,
    app.jarFiles,
    app.ciCdPipeline,
    app.forgejoActions,
    app.repository.cloneUrl,
    app.image,
    app.vulnerabilities,
  ].map(csvEscape).join(','));
  await writeFile(resolve(dataDir, 'fake-applications.csv'), `${headers.join(',')}\n${rows.join('\n')}\n`, 'utf-8');
}

async function writeLocalRepoTemplates(apps) {
  for (const app of apps) {
    const repoDir = resolve(outputDir, app.repository.name);
    await mkdir(repoDir, { recursive: true });
    const files = repoFilesFor(app);
    for (const [filePath, content] of Object.entries(files)) {
      const fullPath = resolve(repoDir, filePath);
      await mkdir(resolve(fullPath, '..'), { recursive: true });
      await writeFile(fullPath, content, 'utf-8');
    }
  }
}

async function forgeRequest(baseUrl, token, path, { method = 'GET', body } = {}) {
  const response = await fetch(`${baseUrl.replace(/\/$/, '')}/api/v1${path}`, {
    method,
    headers: {
      accept: 'application/json',
      authorization: `token ${token}`,
      'content-type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) {
    const error = new Error(`Forgejo API ${response.status}`);
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

async function ensureRepo(baseUrl, token, owner, app) {
  const repoName = app.repository.name;
  try {
    await forgeRequest(baseUrl, token, `/repos/${owner}/${repoName}`);
    return { created: false };
  } catch (error) {
    if (error.status !== 404) throw error;
  }

  await forgeRequest(baseUrl, token, '/user/repos', {
    method: 'POST',
    body: {
      name: repoName,
      private: false,
      auto_init: true,
      default_branch: 'main',
      description: `Fake vulnerable AVRC repo for ${app.appName}`,
    },
  });
  return { created: true };
}

async function upsertFile(baseUrl, token, owner, repoName, branch, filePath, content, message) {
  const encodedPath = filePath.split('/').map(encodeURIComponent).join('/');
  let sha = null;
  try {
    const current = await forgeRequest(baseUrl, token, `/repos/${owner}/${repoName}/contents/${encodedPath}?ref=${encodeURIComponent(branch)}`);
    sha = current.sha;
  } catch (error) {
    if (error.status !== 404) throw error;
  }

  const body = {
    branch,
    content: Buffer.from(content, 'utf-8').toString('base64'),
    message,
    author: {
      name: process.env.GIT_AUTHOR_NAME || 'AVRC Seeder',
      email: process.env.GIT_AUTHOR_EMAIL || 'avrc-seeder@example.local',
    },
    committer: {
      name: process.env.GIT_AUTHOR_NAME || 'AVRC Seeder',
      email: process.env.GIT_AUTHOR_EMAIL || 'avrc-seeder@example.local',
    },
  };
  if (sha) {
    body.sha = sha;
  }

  await forgeRequest(baseUrl, token, `/repos/${owner}/${repoName}/contents/${encodedPath}`, {
    method: sha ? 'PUT' : 'POST',
    body,
  });
}

async function seedForgejo(apps, { baseUrl, token, owner, concurrency }) {
  if (!token) throw new Error('FORGEJO_TOKEN is required for --forgejo');
  const user = await forgeRequest(baseUrl, token, '/user');
  const repoOwner = owner || user.login || user.username;
  const queue = [...apps];
  let created = 0;
  let updated = 0;
  let failed = 0;

  async function worker(workerId) {
    while (queue.length) {
      const app = queue.shift();
      try {
        app.repository.owner = repoOwner;
        Object.assign(app.repository, cloneUrls(baseUrl, repoOwner, app.repository.name));
        const repoResult = await ensureRepo(baseUrl, token, repoOwner, app);
        created += repoResult.created ? 1 : 0;
        updated += repoResult.created ? 0 : 1;
        const files = repoFilesFor(app);
        for (const [filePath, content] of Object.entries(files)) {
          await upsertFile(baseUrl, token, repoOwner, app.repository.name, 'main', filePath, content, `seed ${app.appName}: ${filePath}`);
        }
        if ((created + updated + failed) % 25 === 0) {
          console.log(`Seeded ${created + updated + failed}/${apps.length} repos`);
        }
      } catch (error) {
        failed += 1;
        console.error(`worker ${workerId}: failed ${app.repository.name}: ${error.message}`);
      }
    }
  }

  await Promise.all(Array.from({ length: concurrency }, (_, index) => worker(index + 1)));
  return { owner: repoOwner, created, updated, failed };
}

async function main() {
  await loadEnv();
  const args = parseArgs();
  const count = Number(args.get('count') || 1000);
  const baseUrl = String(args.get('forgejo-url') || process.env.FORGEJO_BASE_URL || 'http://localhost:3001');
  const token = String(args.get('token') || process.env.FORGEJO_TOKEN || '');
  const requestedOwner = args.get('owner') ? String(args.get('owner')) : null;
  const concurrency = Number(args.get('concurrency') || 4);
  const ownerForInventory = requestedOwner || process.env.FORGEJO_OWNER || 'tejdeep';
  const shouldSeedForgejo = Boolean(args.get('forgejo'));
  const shouldWriteLocalRepos = Boolean(args.get('local-repos'));

  const apps = Array.from({ length: count }, (_, index) => generateApplication(index, ownerForInventory, baseUrl));
  await writeInventory(apps);

  if (shouldWriteLocalRepos) {
    await writeLocalRepoTemplates(apps);
  }

  let forgejo = null;
  if (shouldSeedForgejo) {
    forgejo = await seedForgejo(apps, { baseUrl, token, owner: requestedOwner, concurrency });
    for (const app of apps) {
      app.repository.owner = forgejo.owner;
      Object.assign(app.repository, cloneUrls(baseUrl, forgejo.owner, app.repository.name));
    }
    await writeInventory(apps);
  }

  const summary = {
    generatedAt: new Date().toISOString(),
    count: apps.length,
    inventoryJson: resolve(dataDir, 'fake-applications.json'),
    inventoryCsv: resolve(dataDir, 'fake-applications.csv'),
    localRepos: shouldWriteLocalRepos ? outputDir : null,
    forgejo,
    byEnvironment: Object.fromEntries(environments.map((env) => [env, apps.filter((app) => app.environment === env).length])),
    byRuntime: Object.fromEntries(runtimes.map((runtime) => [runtime, apps.filter((app) => app.runtime === runtime).length])),
  };
  await writeFile(resolve(dataDir, 'seed-summary.json'), JSON.stringify(summary, null, 2), 'utf-8');
  console.log(JSON.stringify(summary, null, 2));
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
