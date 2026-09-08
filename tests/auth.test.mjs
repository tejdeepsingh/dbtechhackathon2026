import test from 'node:test';
import assert from 'node:assert/strict';
import { scryptSync } from 'node:crypto';
import { mkdtemp, writeFile, rm, rmdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { createAuth, canAccess } from '../src/auth.mjs';
import { MainAgent } from '../src/agents/main_agent.mjs';

const password = 'Test-only-password!';
const users = ['administrator', 'analyst', 'auditor'].map((role) => ({ username: role, role, salt: 'test-fixture-salt', passwordHash: scryptSync(password, 'test-fixture-salt', 64).toString('hex') }));

test('role permission matrix rejects privilege escalation and unknown writes', () => {
  assert.equal(canAccess('auditor', 'POST', '/chat'), false);
  assert.equal(canAccess('analyst', 'POST', '/chat'), true);
  for (const route of ['/chat/remediate', '/llm/test', '/llm/unload']) {
    assert.equal(canAccess('analyst', 'POST', route), false);
    assert.equal(canAccess('administrator', 'POST', route), true);
  }
  assert.equal(canAccess('administrator', 'DELETE', '/tools'), false);
  assert.equal(canAccess('administrator', 'POST', '/unknown'), false);
  assert.equal(canAccess('forged-role', 'GET', '/tools'), false);
});

test('password verification, secure cookie, token tampering and logout', async () => {
  const auth = createAuth(users, { secure: true });
  assert.equal(await auth.login('administrator', 'incorrect', 'test'), null);
  assert.equal(await auth.login('unknown', password, 'test'), null);
  const result = await auth.login('administrator', password, 'test');
  assert.match(result.cookie, /HttpOnly; SameSite=Strict/);
  assert.match(result.cookie, /; Secure$/);
  const req = { headers: { cookie: result.cookie.split(';')[0] } };
  assert.equal(auth.current(req).role, 'administrator');
  assert.equal(auth.current({ headers: { cookie: 'qcs_session=forged' } }), undefined);
  auth.logout(req);
  assert.equal(auth.current(req), undefined);
});

test('failed logins are rate limited', async () => {
  const auth = createAuth(users);
  for (let i = 0; i < 8; i++) assert.equal(await auth.login('analyst', 'bad', 'test'), null);
  assert.equal((await auth.login('analyst', password, 'test')).limited, true);
});

test('scan-only requests never invoke remediation tools', async () => {
  const config = JSON.parse(await readFile(new URL('../config/config.json', import.meta.url)));
  const agent = new MainAgent({ config, rootDir: resolve('.') });
  const calls = [];
  agent.executeTool = async (tool, operation) => { calls.push({ tool, operation }); return { status: 'success', data: { findings: [] } }; };
  const result = await agent.handle({ prompt: 'Scan repository', repo: 'https://example.com/repo', readOnly: true, approved: true });
  assert.equal(result.status, 'success');
  assert(calls.length > 0);
  assert(!calls.some((call) => /remediat|git_ops|notification|audit_logger|verification/.test(call.tool)));
  calls.length = 0;
  const blocked = await agent.handle({ prompt: 'Use renovate to fix dependencies', readOnly: true, approved: true });
  assert.equal(blocked.status, 'blocked');
  assert.equal(calls.length, 0);
});

test('HTTP authentication and role enforcement', { timeout: 30000 }, async () => {
  const folder = await mkdtemp(join(tmpdir(), 'qcs-auth-test-'));
  const file = join(folder, 'users.json');
  await writeFile(file, JSON.stringify(users));
  const probe = createServer(); probe.listen(0, '127.0.0.1'); await once(probe, 'listening');
  const port = probe.address().port; await new Promise((done) => probe.close(done));
  const server = spawn(process.execPath, ['src/server.mjs'], { env: { ...process.env, PORT: String(port), QCS_DEMO_USERS_FILE: file, K_SERVICE: '' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let logs = ''; server.stdout.on('data', (chunk) => { logs += chunk; }); server.stderr.on('data', (chunk) => { logs += chunk; });
  const base = `http://127.0.0.1:${port}`;
  const request = (path, opts = {}) => fetch(base + path, { redirect: 'manual', ...opts });
  const post = (path, cookie, body = {}, headers = {}) => request(path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-QCS-Request': '1', cookie, ...headers }, body: JSON.stringify(body) });
  try {
    for (let i = 0; i < 100 && !logs.includes('listening on'); i++) await new Promise((done) => setTimeout(done, 50));
    assert.match(logs, /listening on/);
    assert.equal((await request('/')).status, 303);
    assert.equal((await request('/admin')).headers.get('location'), '/login');
    assert.equal((await request('/tools')).status, 401);
    assert.equal((await request('/login')).status, 200);
    assert.equal((await request('/health')).status, 200);
    for (const path of ['/static/server.mjs', '/static/auth.mjs', '/static/../config/demo-users.json']) assert.notEqual((await request(path)).status, 200);
    assert.equal((await post('/auth/login', '', { username: 'analyst', password: 'bad' })).status, 401);
    for (const user of users) {
      const login = await post('/auth/login', '', { username: user.username, password });
      assert.equal(login.status, 200);
      const cookie = login.headers.get('set-cookie').split(';')[0];
      const me = await request('/auth/me', { headers: { cookie } });
      const payload = await me.json(); assert.equal(payload.user.role, user.role);
      assert.equal(payload.user.passwordHash, undefined);
      assert.equal((await request('/admin', { headers: { cookie } })).status, 200);
      assert.equal((await post('/chat', cookie, { prompt: '', approved: true, readOnly: false })).status, user.role === 'auditor' ? 403 : 400);
      if (user.role !== 'administrator') {
        assert.equal((await post('/chat/remediate', cookie)).status, 403);
        assert.equal((await post('/llm/unload', cookie)).status, 403);
      }
      assert.equal((await post('/auth/logout', cookie, {}, { Origin: 'https://outside.example' })).status, 403);
      assert.equal((await post('/auth/logout', cookie, {}, { 'X-QCS-Request': '' })).status, 403);
      assert.equal((await post('/auth/logout', cookie)).status, 200);
      assert.equal((await request('/auth/me', { headers: { cookie } })).status, 401);
    }
  } finally {
    server.kill(); await once(server, 'exit');
    await rm(file); await rmdir(folder);
  }
});
