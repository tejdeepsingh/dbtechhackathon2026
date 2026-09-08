import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
const derive = promisify(scrypt);
const lifetime = 8 * 60 * 60 * 1000;
export const roles = {
  administrator: { label: 'Administrator', scan: true, approve: true, manageModels: true },
  analyst: { label: 'Analyst', scan: true, approve: false, manageModels: false },
  auditor: { label: 'Auditor', scan: false, approve: false, manageModels: false },
};
export function canAccess(role, method, path) {
  if (!roles[role]) return false;
  if (method === 'GET') return true;
  if (method !== 'POST') return false;
  if (path === '/auth/logout') return true;
  if (['/chat', '/chat/stream'].includes(path)) return roles[role].scan;
  if (path === '/chat/remediate') return roles[role].approve;
  if (['/llm/test', '/llm/unload'].includes(path)) return roles[role].manageModels;
  return false;
}
export function createAuth(users, { secure = false } = {}) {
  const sessions = new Map();
  const attempts = new Map();
  function prune() {
    const now = Date.now();
    for (const [id, session] of sessions) if (session.expires <= now) sessions.delete(id);
    for (const [id, attempt] of attempts) if (attempt.until <= now) attempts.delete(id);
  }
  const cookie = (token, age) => `qcs_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${age}${secure ? '; Secure' : ''}`;
  function token(req) { return (req.headers.cookie || '').split(';').map((v) => v.trim()).find((v) => v.startsWith('qcs_session='))?.slice(12); }
  function current(req) { prune(); return sessions.get(token(req))?.user; }
  async function login(username, password, address) {
    prune();
    if (typeof username !== 'string' || typeof password !== 'string' || username.length > 100 || password.length > 200) return null;
    const key = `${address}:${username.toLowerCase()}`;
    const attempt = attempts.get(key) || { count: 0, until: Date.now() + 60000 };
    if (attempt.count >= 8) return { limited: true };
    if (attempts.size > 10000) return { limited: true };
    attempt.count++; attempts.set(key, attempt);
    const account = users.find((u) => u.username === username.toLowerCase());
    const hash = await derive(password, account?.salt || 'invalid-account-salt', 64);
    const expected = account ? Buffer.from(account.passwordHash, 'hex') : Buffer.alloc(64);
    if (!timingSafeEqual(hash, expected) || !account || !roles[account.role]) return null;
    attempts.delete(key);
    const user = { username: account.username, role: account.role, ...roles[account.role] };
    const id = randomBytes(32).toString('hex');
    sessions.set(id, { user, expires: Date.now() + lifetime });
    return { user, cookie: cookie(id, lifetime / 1000) };
  }
  function logout(req) { sessions.delete(token(req)); return cookie('', 0); }
  return { current, login, logout };
}
