import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, resolve } from 'node:path';
import { AgentRunner } from './core/agent_runner.js';
import { getRootDir, loadConfig } from './core/config_loader.js';
import { listTools } from './tools/tool_registry.js';
import { AgentRequest } from './types.js';

const config = loadConfig();
const runner = new AgentRunner();
const rootDir = getRootDir();

const contentTypes = new Map<string, string>([
  ['.html', 'text/html; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
]);

function sendJson(res: ServerResponse, statusCode: number, payload: unknown): void {
  res.writeHead(statusCode, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  const raw = Buffer.concat(chunks).toString('utf-8');
  return raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
}

async function sendStatic(res: ServerResponse, filePath: string): Promise<void> {
  const content = await readFile(filePath);
  res.writeHead(200, {
    'content-type': contentTypes.get(extname(filePath)) ?? 'application/octet-stream',
  });
  res.end(content);
}

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);

  if (req.method === 'GET' && url.pathname === '/') {
    await sendStatic(res, resolve(rootDir, 'src', 'index.html'));
    return;
  }

  if (req.method === 'GET' && url.pathname.startsWith('/static/')) {
    await sendStatic(res, resolve(rootDir, 'src', url.pathname.replace('/static/', '')));
    return;
  }

  if (req.method === 'GET' && url.pathname === '/health') {
    sendJson(res, 200, { status: 'ok', app: config.app.name });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/agents') {
    sendJson(res, 200, { agents: config.agents });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/tools') {
    sendJson(res, 200, { tools: listTools() });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/chat') {
    const body = (await readBody(req)) as Partial<AgentRequest>;
    if (!body.prompt) {
      sendJson(res, 400, { status: 'error', message: 'prompt is required' });
      return;
    }

    const result = await runner.run({
      prompt: body.prompt,
      target: body.target,
      environment: body.environment ?? 'development',
      severity: body.severity,
      approved: body.approved,
    });
    sendJson(res, 200, result);
    return;
  }

  sendJson(res, 404, { status: 'error', message: 'Not found' });
}

createServer((req, res) => {
  handleRequest(req, res).catch((error) => {
    sendJson(res, 500, {
      status: 'error',
      message: error instanceof Error ? error.message : 'Unknown server error',
    });
  });
}).listen(config.app.port, () => {
  console.log(`${config.app.name} listening on http://localhost:${config.app.port}`);
});
