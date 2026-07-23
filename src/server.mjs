import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, extname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MainAgent } from './agents/main_agent.mjs';

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const config = JSON.parse(await readFile(resolve(rootDir, 'config', 'config.json'), 'utf-8'));
const mainAgent = new MainAgent({ config, rootDir });

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

  if (req.method === 'POST' && url.pathname === '/chat') {
    const request = await body(req);
    if (!request.prompt) {
      json(res, 400, { status: 'error', message: 'prompt is required' });
      return;
    }
    json(res, 200, await mainAgent.handle(request));
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
      message: 'Streaming AVRC agent progress.',
      timestamp: new Date().toISOString(),
    });

    const result = await mainAgent.handle(request, {
      onProgress: (event) => sse(res, event.type ?? 'progress', event),
    });

    sse(res, 'final', result);
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
