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

createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);

  if (req.method === 'GET' && url.pathname === '/health') {
    sendJson(res, 200, {
      status: 'ok',
      tool: toolName,
    });
    return;
  }

  if (req.method === 'POST') {
    sendJson(res, 200, {
      status: 'success',
      tool: toolName,
      path: url.pathname,
      received: await readBody(req),
      data: {
        mock: true,
        findings: [
          {
            cve: 'CVE-2024-12345',
            severity: 'high',
            package: 'demo-package',
          },
        ],
      },
    });
    return;
  }

  sendJson(res, 404, {
    status: 'error',
    tool: toolName,
    message: 'Route not found',
  });
}).listen(port, () => {
  console.log(`${toolName} listening on 0.0.0.0:${port}`);
});
