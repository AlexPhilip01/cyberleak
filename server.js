// Local server: serves the web app and the same API routes the Vercel functions provide.
// Zero dependencies. Requires Node.js 18+ (built-in fetch). On Vercel, api/*.js is used instead.
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');

// Tiny .env loader (no dotenv dependency)
try {
  for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
} catch { /* no .env file */ }

const api = require('./lib/hibp');
const PORT = Number(process.env.PORT) || 3000;
const PAGE = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
const CSP = JSON.parse(fs.readFileSync(path.join(__dirname, 'vercel.json'), 'utf8'))
  .headers[0].headers.find(h => h.key === 'Content-Security-Policy').value;

http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  if (req.method !== 'GET') { res.statusCode = 405; return res.end(); }

  if (url.pathname === '/' || url.pathname === '/index.html') {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.end(PAGE);
  }
  const ICONS = { '/favicon.ico': 'image/x-icon', '/favicon.png': 'image/png', '/apple-touch-icon.png': 'image/png' };
  if (ICONS[url.pathname]) {
    res.setHeader('Content-Type', ICONS[url.pathname]);
    return res.end(fs.readFileSync(path.join(__dirname, 'public', url.pathname)));
  }
  if (url.pathname === '/api/health') return api.respond(res, () => api.health(), 'health');
  if (url.pathname === '/api/breaches') return api.respond(res, () => api.breaches(), 'breaches');
  if (url.pathname === '/api/email')
    return api.respond(res, () => api.email(url.searchParams.get('account'), api.clientIp(req)), 'email');
  if (url.pathname === '/api/xon')
    return api.respond(res, () => api.xon(url.searchParams.get('account'), api.clientIp(req)), 'xon');
  if (url.pathname === '/api/leakcheck')
    return api.respond(res, () => api.leakcheck(url.searchParams.get('account'), api.clientIp(req)), 'leakcheck');
  const m = url.pathname.match(/^\/api\/range\/([^/]+)$/);
  if (m) return api.respond(res, () => api.range(m[1]), 'range');

  res.statusCode = 404;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify({ error: 'Not found.' }));
}).listen(PORT, () => {
  console.log(`CyberLeak running at http://localhost:${PORT}`);
  console.log(process.env.HIBP_API_KEY ? 'Email lookups: enabled' : 'Email lookups: free sources (XposedOrNot + LeakCheck). Set HIBP_API_KEY to use HIBP instead.');
});
