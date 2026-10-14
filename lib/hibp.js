// Shared API logic for both the local server (server.js) and Vercel functions (api/*.js).
// Each handler returns { status, body, type?, headers? }.
'use strict';

const HIBP = 'https://haveibeenpwned.com/api/v3';
const PWNED_PASSWORDS = 'https://api.pwnedpasswords.com/range/';
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/;

const apiKey = () => process.env.HIBP_API_KEY || '';
const userAgent = () => process.env.USER_AGENT || 'CyberLeak/1.0 (self-hosted breach checker)';
const limitPerMin = () => Number(process.env.EMAIL_LIMIT_PER_MIN) || 10;

// Per-IP rate limit for email lookups. In-memory: exact on one server,
// best-effort on serverless (each warm instance keeps its own counts).
const hits = new Map();
function allowed(ip) {
  const now = Date.now();
  if (hits.size > 5000) for (const [k, ts] of hits) if (!ts.some(t => now - t < 60_000)) hits.delete(k);
  const recent = (hits.get(ip) || []).filter(t => now - t < 60_000);
  if (recent.length >= limitPerMin()) { hits.set(ip, recent); return false; }
  recent.push(now); hits.set(ip, recent); return true;
}

let catalogue = { data: null, at: 0 };

async function health() {
  return { status: 200, body: { ok: true, emailLookup: true, emailSource: apiKey() ? 'hibp' : 'xon' }, headers: { 'Cache-Control': 'no-store' } };
}

// k-anonymity: only a 5-hex-char SHA-1 prefix ever arrives here.
async function range(prefix) {
  if (!/^[0-9A-Fa-f]{5}$/.test(prefix || '')) return { status: 400, body: { error: 'Expected a 5-character hash prefix.' } };
  const r = await fetch(PWNED_PASSWORDS + prefix.toUpperCase(), {
    headers: { 'User-Agent': userAgent(), 'Add-Padding': 'true' },
  });
  if (!r.ok) return { status: 502, body: { error: 'The password service did not respond.' } };
  return { status: 200, body: await r.text(), type: 'text/plain; charset=utf-8', headers: { 'Cache-Control': 'public, max-age=86400, s-maxage=86400' } };
}

async function breaches() {
  if (!catalogue.data || Date.now() - catalogue.at > 6 * 3600_000) {
    const r = await fetch(`${HIBP}/breaches`, { headers: { 'User-Agent': userAgent() } });
    if (!r.ok) return { status: 502, body: { error: `The breach catalogue is unavailable (${r.status}).` } };
    catalogue = { data: await r.json(), at: Date.now() };
  }
  return { status: 200, body: catalogue.data, headers: { 'Cache-Control': 'public, max-age=3600, s-maxage=21600' } };
}

async function email(account, ip) {
  if (!apiKey()) return { status: 503, body: { error: 'Email lookups are not configured. Set HIBP_API_KEY on the server.' } };
  account = (account || '').trim();
  if (account.length > 254 || !EMAIL_RE.test(account)) return { status: 400, body: { error: 'That does not look like an email address.' } };
  if (!allowed(ip || 'unknown')) return { status: 429, body: { error: 'Too many lookups. Wait a minute and try again.' }, headers: { 'Retry-After': '60' } };

  const r = await fetch(`${HIBP}/breachedaccount/${encodeURIComponent(account)}?truncateResponse=false`, {
    headers: { 'User-Agent': userAgent(), 'hibp-api-key': apiKey() },
  });
  const noStore = { 'Cache-Control': 'no-store' };
  if (r.status === 404) return { status: 200, body: { breaches: [] }, headers: noStore };
  if (r.status === 429) return { status: 429, body: { error: 'The breach service is busy. Try again in a few seconds.' }, headers: { 'Retry-After': r.headers.get('retry-after') || '5' } };
  if (r.status === 401 || r.status === 403) return { status: 502, body: { error: 'The server’s API key was rejected. Check HIBP_API_KEY.' } };
  if (!r.ok) return { status: 502, body: { error: `The breach service returned an error (${r.status}).` } };
  return { status: 200, body: { breaches: await r.json() }, headers: noStore };
}

function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || (req.socket && req.socket.remoteAddress) || 'unknown';
}

// Adapter: run a handler and write its result to a Node response (works for Vercel and http).
async function respond(res, work, label) {
  try {
    const out = await work();
    const type = out.type || 'application/json; charset=utf-8';
    res.statusCode = out.status;
    res.setHeader('Content-Type', type);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    for (const [k, v] of Object.entries(out.headers || {})) res.setHeader(k, v);
    res.end(typeof out.body === 'string' ? out.body : JSON.stringify(out.body));
  } catch (err) {
    // Never log email addresses or query strings.
    console.error(`[error] ${label}: ${err.message}`);
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({ error: 'Something went wrong on the server. Try again shortly.' }));
    }
  }
}

// Free fallback when no HIBP key is set: XposedOrNot breach analytics (no key needed).
// The browser calls XposedOrNot directly; this route is only used if that call is blocked.
async function xon(account, ip) {
  account = (account || '').trim();
  if (account.length > 254 || !EMAIL_RE.test(account)) return { status: 400, body: { error: 'That does not look like an email address.' } };
  if (!allowed(ip || 'unknown')) return { status: 429, body: { error: 'Too many lookups. Wait a minute and try again.' }, headers: { 'Retry-After': '60' } };
  const r = await fetch('https://api.xposedornot.com/v1/breach-analytics?email=' + encodeURIComponent(account), { headers: { 'User-Agent': userAgent() } });
  const noStore = { 'Cache-Control': 'no-store' };
  if (r.status === 404) return { status: 404, body: { breaches: [] }, headers: noStore };
  if (r.status === 429) return { status: 429, body: { error: 'The free lookup limit has been reached. Try again later.' } };
  if (!r.ok) return { status: 502, body: { error: `The free breach service returned an error (${r.status}).` } };
  return { status: 200, body: await r.text(), headers: noStore };
}

module.exports = { xon, health, range, breaches, email, clientIp, respond };
