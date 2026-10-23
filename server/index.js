// LeakLock checker server: serves the checker page and one scan API.
// Stores nothing. Returns masked keys only. Rate-limited so it cannot be used to harvest keys.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, dirname, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanUrl } from '../src/scan-url.js';

const PORT = Number(process.env.PORT) || 8080;
const PUBLIC = join(dirname(fileURLToPath(import.meta.url)), '..', 'public');
const PER_IP_PER_HOUR = Number(process.env.RATE_LIMIT || 12);
const MAX_CONCURRENT = Number(process.env.MAX_CONCURRENT || 4);
const CACHE_MS = 10 * 60 * 1000;

const hits = new Map(); // ip -> [timestamps]
const cache = new Map(); // normalized url -> { at, result }
let running = 0;
let totalScans = 0;

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.txt': 'text/plain', '.woff2': 'font/woff2', '.webp': 'image/webp' };
const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
  'content-security-policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
};

function ipOf(req) {
  // Behind Railway's proxy the real client is the last hop it appended; the first entry can be forged.
  const xff = (req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
  return req.headers['x-real-ip'] || xff[xff.length - 1] || req.socket.remoteAddress || '?';
}

function limited(ip) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter((t) => now - t < 3600_000);
  if (list.length >= PER_IP_PER_HOUR) { hits.set(ip, list); return true; }
  list.push(now);
  hits.set(ip, list);
  return false;
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of cache) if (now - v.at > CACHE_MS) cache.delete(k);
  for (const [k, v] of hits) if (!v.some((t) => now - t < 3600_000)) hits.delete(k);
}, 60_000).unref();

function send(res, status, body, headers = {}) {
  const isJson = typeof body !== 'string' && !Buffer.isBuffer(body);
  res.writeHead(status, { ...SECURITY_HEADERS, 'content-type': isJson ? 'application/json' : 'text/plain', ...headers });
  res.end(isJson ? JSON.stringify(body) : body);
}

async function handleScan(req, res, url) {
  const target = (url.searchParams.get('url') || '').trim();
  if (!target || target.length > 500) return send(res, 400, { error: 'Paste a website address, like yourapp.com' });
  const key = target.toLowerCase().replace(/^https?:\/\//, '').replace(/\/+$/, '');
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < CACHE_MS) return send(res, 200, { ...hit.result, cached: true });
  if (limited(ipOf(req))) return send(res, 429, { error: 'Too many scans from your network. Try again in an hour, or run it yourself: npx leaklock scan <url>' });
  if (running >= MAX_CONCURRENT) return send(res, 503, { error: 'The checker is busy. Try again in a few seconds.' });
  running++;
  try {
    const result = await scanUrl(target, { maxFiles: 50 });
    totalScans++;
    cache.set(key, { at: Date.now(), result });
    send(res, 200, result);
  } catch (e) {
    send(res, 422, { error: e.message || 'Could not scan that site.' });
  } finally {
    running--;
  }
}

async function handleStatic(res, path) {
  if (path === '/') path = '/index.html';
  if (path.includes('..')) return send(res, 400, 'Bad path');
  try {
    const body = await readFile(join(PUBLIC, path));
    send(res, 200, body, { 'content-type': TYPES[extname(path)] || 'application/octet-stream', 'cache-control': (path.startsWith('/fonts/') || path.endsWith('.webp')) ? 'public, max-age=31536000, immutable' : 'public, max-age=300' });
  } catch {
    send(res, 404, 'Not found');
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed');
  if (url.pathname === '/api/scan') return handleScan(req, res, url);
  if (url.pathname === '/healthz') return send(res, 200, { ok: true, running, totalScans });
  return handleStatic(res, url.pathname);
});

server.listen(PORT, () => console.log(`LeakLock checker on http://localhost:${PORT}`));
