import { withFixes } from './fix.js';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { scanText, mergeFindings, summarize } from './detect.js';

const DEFAULTS = {
  maxFiles: 60,
  maxFileBytes: 15 * 1024 * 1024,
  maxTotalBytes: 80 * 1024 * 1024,
  timeoutMs: 12000,
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 LeakLock/0.1 (+https://github.com/sgroy10/leaklock)',
  allowPrivate: false,
};

function isPrivateIp(ip) {
  if (isIP(ip) === 6) {
    const v = ip.toLowerCase();
    if (v === '::1' || v === '::' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80')) return true;
    const mapped = v.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    return mapped ? isPrivateIp(mapped[1]) : false;
  }
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
}

async function assertPublicUrl(u, opts) {
  if (!/^https?:$/.test(u.protocol)) throw new Error('Only http and https URLs can be scanned.');
  if (u.username || u.password) throw new Error('URLs with credentials are not allowed.');
  if (!opts.allowAnyPort && u.port && !['80', '443'].includes(u.port)) throw new Error('Only ports 80 and 443 are allowed.');
  if (opts.allowPrivate) return;
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal')) throw new Error('Private addresses cannot be scanned.');
  const addrs = isIP(host) ? [{ address: host }] : await lookup(host, { all: true });
  if (addrs.some((a) => isPrivateIp(a.address))) throw new Error('Private addresses cannot be scanned.');
}

async function get(url, opts, budget) {
  let u = new URL(url);
  for (let hop = 0; hop < 5; hop++) {
    await assertPublicUrl(u, opts);
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), opts.timeoutMs);
    let res;
    try {
      res = await fetch(u, { redirect: 'manual', signal: ctrl.signal, headers: { 'user-agent': opts.userAgent, accept: '*/*' } });
    } finally {
      clearTimeout(t);
    }
    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
      u = new URL(res.headers.get('location'), u);
      continue;
    }
    if (!res.ok) return { url: u.href, status: res.status, text: null };
    // Read with a size cap.
    const reader = res.body.getReader();
    const chunks = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > opts.maxFileBytes || budget.bytes + size > opts.maxTotalBytes) {
        reader.cancel();
        return { url: u.href, status: res.status, text: null, truncated: true };
      }
      chunks.push(value);
    }
    budget.bytes += size;
    return { url: u.href, status: res.status, type: res.headers.get('content-type') || '', text: Buffer.concat(chunks).toString('utf8') };
  }
  throw new Error('Too many redirects.');
}

// Second-level labels used under country TLDs (example.co.in, example.com.au, example.co.uk).
const SLD = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'ltd', 'plc', 'nic', 'gen', 'firm', 'ind', 'res', 'ne', 'or', 'go']);
// Shared hosting suffixes: each subdomain is a different owner.
const SHARED = /\.(lovable\.app|lovableproject\.com|bolt\.host|netlify\.app|vercel\.app|pages\.dev|workers\.dev|github\.io|web\.app|firebaseapp\.com|up\.railway\.app|onrender\.com|herokuapp\.com|replit\.app|repl\.co|glitch\.me|surge\.sh|framer\.website|webflow\.io|wixsite\.com|azurewebsites\.net|amplifyapp\.com|fly\.dev|deno\.dev|stackblitz\.io|v0\.dev|vusercontent\.net)$/i;

/** The domain a site owner controls: myapp.lovable.app, shop.example.co.in -> example.co.in. */
export function registrableDomain(host) {
  host = host.toLowerCase().replace(/\.$/, '');
  if (isIP(host)) return host;
  if (SHARED.test(host)) return host;
  const p = host.split('.');
  if (p.length <= 2) return host;
  const n = p.length;
  return SLD.has(p[n - 2]) && p[n - 1].length === 2 ? p.slice(-3).join('.') : p.slice(-2).join('.');
}

// Third-party scripts a site embeds; any keys inside belong to the vendor, not the site.
const THIRD_PARTY = /(^|\.)(google-analytics\.com|googletagmanager\.com|googlesyndication\.com|doubleclick\.net|gstatic\.com|google\.com|recaptcha\.net|facebook\.net|connect\.facebook\.net|hotjar\.com|clarity\.ms|segment\.com|segment\.io|mixpanel\.com|amplitude\.com|intercom\.io|intercomcdn\.com|crisp\.chat|tawk\.to|hubspot\.com|hs-scripts\.com|hsforms\.net|stripe\.com|js\.stripe\.com|paypal\.com|razorpay\.com|cloudflareinsights\.com|challenges\.cloudflare\.com|sentry-cdn\.com|browser\.sentry-cdn\.com|posthog\.com|plausible\.io|youtube\.com|vimeo\.com|twitter\.com|x\.com|linkedin\.com|licdn\.com|tiktok\.com|calendly\.com|typeform\.com|zdassets\.com|zendesk\.com|onesignal\.com|cookiebot\.com|cookielaw\.org|onetrust\.com|jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|gpteng\.co|lovable\.dev)$/i;

/** Script and preload URLs referenced by an HTML page. */
export function extractAssetUrls(html, base) {
  const out = new Set();
  const re = /<(?:script|link)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let m;
  while ((m = re.exec(html))) {
    const tag = m[0].toLowerCase();
    const ref = m[1];
    if (tag.startsWith('<link') && !/rel\s*=\s*["']?(modulepreload|preload)/.test(tag)) continue;
    if (tag.startsWith('<link') && /as\s*=\s*["']?(style|font|image)/.test(tag)) continue;
    try { out.add(new URL(ref, base).href); } catch {}
  }
  return [...out];
}

/** Other JS chunks imported by a bundle (Vite code-splitting), plus its source map. */
export function extractJsRefs(js, base) {
  const out = new Set();
  const re = /(?:import\(|from|import)\s*["'`]((?:\.{1,2}\/|\/)[^"'`\s]+?\.m?js)["'`]/g;
  let m;
  while ((m = re.exec(js))) {
    try { out.add(new URL(m[1], base).href); } catch {}
  }
  // Vite's preload helper lists chunks as "assets/x.js" strings.
  const re2 = /["'`]((?:\.\/|\/)?assets\/[A-Za-z0-9_.-]+\.m?js)["'`]/g;
  while ((m = re2.exec(js))) {
    try { out.add(new URL(m[1].startsWith('assets/') ? '/' + m[1] : m[1], base).href); } catch {}
  }
  // Next.js and webpack chunk paths.
  const re3 = /["'`](\/?_next\/static\/[A-Za-z0-9_\/.\-\[\]%]+?\.js)["'`]/g;
  while ((m = re3.exec(js))) {
    try { out.add(new URL(m[1].startsWith('/') ? m[1] : '/' + m[1], base).href); } catch {}
  }
  const re4 = /["'`]((?:\/|\.\/)?(?:static\/js|js|chunks|_app\/immutable|build)\/[A-Za-z0-9_\/.\-]+?\.m?js)["'`]/g;
  while ((m = re4.exec(js))) {
    try { out.add(new URL(m[1], base).href); } catch {}
  }
  const map = js.match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)\s*$/m);
  const maps = [];
  if (map && !map[1].startsWith('data:')) {
    try { maps.push(new URL(map[1], base).href); } catch {}
  }
  return { scripts: [...out], maps };
}

/**
 * Scan a public website the way a visitor's browser sees it: the HTML,
 * every same-site JavaScript file it loads, and any public source maps.
 */
export async function scanUrl(input, options = {}) {
  const opts = { ...DEFAULTS, ...options };
  const started = Date.now();
  let target;
  if (/^[a-z][a-z0-9+.-]*:/i.test(input) && !/^https?:\/\//i.test(input)) throw new Error('Only http and https URLs can be scanned.');
  try {
    target = new URL(/^https?:\/\//i.test(input) ? input : 'https://' + input);
  } catch {
    throw new Error('That does not look like a website address.');
  }
  const budget = { bytes: 0 };
  const page = await get(target.href, opts, budget);
  if (!page.text) throw new Error(`The site answered with status ${page.status}.`);
  const origin = new URL(page.url);
  const root = registrableDomain(origin.hostname);
  // A page's own <script> tags are followed on any host except well-known third-party
  // trackers/widgets (their keys are not the site owner's). Chunks those scripts import
  // are followed on the same registrable domain or the script's own host (CDNs).
  const ownedHost = (h) => h === origin.hostname || registrableDomain(h) === root;
  const sameSite = (href) => ownedHost(new URL(href).hostname);
  const pageScriptOk = (href) => !THIRD_PARTY.test(new URL(href).hostname);
  const findings = scanText(page.text, { file: new URL(page.url).pathname || '/' });
  const files = [{ url: page.url, kind: 'html', bytes: page.text.length }];
  const queue = extractAssetUrls(page.text, page.url).filter(pageScriptOk).map((u) => ({ url: u, kind: 'js' }));
  const seen = new Set([page.url, ...queue.map((q) => q.url)]);
  const sourceMaps = [];
  const skipped = [];

  while (queue.length && files.length < opts.maxFiles) {
    const batch = queue.splice(0, 6);
    const results = await Promise.allSettled(batch.map((q) => get(q.url, opts, budget).then((r) => ({ ...r, kind: q.kind }))));
    for (const r of results) {
      if (r.status !== 'fulfilled' || !r.value.text) {
        if (r.status === 'fulfilled' && r.value.truncated) skipped.push(r.value.url);
        continue;
      }
      const { url, text, kind } = r.value;
      const path = new URL(url).pathname;
      files.push({ url, kind, bytes: text.length });
      findings.push(...scanText(text, { file: path }));
      if (kind === 'map') {
        sourceMaps.push(path);
        continue;
      }
      const refs = extractJsRefs(text, url);
      const fromHost = new URL(url).hostname;
      const okChild = (u) => sameSite(u) || new URL(u).hostname === fromHost;
      for (const u of refs.scripts) {
        if (!seen.has(u) && okChild(u)) { seen.add(u); queue.push({ url: u, kind: 'js' }); }
      }
      for (const u of refs.maps) {
        if (!seen.has(u) && okChild(u)) { seen.add(u); queue.push({ url: u, kind: 'map' }); }
      }
    }
  }

  const merged = mergeFindings(findings);
  return withFixes({
    url: page.url,
    scannedAt: new Date().toISOString(),
    ms: Date.now() - started,
    files: files.length,
    bytes: budget.bytes,
    sourceMapsPublic: sourceMaps,
    skipped,
    hitFileLimit: queue.length > 0,
    summary: summarize(merged),
    findings: merged,
  });
}
