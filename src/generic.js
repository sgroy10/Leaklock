// Generic detection: catches keys for ANY API, not just known providers.
// Finds secrets by how the code USES them, not by their shape:
//   1. sent as a credential: `Authorization: Bearer ${x}`, `"x-api-key": x`, `?key=...`
//   2. stored in a credential-named variable: apiKey = "...", SECRET_TOKEN: "..."
// Minified bundles rename variables (B, Ge, eS), so for (1) we resolve the variable
// back to the string literal it was assigned. Then we name the provider from the API
// host the request goes to (e.g. api.kie.ai -> kie.ai).
import { entropy } from './entropy.js';

const LIT = String.raw`["'\x60]([A-Za-z0-9_\-.+/=:]{16,256})["'\x60]`;

// Values that are public by design or not secrets at all.
const PUBLIC_PREFIX = /^(pk_|pk\.|phc_|sb_publishable_|NEXT_PUBLIC|G-|UA-|GTM-|AW-|ca-pub-|pub-|price_|prod_|acct_|cus_|whsec_test)/;
const NOT_SECRET = /^(https?:|data:|\/|\.\/|[a-z]+(?:-[a-z]+){2,}$)|\.(?:js|css|png|svg|jpe?g|webp|json|html?|woff2?)$|^[A-Za-z]+$|^[0-9.]+$|^[a-z0-9-]+\.[a-z]{2,}$/;

const CRED_NAME = /(?:^|[_\-.]|[a-z])(?:api[_-]?key|apikey|secret|token|access[_-]?key|private[_-]?key|auth[_-]?key|client[_-]?secret|bearer|password|passwd|credential)s?$/i;
const PUBLIC_NAME = /(?:publishable|public|anon|site[_-]?key|recaptcha|measurement|tracking|analytics|pixel|gtag|algolia.*search|search[_-]?only|mapbox[_-]?public)/i;

function plausibleSecret(v) {
  if (v.length < 20 || v.length > 256) return false;
  if (PUBLIC_PREFIX.test(v) || NOT_SECRET.test(v)) return false;
  if ((v.match(/[0-9]/g) || []).length < 3 || !/[A-Za-z]/.test(v)) return false;
  // identifiers like PrimerNav_Item_4a, unless a segment is clearly random (keys like vx_cOV1UNMbm-TbruXA)
  if (/^[A-Z]?[a-z]+(?:[A-Z][a-z0-9]+|[_-][A-Za-z0-9]+){2,}$/.test(v) && !v.split(/[_-]/).some((seg) => seg.length >= 10 && /[A-Z]{2}/.test(seg) && /[a-z]/.test(seg))) return false;
  if (/\s/.test(v)) return false;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) return false; // UUIDs: usually ids, not secrets
  return entropy(v) >= 3.2;
}

// Find the string literal most recently assigned to identifier `id` before `before`.
function resolveIdentifier(text, id, before, window = 20000, lit = LIT) {
  const from = Math.max(0, before - window);
  const re = new RegExp(String.raw`(?:^|[^\w$.])` + id.replace(/\$/g, '\\$') + String.raw`\s*=\s*` + lit, 'g');
  re.lastIndex = from;
  let m;
  let last = null;
  while ((m = re.exec(text)) && m.index < before) last = { value: m[1], index: m.index + m[0].lastIndexOf(m[1]) };
  return last;
}

const toHost = (url) => {
  const m = /^https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/i.exec(url || '');
  if (!m) return null;
  const host = m[1].toLowerCase();
  return { host, domain: host.split('.').slice(-2).join('.') };
};

// The URL of the request this credential is attached to: fetch("https://..."), fetch(`${BASE}/x`), fetch(url).
function requestHost(text, index) {
  const seg = text.slice(Math.max(0, index - 600), index);
  const calls = [...seg.matchAll(/(?:fetch|axios(?:\.[a-z]+)?|\.(?:get|post|put|patch|request))\(\s*(?:["'\x60](https?:\/\/[^"'\x60$]+)|\x60\$\{\s*([A-Za-z_$][\w$]*)\s*\}|([A-Za-z_$][\w$]*)\s*[,)])/g)];
  const last = calls[calls.length - 1];
  if (!last) return null;
  if (last[1]) return toHost(last[1]);
  const id = last[2] || last[3];
  const at = Math.max(0, index - 600) + last.index;
  const r = resolveIdentifier(text, id, at, 20000, String.raw`["'\x60](https?:\/\/[^"'\x60]+)`);
  return r ? toHost(r.value) : null;
}

// Name the API from the nearest https://host in a string near the usage.
function nearbyHost(text, index) {
  const seg = text.slice(Math.max(0, index - 1500), index + 1500);
  const re = /https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/gi;
  let best = null;
  let m;
  while ((m = re.exec(seg))) {
    const host = m[1].toLowerCase();
    if (/(w3\.org|reactjs|github\.com|mozilla|schema\.org|googleapis\.com\/css|fonts\.)/.test(host)) continue;
    const dist = Math.abs(m.index - 1500);
    if (!best || dist < best.dist) best = { host, dist };
  }
  if (!best) return null;
  const p = best.host.split('.');
  return { host: best.host, domain: p.slice(-2).join('.') };
}

/**
 * @returns Array<{ value, index, severity, provider, why }>
 */
export function genericCandidates(text) {
  const out = [];
  const add = (value, index, severity, why, usageIndex) => {
    if (usageIndex == null) usageIndex = index;
    if (!plausibleSecret(value)) return;
    // Algolia search-only keys are public by design.
    const ctx = text.slice(Math.max(0, index - 250), index + 250);
    if (/algolia|indexName|appId\s*:/i.test(ctx)) return;
    // Public-by-design tokens sent the normal way: Shopify Storefront tokens, Supabase anon JWTs.
    if (/storefront/i.test(ctx) || /storefront/i.test(text.slice(Math.max(0, usageIndex - 400), usageIndex + 400))) return;
    if (/^AIza/.test(value)) return; // Google keys are judged by the Google rule, with context
    if (/^eyJ/.test(value)) {
      try {
        const payload = JSON.parse(Buffer.from(value.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
        if (['anon', 'authenticated'].includes(payload.role)) return;
      } catch {}
    }
    if (severity === 'secret' && why === 'sent in an API-key header' && !/headers/i.test(text.slice(Math.max(0, usageIndex - 400), usageIndex))) {
      severity = 'review';
      why = 'stored in an API-key field';
    }
    const h = (usageIndex != null && requestHost(text, usageIndex)) || nearbyHost(text, usageIndex ?? index) || nearbyHost(text, index);
    if (why === 'sent in a URL query string' && h) {
      // Share links, embeds and ad tags carry ?key= values that are not API credentials.
      if (/(^|\.)(photos\.google\.com|photos\.app\.goo\.gl|docs\.google\.com|drive\.google\.com|youtube\.com|google\.com|maps\.google\.com)$/.test(h.host)) return;
      if (/(cpm|adsterra|propeller|monetag|adserver|doubleclick|highperformanceformat|effectivegate|popads|adcash)/i.test(h.host)) return;
      // Supabase Storage signed URLs carry a scoped, expiring JWT in ?token=.
      if (/supabase\.(co|in)$/.test(h.host) && /^eyJ/.test(value)) return;
      if (/githubusercontent\.com$/.test(h.host)) { severity = 'review'; why = 'a short-lived raw-file token in a URL'; }
    }
    const provider = h ? `${h.domain} API key` : 'Unknown API key';
    out.push({ value, index, severity, why, provider, host: h?.host });
  };

  // 1a. Bearer with a literal: "Bearer abc123..." / `Bearer abc123...`
  for (const m of text.matchAll(/["'\x60]Bearer\s+([A-Za-z0-9_\-.+/=]{20,256})["'\x60]/g)) {
    add(m[1], m.index + m[0].indexOf(m[1]), 'secret', 'sent as a Bearer token');
  }
  // 1b. Bearer with a variable: `Bearer ${x}` / "Bearer "+x / "Bearer ".concat(x)
  for (const m of text.matchAll(/\x60Bearer\s+\$\{\s*([A-Za-z_$][\w$]*)\s*\}\x60|["']Bearer ["']\s*\+\s*([A-Za-z_$][\w$]*)|["']Bearer ["']\.concat\(\s*([A-Za-z_$][\w$]*)/g)) {
    const id = m[1] || m[2] || m[3];
    const r = resolveIdentifier(text, id, m.index);
    if (r) add(r.value, r.index, 'secret', 'sent as a Bearer token', m.index);
  }
  // 1c. API-key headers with a literal or a variable.
  const HDR = String.raw`["']?(?:x-api-key|api-key|apikey|x-auth-token|x-access-token|x-api-token|xi-api-key|x-goog-api-key|authorization|token)["']?\s*:\s*`;
  for (const m of text.matchAll(new RegExp(HDR + LIT, 'gi'))) {
    add(m[1].replace(/^(?:Bearer|Token|Basic)\s+/i, ''), m.index + m[0].lastIndexOf(m[1]), 'secret', 'sent in an API-key header');
  }
  for (const m of text.matchAll(new RegExp(HDR + String.raw`([A-Za-z_$][\w$]*)\s*[,}]`, 'gi'))) {
    const id = m[1];
    if (/^(true|false|null|undefined|void)$/.test(id)) continue;
    const r = resolveIdentifier(text, id, m.index);
    if (r) add(r.value, r.index, 'secret', 'sent in an API-key header', m.index);
  }
  // 1d. Key in a query string: ?key=..., &api_key=..., ?access_token=...
  for (const m of text.matchAll(/[?&](?:key|api_key|apikey|api-key|token|access_token|auth|secret)=([A-Za-z0-9_\-.]{20,256})/gi)) {
    add(m[1], m.index + m[0].indexOf(m[1]), 'secret', 'sent in a URL query string');
  }
  // 2. Credential-named variables or properties holding a literal.
  for (const m of text.matchAll(new RegExp(String.raw`["']?([A-Za-z_$][\w$\-]*)["']?\s*[:=]\s*` + LIT, 'g'))) {
    const name = m[1];
    if (!CRED_NAME.test(name) || PUBLIC_NAME.test(name)) continue;
    add(m[2], m.index + m[0].lastIndexOf(m[2]), 'review', `stored in "${name}"`);
  }
  return out;
}
