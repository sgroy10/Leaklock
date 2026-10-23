import { createHash } from 'node:crypto';
import { RULES, SEVERITY_ORDER } from './rules.js';

/** Show the first 4 and last 4 characters only: "sk-p…9xQz". */
export function mask(value) {
  if (value.length <= 12) return value.slice(0, 2) + '…';
  return value.slice(0, 4) + '…' + value.slice(-4);
}

/** Short, non-reversible id so the same key found in two files is reported once. */
export function fingerprint(value) {
  return createHash('sha256').update(value).digest('hex').slice(0, 12);
}

/** Shannon entropy in bits per character. */
export function entropy(s) {
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function decodeJwtPayload(token) {
  try {
    const part = token.split('.')[1];
    const json = Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function lineCol(text, index) {
  let line = 1;
  let last = -1;
  for (let i = text.indexOf('\n'); i !== -1 && i < index; i = text.indexOf('\n', i + 1)) {
    line++;
    last = i;
  }
  return { line, column: index - last };
}

// Obvious placeholders that people leave in docs and examples.
const PLACEHOLDER = /(x{8,}|X{8,}|0{12,}|your[_-]?(api[_-]?)?key|example|placeholder|dummy|redacted|\*{6,}|\.{6,})/i;

function looksFake(value) {
  if (PLACEHOLDER.test(value)) return true;
  const body = value.replace(/^[a-z]+[-_](?:[a-z]+[-_])?/i, '');
  return body.length >= 16 && entropy(body) < 2.5;
}

function classifyJwt(value) {
  const p = decodeJwtPayload(value);
  if (!p || typeof p !== 'object') return null;
  const isSupabase = typeof p.iss === 'string' && p.iss.includes('supabase') || typeof p.ref === 'string';
  if (!isSupabase) {
    // Only report non-Supabase JWTs that claim an admin-like role.
    if (p.role === 'service_role' || p.role === 'admin') {
      return { provider: 'JWT (admin role)', severity: 'secret', advice: 'This token claims an admin role. Check what it can do and revoke it.' };
    }
    return null;
  }
  const project = p.ref ? ` (project ${p.ref})` : '';
  if (p.role === 'service_role') {
    return {
      provider: 'Supabase service_role key' + project,
      severity: 'critical',
      rotate: 'https://supabase.com/dashboard/project/_/settings/api-keys',
      advice: 'The service_role key bypasses Row Level Security. Anyone with it can read, change or delete your entire database. Rotate the JWT secret now and keep this key on the server only.',
    };
  }
  if (p.role === 'anon') {
    return {
      provider: 'Supabase anon key' + project,
      severity: 'safe',
      advice: 'Public by design. Your data is only as safe as your Row Level Security policies.',
    };
  }
  return null;
}

function classifyGoogle(text, index) {
  const around = text.slice(Math.max(0, index - 400), index + 400);
  if (/authDomain|messagingSenderId|storageBucket|firebaseapp\.com/.test(around)) {
    return {
      provider: 'Firebase web API key',
      severity: 'safe',
      advice: 'Firebase web keys are public by design. Protect data with Firebase Security Rules and App Check.',
    };
  }
  if (/generativelanguage\.googleapis\.com|GoogleGenerativeAI|@google\/genai|gemini-[0-9]/i.test(text)) {
    return {
      provider: 'Google Gemini API key',
      severity: 'secret',
      endpoint: 'https://generativelanguage.googleapis.com',
      rotate: 'https://aistudio.google.com/apikey',
      advice: 'This key calls Gemini from the browser. Anyone can copy it and spend your credits. Rotate it and move the call behind a server.',
    };
  }
  if (/maps\.googleapis\.com|google\.maps/.test(around)) {
    return {
      provider: 'Google Maps API key',
      severity: 'review',
      advice: 'Maps keys can be public if restricted. In Google Cloud Console, restrict it to your website (HTTP referrers) and to the Maps APIs only.',
    };
  }
  return {
    provider: 'Google API key',
    severity: 'review',
    advice: 'Check this key in Google Cloud Console. If it is not restricted to your domain and to specific APIs, anyone can use it.',
  };
}

/**
 * Scan one text (a JS bundle, HTML page or source map) for secret keys.
 * @param {string} text
 * @param {{ file?: string }} [opts]
 * @returns {Array<object>} findings. Never contains the full key: only `masked` and `fingerprint`.
 *          `value` is included only when opts.includeValue is true (local CLI / shield use).
 */
export function scanText(text, opts = {}) {
  const file = opts.file || '<input>';
  const taken = []; // [start, end] spans already matched by an earlier rule
  const findings = [];

  for (const rule of RULES) {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(text)) !== null) {
      const value = m[0];
      const start = m.index;
      const end = start + value.length;
      if (taken.some(([s, e]) => start < e && end > s)) continue;
      if (rule.id !== 'private-key' && looksFake(value)) continue;

      let info = { provider: rule.provider, severity: rule.severity, endpoint: rule.endpoint, rotate: rule.rotate, advice: rule.advice };
      if (rule.classify === 'jwt') {
        const c = classifyJwt(value);
        if (!c) continue;
        info = { ...info, ...c };
      } else if (rule.classify === 'google') {
        info = { ...info, ...classifyGoogle(text, start) };
      }

      taken.push([start, end]);
      const f = {
        rule: rule.id,
        provider: info.provider,
        severity: info.severity,
        masked: mask(value),
        fingerprint: fingerprint(value),
        file,
        ...lineCol(text, start),
      };
      if (info.endpoint) f.endpoint = info.endpoint;
      if (info.rotate) f.rotate = info.rotate;
      if (info.advice) f.advice = info.advice;
      if (opts.includeValue) f.value = value;
      findings.push(f);
    }
  }
  return findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.line - b.line);
}

/** Merge findings from many files: one entry per key, listing every file it appears in. */
export function mergeFindings(list) {
  const byKey = new Map();
  for (const f of list) {
    const k = f.fingerprint;
    if (!byKey.has(k)) byKey.set(k, { ...f, files: [f.file] });
    else if (!byKey.get(k).files.includes(f.file)) byKey.get(k).files.push(f.file);
  }
  return [...byKey.values()]
    .map(({ file, line, column, ...rest }) => rest)
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

export function summarize(findings) {
  const s = { critical: 0, secret: 0, review: 0, safe: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}
