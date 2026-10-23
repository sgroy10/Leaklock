import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanText, mergeFindings, mask } from '../src/detect.js';
import { KEYS, VITE_BUNDLE } from './fixtures.js';

const one = (text) => scanText(text);
const byRule = (fs, rule) => fs.filter((f) => f.rule === rule);

test('finds each provider by its key shape', () => {
  const cases = [
    ['openai', KEYS.openai, 'secret'],
    ['openai-legacy', KEYS.openaiLegacy, 'secret'],
    ['anthropic', KEYS.anthropic, 'secret'],
    ['openrouter', KEYS.openrouter, 'secret'],
    ['groq', KEYS.groq, 'secret'],
    ['stripe-secret', KEYS.stripeLive, 'critical'],
    ['github-token', KEYS.github, 'critical'],
    ['aws-access-key', KEYS.aws, 'critical'],
    ['sendgrid', KEYS.sendgrid, 'secret'],
  ];
  for (const [rule, key, severity] of cases) {
    const fs = one(`const k = "${key}";`);
    assert.equal(fs.length, 1, `${rule}: expected one finding, got ${JSON.stringify(fs)}`);
    assert.equal(fs[0].rule, rule);
    assert.equal(fs[0].severity, severity);
  }
});

test('never returns the full key unless asked', () => {
  const [f] = one(`x="${KEYS.openai}"`);
  assert.equal(f.value, undefined);
  assert.ok(!JSON.stringify(f).includes(KEYS.openai));
  assert.equal(f.masked, mask(KEYS.openai));
  const [g] = scanText(`x="${KEYS.openai}"`, { includeValue: true });
  assert.equal(g.value, KEYS.openai);
});

test('anthropic and openrouter keys are not double-reported as OpenAI', () => {
  const fs = one(`a="${KEYS.anthropic}";b="${KEYS.openrouter}"`);
  assert.deepEqual(fs.map((f) => f.rule).sort(), ['anthropic', 'openrouter']);
});

test('Supabase: service_role is critical, anon is safe, random JWTs ignored', () => {
  const fs = one(VITE_BUNDLE);
  const jwts = byRule(fs, 'jwt');
  assert.equal(jwts.length, 2);
  assert.equal(jwts.find((f) => f.severity === 'critical').provider.startsWith('Supabase service_role'), true);
  assert.equal(jwts.find((f) => f.severity === 'safe').provider.startsWith('Supabase anon'), true);
});

test('Firebase web key is safe; bare Google key needs review; Gemini key is secret', () => {
  const fb = byRule(one(VITE_BUNDLE), 'google-api-key');
  assert.equal(fb.length, 1);
  assert.equal(fb[0].severity, 'safe');
  assert.equal(one(`k="${KEYS.google}"`)[0].severity, 'review');
  const gem = one(`k="${KEYS.google}";fetch("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key="+k)`);
  assert.equal(gem[0].severity, 'secret');
  assert.match(gem[0].provider, /Gemini/);
});

test('Stripe publishable key is safe, secret key is critical', () => {
  const fs = one(VITE_BUNDLE);
  assert.equal(byRule(fs, 'stripe-publishable')[0].severity, 'safe');
  assert.equal(byRule(fs, 'stripe-secret')[0].severity, 'critical');
});

test('placeholders are ignored', () => {
  assert.equal(one('apiKey: "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"').length, 0);
  assert.equal(one('OPENAI_API_KEY=sk-your-api-key-here').length, 0);
});

test('a realistic Vite bundle produces the right verdicts', () => {
  const fs = one(VITE_BUNDLE);
  const sev = fs.map((f) => `${f.rule}:${f.severity}`).sort();
  assert.deepEqual(sev, [
    'google-api-key:safe',
    'jwt:critical',
    'jwt:safe',
    'openai:secret',
    'stripe-publishable:safe',
    'stripe-secret:critical',
  ]);
  assert.equal(fs[0].severity, 'critical'); // sorted worst first
});

test('reports line numbers', () => {
  const [f] = one(`\n\nconst k="${KEYS.groq}"`);
  assert.equal(f.line, 3);
});

test('mergeFindings dedupes the same key across files', () => {
  const a = scanText(`k="${KEYS.openai}"`, { file: 'a.js' });
  const b = scanText(`k="${KEYS.openai}"`, { file: 'a.js.map' });
  const m = mergeFindings([...a, ...b]);
  assert.equal(m.length, 1);
  assert.deepEqual(m[0].files, ['a.js', 'a.js.map']);
});
