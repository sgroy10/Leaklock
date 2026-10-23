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

test('generic: catches a key for an unknown API by how it is used', () => {
  const k1 = 'a7b91c' + 'e04f2d8b3a6c9e1f5d7b2a4e9e24';
  const k2 = 'Zq8' + 'Lm3Np7Rt2Vx9Bc4Df6Gh1Jk5';
  const bundle = `const B="${k1}",X="https://api.newthing.ai/api/v1";async function go(){const D=await fetch(\`\${X}/jobs/create\`,{method:"POST",headers:{"Content-Type":"application/json",Authorization:\`Bearer \${B}\`}})}
    const JC="${k2}";async function seg(f){await fetch("https://image-api.otherapi.com/v2/edit",{method:"POST",headers:{"x-api-key":JC},body:f})}`;
  const fs = scanText(bundle);
  assert.equal(fs.length, 2, JSON.stringify(fs));
  const a = fs.find((f) => f.masked.startsWith('a7b9'));
  assert.equal(a.severity, 'secret');
  assert.equal(a.provider, 'newthing.ai API key');
  const b = fs.find((f) => f.masked.startsWith('Zq8'));
  assert.equal(b.severity, 'secret');
  assert.equal(b.provider, 'otherapi.com API key');
});

test('generic: ignores public search keys, ids, URLs and class names', () => {
  const bundle = `algolia:{appId:"1FCF9AYYAT",apiKey:"1b7ad4e1c89e645e351e59d40544eda1",indexName:"beta"}
    const cls="flex items-center justify-between gap-3";const u="https://cdn.example.com/a/b/c/d.png";const id="550e8400-e29b-41d4-a716-446655440000";
    gtag("config","G-B02DKTPWW5");`;
  assert.equal(scanText(bundle).length, 0, JSON.stringify(scanText(bundle)));
});

test('no false alarms from real-world patterns found in the study', () => {
  // A form placeholder showing the shape of a service-account file is not a key.
  assert.equal(one('placeholder:`{"private_key": "-----BEGIN PRIVATE KEY-----\\\\n..."}`').length, 0);
  // Shopify Storefront tokens are public by design.
  assert.equal(one('fetch("https://shop.myshopify.com/api/2024-01/graphql.json",{headers:{"X-Shopify-Storefront-Access-Token":"cd19f0a7b3e24c5d8e6f1a2b3c4d4b4f"}})').filter((f) => f.severity !== 'safe').length, 0);
  // A Supabase anon JWT passed as ?apikey= is the normal Supabase pattern.
  const anon = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + Buffer.from(JSON.stringify({ iss: 'supabase', ref: 'abcdefghijklmnop', role: 'anon' })).toString('base64url') + '.c2lnbmF0dXJlc2lnbmF0dXJlc2lnbmF0dXJl';
  assert.equal(one(`const u="https://abcdefghijklmnop.supabase.co/rest/v1/items?apikey=${anon}";`).filter((f) => f.severity !== 'safe').length, 0);
  // A Google Photos share link is not an API credential.
  assert.equal(one('const a="https://photos.google.com/share/AF1QipM6zv3X8?key=ZGQ1a2V5c2hhcmVsaW5rMTIzNDU2Nzg5";').filter((f) => f.severity !== 'safe').length, 0);
});

test('Storefront tokens resolved through variables and Supabase signed URLs are not flagged', () => {
  const sf = 'const O="shop.myshopify.com",E="de4e0a7b3e24c5d8e6f1a2b3c4d47d49",A=`https://${O}/api/2024-01/graphql.json`;' + ' '.repeat(50) + 'async function g(){return fetch(A,{method:"POST",headers:{"Content-Type":"application/json","X-Shopify-Storefront-Access-Token":E}})}';
  assert.equal(one(sf).filter((f) => f.severity !== 'safe').length, 0);
  const signed = 'const u="https://abcdefghijklmnop.supabase.co/storage/v1/object/sign/img/a.png?token=eyJraWQiOiJzdG9yYWdlLXVybC1zaWduaW5nLWtleSJ9.eyJ1cmwiOiJpbWcvYS5wbmcifQ.c2lnbmF0dXJlc2ln";';
  assert.equal(one(signed).filter((f) => f.severity !== 'safe').length, 0);
});
