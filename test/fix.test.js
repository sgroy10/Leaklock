import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { scanDir } from '../src/scan-dir.js';
import { fixFor } from '../src/fix.js';

const demo = fileURLToPath(new URL('../examples/leaky-app/dist', import.meta.url));

test('demo app: unknown-format keys found by usage, anon key marked safe', async () => {
  const r = await scanDir(demo);
  assert.equal(r.summary.secret, 2);
  assert.equal(r.summary.safe, 1);
  const names = r.findings.map((f) => f.provider).join(' | ');
  assert.match(names, /imagegen-demo\.ai/);
  assert.match(names, /voicecloner-demo\.io/);
});

test('every secret gets a fix prompt that never contains the key', async () => {
  const r = await scanDir(demo);
  for (const f of r.findings.filter((x) => x.severity === 'secret')) {
    assert.ok(f.fix && f.fix.steps.length >= 3);
    assert.match(f.fix.prompt, /Do not change any UI/);
    assert.ok(!f.fix.prompt.includes(f.masked.slice(0, 4) + f.masked.slice(-4)));
  }
  assert.ok(!r.findings.find((x) => x.severity === 'safe').fix);
});

test('service_role gets the Supabase-specific fix', () => {
  const fix = fixFor({ provider: 'Supabase service_role key (project abc)', severity: 'critical', files: ['/a.js'] });
  assert.match(fix.prompt, /Edge Function/);
  assert.match(fix.prompt, /anon key/);
});
