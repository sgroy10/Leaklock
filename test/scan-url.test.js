import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { scanUrl } from '../src/scan-url.js';
import { KEYS, VITE_BUNDLE } from './fixtures.js';

function site() {
  const files = {
    '/': `<!doctype html><html><head><script type="module" crossorigin src="/assets/index-a1b2.js"></script>
          <link rel="modulepreload" href="/assets/vendor-c3d4.js"><link rel="stylesheet" href="/assets/index.css"></head><body><div id="root"></div></body></html>`,
    '/assets/index-a1b2.js': `import{a as x}from"./vendor-c3d4.js";const C=()=>import("./Chat-e5f6.js");console.log(x)\n//# sourceMappingURL=index-a1b2.js.map`,
    '/assets/vendor-c3d4.js': 'export const a=1;',
    '/assets/Chat-e5f6.js': VITE_BUNDLE,
    '/assets/index-a1b2.js.map': JSON.stringify({ version: 3, sources: ['src/lib/ai.ts'], sourcesContent: [`export const KEY = "${KEYS.anthropic}";`] }),
  };
  const srv = createServer((req, res) => {
    const body = files[req.url];
    if (!body) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': req.url === '/' ? 'text/html' : 'application/javascript' });
    res.end(body);
  });
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r(srv)));
}

test('scans HTML, follows lazy chunks and source maps', async () => {
  const srv = await site();
  const { port } = srv.address();
  // Port is not 80/443 in tests, so relax the port rule via allowPrivate + a custom URL.
  try {
    const r = await scanUrl(`http://127.0.0.1:${port}/`, { allowPrivate: true, allowAnyPort: true });
    assert.ok(r.files >= 5, `files=${r.files}`);
    assert.deepEqual(r.sourceMapsPublic, ['/assets/index-a1b2.js.map']);
    const rules = r.findings.map((f) => f.rule);
    assert.ok(rules.includes('openai'));
    assert.ok(rules.includes('anthropic'), 'key inside a source map is found');
    assert.equal(r.summary.critical, 2);
    assert.ok(!JSON.stringify(r).includes(KEYS.openai), 'full key never in the report');
  } finally {
    srv.close();
  }
});

test('refuses private addresses by default', async () => {
  await assert.rejects(scanUrl('http://127.0.0.1/'), /Private addresses/);
  await assert.rejects(scanUrl('http://localhost/'), /Private addresses/);
  await assert.rejects(scanUrl('file:///etc/passwd'), /http and https/);
});
