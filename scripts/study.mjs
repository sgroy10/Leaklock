#!/usr/bin/env node
// Research scan: run LeakLock over a list of public app URLs and publish ONLY aggregate numbers.
// Never writes a site name next to a finding. Keys are never stored, only masked.
//   node scripts/study.mjs urls.txt > study.json
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { scanUrl } from '../src/scan-url.js';

const urls = [...new Set(readFileSync(process.argv[2], 'utf8').split(/\s+/).filter(Boolean))];
const CONC = Number(process.env.CONC || 4);
const anon = (u) => createHash('sha256').update(u).digest('hex').slice(0, 10);

const sites = [];
let i = 0;
async function worker() {
  while (i < urls.length) {
    const u = urls[i++];
    try {
      const r = await scanUrl(u, { maxFiles: 50 });
      sites.push({
        id: anon(u),
        ok: true,
        files: r.files,
        summary: r.summary,
        sourceMaps: r.sourceMapsPublic.length > 0,
        findings: r.findings.filter((f) => f.severity !== 'safe').map((f) => ({ severity: f.severity, provider: f.provider.replace(/ \(project .*\)$/, ''), byUsage: f.rule === 'generic' })),
      });
    } catch (e) {
      sites.push({ id: anon(u), ok: false, error: String(e.message).slice(0, 80) });
    }
    process.stderr.write(`\r${sites.length}/${urls.length}`);
  }
}
await Promise.all(Array.from({ length: CONC }, worker));

const ok = sites.filter((s) => s.ok);
const leaking = ok.filter((s) => s.summary.critical + s.summary.secret > 0);
const byUsageOnly = leaking.filter((s) => s.findings.filter((f) => f.severity !== 'review').every((f) => f.byUsage));
const providers = {};
for (const s of ok) for (const f of s.findings) if (f.severity !== 'review') {
  const k = f.byUsage ? 'Unknown-format (found by usage)' : f.provider.replace(/ API key$| key$/, '');
  providers[k] = (providers[k] || 0) + 1;
}
const pct = (n) => ok.length ? +(100 * n / ok.length).toFixed(1) : 0;
console.log(JSON.stringify({
  scannedAt: new Date().toISOString(),
  attempted: urls.length,
  scanned: ok.length,
  leakingSites: leaking.length, leakingPct: pct(leaking.length),
  criticalSites: ok.filter((s) => s.summary.critical).length,
  sitesWhoseLeaksOnlyUsageDetectionFinds: byUsageOnly.length,
  sitesWithAnyUsageFoundKey: leaking.filter((s) => s.findings.some((f) => f.byUsage && f.severity !== 'review')).length,
  publicSourceMapsPct: pct(ok.filter((s) => s.sourceMaps).length),
  keysByProvider: Object.fromEntries(Object.entries(providers).sort((a, b) => b[1] - a[1])),
  sites,
}, null, 2));
