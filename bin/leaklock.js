#!/usr/bin/env node
import { existsSync, statSync } from 'node:fs';
import { scanUrl } from '../src/scan-url.js';
import { scanDir } from '../src/scan-dir.js';

const args = process.argv.slice(2);
const cmd = args[0];
const json = args.includes('--json');
const showFix = args.includes('--fix');
const target = args.filter((a) => !a.startsWith('--'))[1];

const C = process.stdout.isTTY && !json
  ? { red: '\x1b[31m', yellow: '\x1b[33m', green: '\x1b[32m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' }
  : { red: '', yellow: '', green: '', dim: '', bold: '', reset: '' };

const LABEL = {
  critical: `${C.red}${C.bold}CRITICAL${C.reset}`,
  secret: `${C.red}SECRET  ${C.reset}`,
  review: `${C.yellow}REVIEW  ${C.reset}`,
  safe: `${C.green}SAFE    ${C.reset}`,
};

function help() {
  console.log(`LeakLock: find secret API keys your website ships to the browser.

Usage:
  leaklock scan <url>        scan a live site (HTML, JS bundles, source maps)
  leaklock scan <dir>        scan a build folder, e.g. dist/
  options: --fix             show how to fix each leak, with a prompt for your AI builder
           --json            machine-readable output
           --fail-on=secret  exit 1 if anything at or above this level is found
                             (critical | secret | review). Default: secret

Keys are always shown masked. LeakLock never sends your keys anywhere.`);
}

function print(r) {
  const where = r.url || r.dir;
  console.log(`\n${C.bold}LeakLock${C.reset} scanned ${where} ${C.dim}(${r.files} files)${C.reset}\n`);
  const shown = r.findings;
  if (!shown.length) {
    console.log(`${C.green}No secret keys found.${C.reset} ${C.dim}(That is not a guarantee: keys hidden in unusual ways can be missed.)${C.reset}`);
  }
  for (const f of shown) {
    console.log(`${LABEL[f.severity]} ${C.bold}${f.provider}${C.reset}  ${f.masked}`);
    console.log(`         ${C.dim}in ${f.files.slice(0, 3).join(', ')}${f.files.length > 3 ? ` +${f.files.length - 3} more` : ''}${C.reset}`);
    if (f.advice) console.log(`         ${f.advice}`);
    if (f.rotate && f.severity !== 'safe') console.log(`         ${C.dim}Rotate: ${f.rotate}${C.reset}`);
    if (f.fix && showFix) {
      console.log(`\n         ${C.bold}How to fix${C.reset}`);
      f.fix.steps.forEach((st, i) => console.log(`         ${i + 1}. ${st}`));
      console.log(`\n         ${C.bold}Paste this into Lovable, Bolt, Cursor or your AI builder:${C.reset}`);
      console.log(f.fix.prompt.split('\n').map((l) => `         ${C.dim}│${C.reset} ${l}`).join('\n') + '\n');
    }
  }
  if (r.sourceMapsPublic?.length) {
    console.log(`\n${C.yellow}Note:${C.reset} ${r.sourceMapsPublic.length} source map(s) are public, so your original source code is readable too.`);
  }
  const s = r.summary;
  if (!showFix && r.findings.some((f) => f.fix)) console.log(`\n${C.dim}Add --fix to get step-by-step fixes and a prompt to paste into your AI builder.${C.reset}`);
  console.log(`\n${s.critical} critical · ${s.secret} secret · ${s.review} to review · ${s.safe} safe (public by design)`);
  if (s.critical + s.secret > 0) {
    console.log(`\n${C.bold}Anyone can copy these keys from your site.${C.reset} Move the calls to a server, and consider rotating keys that were public.`);
  }
}

async function main() {
  if (cmd !== 'scan' || !target) return help();
  const isDir = existsSync(target) && statSync(target).isDirectory();
  const r = isDir ? await scanDir(target) : await scanUrl(target);
  if (json) console.log(JSON.stringify(r, null, 2));
  else print(r);
  const failOn = (args.find((a) => a.startsWith('--fail-on=')) || '--fail-on=secret').split('=')[1];
  const levels = ['critical', 'secret', 'review'];
  const idx = levels.indexOf(failOn);
  if (idx >= 0 && levels.slice(0, idx + 1).some((l) => r.summary[l] > 0)) process.exitCode = 1;
}

main().catch((e) => {
  console.error(`leaklock: ${e.message}`);
  process.exitCode = 2;
});
