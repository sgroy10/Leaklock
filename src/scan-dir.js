import { withFixes } from './fix.js';
import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative, extname } from 'node:path';
import { scanText, mergeFindings, summarize } from './detect.js';

const EXT = new Set(['.js', '.mjs', '.cjs', '.html', '.htm', '.map', '.json', '.txt']);
const SKIP_DIRS = new Set(['node_modules', '.git']);

async function* walk(dir) {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) yield* walk(join(dir, e.name));
    } else if (EXT.has(extname(e.name))) {
      yield join(dir, e.name);
    }
  }
}

/** Scan a built output folder (dist/, build/, out/) the way it will ship. */
export async function scanDir(dir, { maxFileBytes = 20 * 1024 * 1024 } = {}) {
  const findings = [];
  let files = 0;
  const sourceMaps = [];
  for await (const path of walk(dir)) {
    if ((await stat(path)).size > maxFileBytes) continue;
    const rel = relative(dir, path);
    if (path.endsWith('.map')) sourceMaps.push(rel);
    findings.push(...scanText(await readFile(path, 'utf8'), { file: rel }));
    files++;
  }
  const merged = mergeFindings(findings);
  return withFixes({ dir, files, sourceMapsPublic: sourceMaps, summary: summarize(merged), findings: merged });
}
