#!/usr/bin/env node
// Bulk check from a file, stdin, or args:
//   npm run check:bulk domains.txt
//   npm run check:bulk -- --csv domains.txt > report.csv
//   cat domains.txt | npm run check:bulk
//   npm run check:bulk -- example.com google.com foo.org
import { readFileSync } from 'node:fs';
import { loadEnv } from './lib/env.js';
loadEnv();
import { checkMany, resultsToCsv } from './lib/bulk.js';

const argv = process.argv.slice(2);
const asCsv = argv.includes('--csv');
const withAuth = argv.includes('--auth');
const rest = argv.filter((a) => a !== '--csv' && a !== '--auth');

function parse(text) {
  return text
    .split(/[\r\n]+/)
    .map((l) => l.split(/[,;\t]/)[0])
    .flatMap((c) => c.split(/\s+/))
    .map((s) => s.trim())
    .filter(Boolean);
}

let inputs = [];
if (rest.length === 1 && !rest[0].includes('.')) {
  // single token without a dot -> treat as filename
  inputs = parse(readFileSync(rest[0], 'utf8'));
} else if (rest.length >= 1) {
  // could be a file path or a list of domains
  const looksLikeFile = rest.length === 1 && /\.(txt|csv|lst)$/i.test(rest[0]);
  inputs = looksLikeFile ? parse(readFileSync(rest[0], 'utf8')) : rest;
} else {
  inputs = parse(readFileSync(0, 'utf8')); // stdin
}

if (inputs.length === 0) {
  console.error('usage: npm run check:bulk -- [--auth] [--csv] <file|domains...>   (or pipe a list via stdin)');
  console.error('  --auth  also check SPF, DKIM, DMARC, MX and PTR for every domain');
  process.exit(2);
}

const startedAt = Date.now();
const { results, summary, skipped } = await checkMany(inputs, {
  withAuth,
  concurrency: Number(process.env.DBC_BULK_CONCURRENCY ?? 5),
  onProgress: (done, total) => {
    if (!asCsv) process.stderr.write(`\r  checking ${done}/${total}…   `);
  },
});

if (asCsv) {
  process.stdout.write(resultsToCsv(results) + '\n');
  process.exit(0);
}

process.stderr.write('\r');
const badge = { clean: '✓', listed: '!', blacklisted: '✗', unknown: '?' };
console.log('');
for (const r of results) {
  if (!r.ok) {
    console.log(`  ✗ ${r.input.padEnd(32)} invalid: ${r.error}`);
    continue;
  }
  const b = badge[r.verdict] || '·';
  const listed = r.counts.listed ? `${r.counts.listed} listing(s): ` +
    r.listings.map((l) => l.zone).join(', ') : '';
  const auth = r.auth
    ? `SPF:${r.auth.spf.padEnd(7)} DKIM:${r.auth.dkim.padEnd(4)} DMARC:${r.auth.dmarc.padEnd(7)} `
    : '';
  const score = typeof r.score === 'number' ? String(r.score).padStart(3) + '/100' : '     n/a';
  console.log(`  ${b} ${r.domain.padEnd(28)} ${score} ${auth}${r.verdict.padEnd(10)} ${listed}`);
}

console.log(
  `\n  ${summary.total} domains in ${((Date.now() - startedAt) / 1000).toFixed(1)}s` +
    `, ${summary.clean} clean · ${summary.listed} listed · ${summary.blacklisted} blacklisted · ` +
    `${summary.unknown} unknown · ${summary.invalid} invalid`,
);
if (skipped.blank || skipped.truncated) {
  console.log(`  (skipped ${skipped.blank} blank, ${skipped.truncated} over the ${skipped.max} cap)`);
}
console.log('');
