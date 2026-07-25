#!/usr/bin/env node
// Command-line blacklist check:  npm run check example.com
//   --all   show every blacklist row (default shows listed + timeouts only)
import { loadEnv } from './lib/env.js';
loadEnv();
import { checkDomain } from './lib/check.js';

const args = process.argv.slice(2);
const showAll = args.includes('--all');
const input = args.filter((a) => a !== '--all').join(' ').trim();

if (!input) {
  console.error('usage: npm run check <domain> [--all]');
  process.exit(2);
}

const r = await checkDomain(input);

if (!r.ok) {
  console.error(`✗ ${input}: ${r.error}`);
  process.exit(1);
}

const badge = { clean: '✓ CLEAN', listed: '! LISTED', blacklisted: '✗ BLACKLISTED', unknown: '? UNKNOWN' }[r.verdict];
console.log(
  `\n${badge}, ${r.domain}  resolves to ${r.resolvesTo.join(', ') || 'no IP'}`,
);
console.log(
  `Checked against ${r.zonesChecked} blacklists. Listed ${r.listedCount}, ${r.timeoutCount} timeout/unknown  ·  score ${r.score}/100  (${r.tookMs}ms)\n`,
);

const icon = { listed: '✗', ok: '✓', timeout: '?' };
const rows = showAll ? r.table : r.table.filter((x) => x.state !== 'ok');

// Columns: status  blacklist  reason  TTL  ms
console.log(`  ${'St'.padEnd(2)} ${'Blacklist'.padEnd(34)} ${'Reason'.padEnd(34)} ${'TTL'.padStart(6)} ${'ms'.padStart(5)}`);
console.log('  ' + '-'.repeat(88));
for (const row of rows) {
  const reason = row.reason || (row.state === 'ok' ? '' : '');
  console.log(
    `  ${icon[row.state].padEnd(2)} ${row.name.slice(0, 34).padEnd(34)} ${String(reason).slice(0, 34).padEnd(34)} ${String(row.ttl ?? '').padStart(6)} ${String(row.responseMs ?? '').padStart(5)}`,
  );
}

if (!showAll && r.okCount) console.log(`\n  … and ${r.okCount} OK (pass --all to show every list)`);

// Delist guidance for real listings.
const listed = r.table.filter((x) => x.state === 'listed' && x.delist);
if (listed.length) {
  console.log('\n  Delisting:');
  for (const l of listed) console.log(`  • ${l.name}: ${l.delist}`);
}
console.log('');
