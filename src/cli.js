#!/usr/bin/env node
// Quick command-line check:  npm run check example.com
import { checkDomain } from './lib/check.js';

const input = process.argv.slice(2).join(' ').trim();
if (!input) {
  console.error('usage: npm run check <domain>');
  process.exit(2);
}

const r = await checkDomain(input);

if (!r.ok) {
  console.error(`✗ ${input}: ${r.error}`);
  process.exit(1);
}

const badge = { clean: '✓ CLEAN', listed: '! LISTED', blacklisted: '✗ BLACKLISTED', unknown: '? UNKNOWN' }[r.verdict];
console.log(`\n${badge}  —  ${r.domain}   score ${r.score}/100   (${r.tookMs}ms)`);
console.log(`  A: ${r.dns.a.join(', ') || '—'}   MX: ${r.dns.mx.join(', ') || '—'}`);
console.log(`  ${r.counts.listed} listed · ${r.counts.clean} clean · ${r.counts.unknown} unknown\n`);

for (const l of r.listings) {
  const meaning = l.meanings.length ? ` (${l.meanings.join('; ')})` : '';
  console.log(`  • [${l.severity}] ${l.subject} on ${l.zone}${meaning}`);
  console.log(`      delist: ${l.delist}`);
}
if (r.unknowns.length) {
  console.log(`\n  unknown (timeout/blocked — NOT treated as clean):`);
  for (const u of r.unknowns) console.log(`  • ${u.subject ?? ''} ${u.zone} — ${u.reason}`);
}
console.log('');
