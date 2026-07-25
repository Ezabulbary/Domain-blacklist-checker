#!/usr/bin/env node
// Probe every blocklist and report which ones can be trusted from THIS server.
//   npm run calibrate
import { loadEnv } from './lib/env.js';
loadEnv();
import { calibrateAll, saveCalibration, summarize, isTrusted } from './lib/calibrate.js';
import { ALL_ZONES } from './lib/zones.js';
import { buildResolver } from './lib/resolve.js';

const resolver = buildResolver(null, { timeout: 6000, tries: 2 });
let servers = [];
try { servers = resolver.getServers(); } catch { /* ignore */ }

console.log(`\nCalibrating ${ALL_ZONES.length} blocklists via resolver ${servers.join(', ') || '(system)'}…\n`);

const cal = await calibrateAll({ resolver });
saveCalibration(cal);

const byZone = new Map(ALL_ZONES.map((z) => [z.zone, z]));
const rows = Object.entries(cal.zones).map(([zone, v]) => ({ zone, name: byZone.get(zone)?.name || zone, ...v }));

const ICON = {
  verified: '✓', answering: '·', 'always-positive': '✗', silent: '!', blocked: '!', dead: '×',
};
const ORDER = ['verified', 'answering', 'always-positive', 'silent', 'blocked', 'dead'];
rows.sort((a, b) => ORDER.indexOf(a.verdict) - ORDER.indexOf(b.verdict) || a.name.localeCompare(b.name));

for (const r of rows) {
  console.log(`  ${ICON[r.verdict] || '?'} ${r.verdict.padEnd(16)} ${r.name.slice(0, 36).padEnd(36)} ${r.reason}`);
}

const t = summarize(cal);
const trusted = rows.filter((r) => isTrusted(r.verdict)).length;
console.log(`\n  ${trusted}/${rows.length} blocklists are trusted for scoring.`);
console.log('  ' + Object.entries(t).map(([k, v]) => `${k}: ${v}`).join(' · '));

const bad = rows.filter((r) => r.verdict === 'always-positive');
if (bad.length) {
  console.log(`\n  Excluded as unreliable (would produce FALSE listings):`);
  bad.forEach((r) => console.log(`    • ${r.name}: ${r.reason}`));
}
const silent = rows.filter((r) => r.verdict === 'silent' || r.verdict === 'blocked');
if (silent.length) {
  console.log(`\n  Not answering us (their "clean" would be meaningless):`);
  silent.forEach((r) => console.log(`    • ${r.name}: ${r.reason}`));
  console.log('\n  Fix: run your own recursive resolver (Unbound) and set DBC_RESOLVERS to it,');
  console.log('  and/or get a free Spamhaus DQS key. Then re-run: npm run calibrate');
}
console.log('');
