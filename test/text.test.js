import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

// Copy rules for anything a user can read: no em dashes, no placeholder dashes
// standing in for a value, and no hardcoded blocklist counts that can drift out
// of sync with the catalog.

const SKIP_DIRS = new Set(['node_modules', '.git', 'coverage', 'dist']);
// Generated at runtime, and this file (which must name the character to test
// for), are not authored copy.
const SKIP_FILES = new Set(['.calibration.json', 'package-lock.json', 'test/text.test.js']);
const EXT = new Set(['.js', '.html', '.md', '.sql', '.json']);

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const p = join(dir, entry);
    const rel = p.replace(/^\.\//, '');
    if (SKIP_FILES.has(rel) || SKIP_FILES.has(entry)) continue;
    if (statSync(p).isDirectory()) walk(p, out);
    else if (EXT.has(p.slice(p.lastIndexOf('.')))) out.push(p);
  }
  return out;
}

const files = walk('.');
// Built from its code point so this file contains no em dash of its own.
const EM_DASH = String.fromCharCode(0x2014);

test('no em dashes anywhere in the project', () => {
  const offenders = files.filter((f) => readFileSync(f, 'utf8').includes(EM_DASH));
  assert.deepEqual(offenders, [], `em dash found in: ${offenders.join(', ')}`);
});

test('the UI never hardcodes a blocklist count', () => {
  const html = readFileSync('public/index.html', 'utf8');
  // The catalog size is read from /api/zones at runtime, so no "90+"/"69 lists"
  // style claim should be baked into the markup.
  assert.equal(/\b\d{2,}\+?\s*(DNSBL|URIBL|blacklists|blocklists)/i.test(html), false,
    'hardcoded blocklist count in public/index.html');
});

test('no bare dash placeholders in the UI', () => {
  const html = readFileSync('public/index.html', 'utf8');
  // A missing value must read as a word ("None", "n/a"), not a dash.
  assert.equal(html.includes(`|| '${EM_DASH}'`), false, 'dash used as a fallback value');
  assert.equal(html.includes(`>${EM_DASH}<`), false, 'dash rendered as a value');
});
