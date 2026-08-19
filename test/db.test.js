import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';

// These tests need a throwaway Postgres. Point TEST_DATABASE_URL (or
// DATABASE_URL) at one to run them; otherwise they skip so `npm test` stays
// network/DB-free by default.
const DB_URL = process.env.TEST_DATABASE_URL || process.env.DATABASE_URL;
const skip = DB_URL ? false : 'set TEST_DATABASE_URL to run DB tests';

let db, migrate, closePool, query;

before(async () => {
  if (skip) return;
  process.env.DATABASE_URL = DB_URL;
  ({ db, migrate, closePool, query } = await import('../src/db/index.js'));
  await migrate({ log: () => {} });
  // Clean slate (CASCADE handles the FK chain).
  await query('TRUNCATE alerts, monitors, checks, domains, users RESTART IDENTITY CASCADE');
});

after(async () => {
  if (!skip && closePool) await closePool();
});

// A minimal fake checkDomain() result for persistence tests.
const fakeResult = (domain, listings = []) => ({
  ok: true,
  input: domain,
  domain,
  host: domain,
  score: listings.length ? 60 : 100,
  verdict: listings.length ? 'listed' : 'clean',
  counts: { listed: listings.length, clean: 5, unknown: 0, total: 5 + listings.length },
  dns: { a: ['1.2.3.4'], aaaa: [], mx: [] },
  listings,
});

test('users: create, case-insensitive email, api key, plan, rotate', { skip }, async () => {
  const u = await db.users.createUser({ email: 'Owner@Example.com' });
  assert.ok(u.id);
  assert.equal(u.plan, 'free');
  assert.match(u.api_key, /^[0-9a-f]{48}$/);

  const byEmail = await db.users.getUserByEmail('owner@example.com');
  assert.equal(byEmail.id, u.id, 'lookup is case-insensitive');

  const byKey = await db.users.getUserByApiKey(u.api_key);
  assert.equal(byKey.id, u.id);

  await assert.rejects(() => db.users.createUser({ email: 'OWNER@example.com' }), /duplicate|unique/i);

  const pro = await db.users.setUserPlan(u.id, 'pro');
  assert.equal(pro.plan, 'pro');

  const rotated = await db.users.rotateApiKey(u.id);
  assert.notEqual(rotated.api_key, u.api_key);
});

test('domains: upsert is idempotent and preserves first_seen', { skip }, async () => {
  const a = await db.domains.upsertDomain('Example.COM');
  assert.equal(a.name, 'example.com', 'stored lowercase');
  const b = await db.domains.upsertDomain('example.com');
  assert.equal(b.id, a.id);
  assert.deepEqual(b.first_seen, a.first_seen, 'first_seen unchanged on re-upsert');
});

test('checks: saveCheck creates domain, stores result, stamps last_checked', { skip }, async () => {
  const res = fakeResult('shop.example.net', [{ subject: 'shop.example.net', zone: 'dbl.spamhaus.org' }]);
  const row = await db.checks.saveCheck(res);
  assert.ok(row.id);
  assert.equal(row.score, 60);
  assert.equal(row.verdict, 'listed');
  assert.equal(row.listed_count, 1);
  assert.equal(row.raw_result.domain, 'shop.example.net', 'JSONB round-trips');

  const dom = await db.domains.getDomainByName('shop.example.net');
  assert.ok(dom.last_checked_at, 'last_checked_at stamped');

  const history = await db.checks.listChecksForDomain('shop.example.net');
  assert.equal(history.length, 1);
});

test('checks: per-user daily quota count', { skip }, async () => {
  const u = await db.users.createUser({ email: 'quota@example.com' });
  await db.checks.saveCheck(fakeResult('q1.example.com'), { userId: u.id });
  await db.checks.saveCheck(fakeResult('q2.example.com'), { userId: u.id });
  assert.equal(await db.checks.countChecksToday(u.id), 2);
});

test('monitors: create is upsert per (user,domain); claimDueMonitors advances schedule', { skip }, async () => {
  const u = await db.users.createUser({ email: 'watcher@example.com' });
  const m1 = await db.monitors.createMonitor({ userId: u.id, domainName: 'watch.example.com', frequency: 'daily' });
  const m2 = await db.monitors.createMonitor({ userId: u.id, domainName: 'watch.example.com', frequency: 'hourly' });
  assert.equal(m1.id, m2.id, 'same (user,domain) -> same monitor');
  assert.equal(m2.frequency, 'hourly', 'frequency updated');

  // next_run_at defaults to now(), so it should be due immediately.
  const due = await db.monitors.claimDueMonitors({ limit: 10 });
  assert.ok(due.some((d) => d.id === m1.id), 'monitor claimed as due');
  assert.equal(due.find((d) => d.id === m1.id).domain, 'watch.example.com');

  // Immediately claiming again returns nothing (next_run_at pushed forward).
  const again = await db.monitors.claimDueMonitors({ limit: 10 });
  assert.equal(again.some((d) => d.id === m1.id), false, 'not due twice in the same window');
});

test('alerts: recordChanges diffs listings into listed/delisted rows', { skip }, async () => {
  const u = await db.users.createUser({ email: 'alert@example.com' });
  const m = await db.monitors.createMonitor({ userId: u.id, domainName: 'flip.example.com' });

  const prev = fakeResult('flip.example.com', [{ subject: 'flip.example.com', zone: 'dbl.spamhaus.org' }]);
  const curr = fakeResult('flip.example.com', [{ subject: 'flip.example.com', zone: 'multi.uribl.com' }]);

  const created = await db.alerts.recordChanges(m.id, prev, curr);
  // dbl.spamhaus.org delisted, multi.uribl.com newly listed.
  const changes = created.map((a) => `${a.status_change}:${a.zone}`).sort();
  assert.deepEqual(changes, ['delisted:dbl.spamhaus.org', 'listed:multi.uribl.com']);

  const unnotified = await db.alerts.listUnnotifiedAlerts();
  assert.ok(unnotified.length >= 2);
  const n = await db.alerts.markAlertsNotified(created.map((a) => a.id));
  assert.equal(n, created.length);
});

test('cascade: deleting a user removes monitors and alerts', { skip }, async () => {
  const u = await db.users.createUser({ email: 'cascade@example.com' });
  const m = await db.monitors.createMonitor({ userId: u.id, domainName: 'cascade-dom.example.com' });
  await db.alerts.createAlert({ monitorId: m.id, zone: 'zen.spamhaus.org', statusChange: 'listed' });

  await db.users.deleteUser(u.id);
  assert.equal(await db.monitors.getMonitorById(m.id), null);
  assert.deepEqual(await db.alerts.listAlertsForMonitor(m.id), []);
});

test('checks: the single-check shape (listedCount, no counts) stores its listed count', { skip }, async () => {
  // Regression: checkDomain() carries listedCount while the bulk audit shape
  // carries counts.listed. The saver must read both; it used to read only the
  // latter, so every single check was stored with listed_count 0.
  const res = fakeResult('single-shape.example.net', [{ subject: 'x', zone: 'zen.spamhaus.org' }]);
  delete res.counts;
  res.listedCount = 1;
  const row = await db.checks.saveCheck(res);
  assert.equal(row.listed_count, 1);
});

test('visitors: a record round-trips and an update keeps one row per browser', { skip }, async () => {
  const rec = {
    id: 'a'.repeat(32),
    firstSeen: Date.now() - 60_000,
    lastSeen: Date.now(),
    hits: 3,
    ip: '10.9.9.9',
    browser: 'Chrome 126',
    os: 'Windows 10/11',
    user: 'admin',
    timezone: 'Asia/Dhaka',
  };
  await db.visitors.saveVisitor(rec);
  await db.visitors.saveVisitor({ ...rec, hits: 4, lastSeen: rec.lastSeen + 30_000 });

  const stored = await db.visitors.listStoredVisitors();
  const mine = stored.filter((v) => v.id === rec.id);
  assert.equal(mine.length, 1, 'upsert, not duplicate rows');
  assert.equal(mine[0].hits, 4);
  assert.equal(mine[0].user, 'admin');
  assert.equal(mine[0].timezone, 'Asia/Dhaka');
});
