// Visitor presence for the admin Visitors page. Every browser that opens the
// site (login screen, dashboard or a shared /r/ page) sends heartbeats; this
// module keeps one record per browser and answers "who is here right now".
//
// Deliberately in memory: presence is a live signal, not history. Restarting
// the server forgets everyone, which is the honest answer anyway, since none
// of them have re-announced themselves yet. Everything client-supplied is
// length-capped and re-escaped at render time; this store trusts nothing.

import { randomBytes } from 'node:crypto';

const visitors = new Map(); // vid -> record

const MAX_VISITORS = Number(process.env.DBC_PRESENCE_MAX ?? 500);
// A browser beats every ~30s; three missed beats reads as gone.
const ONLINE_WINDOW_MS = Number(process.env.DBC_PRESENCE_ONLINE_MS ?? 95_000);
// Records older than this drop entirely so the page shows recent reality,
// not an ever-growing museum.
const KEEP_MS = Number(process.env.DBC_PRESENCE_KEEP_MS ?? 7 * 24 * 60 * 60 * 1000);

export function newVisitorId() {
  return randomBytes(16).toString('hex');
}

export function isVisitorId(v) {
  return typeof v === 'string' && /^[a-f0-9]{32}$/.test(v);
}

const str = (v, max = 200) => (typeof v === 'string' ? v.slice(0, max) : null);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const bool = (v) => (typeof v === 'boolean' ? v : null);

/**
 * Record one heartbeat from a browser. `meta` is what the client sent plus
 * what the server saw on the request (ip, user agent, session user).
 */
export function beat(vid, meta = {}) {
  prune();
  const now = Date.now();
  let r = visitors.get(vid);
  if (!r) {
    // Full: drop the longest-gone visitor to make room for the live one.
    if (visitors.size >= MAX_VISITORS) {
      let oldest = null;
      for (const [k, v] of visitors) if (!oldest || v.lastSeen < oldest[1].lastSeen) oldest = [k, v];
      if (oldest) visitors.delete(oldest[0]);
    }
    r = { id: vid, firstSeen: now, hits: 0 };
    visitors.set(vid, r);
  }
  r.lastSeen = now;
  r.hits += 1;
  r.bye = false;

  // Server-observed facts win over anything the client claims.
  if (meta.ip) r.ip = str(meta.ip, 60);
  if (meta.userAgent) {
    r.userAgent = str(meta.userAgent, 400);
    Object.assign(r, parseUserAgent(r.userAgent));
  }
  // Session identity: kept while logged in, and remembered with a loggedOut
  // flag afterwards, so a visitor who signs out still shows who they were.
  if (meta.user) { r.user = str(meta.user, 60); r.role = str(meta.role, 20); r.loggedOut = false; }
  else if (r.user) r.loggedOut = true;

  // Client-reported details. Absent stays absent; nothing is invented.
  const c = meta.client || {};
  const set = (key, val) => { if (val !== null && val !== undefined) r[key] = val; };
  set('page', str(c.page, 80));
  set('path', str(c.path, 200));
  set('referrer', str(c.referrer, 300));
  set('language', str(c.language, 20));
  set('languages', Array.isArray(c.languages) ? c.languages.slice(0, 6).map((x) => str(x, 20)).filter(Boolean) : null);
  set('timezone', str(c.timezone, 60));
  set('tzOffsetMin', num(c.tzOffsetMin));
  set('screen', str(c.screen, 30));
  set('viewport', str(c.viewport, 30));
  set('dpr', num(c.dpr));
  set('cores', num(c.cores));
  set('memoryGb', num(c.memoryGb));
  set('touch', bool(c.touch));
  set('cookieEnabled', bool(c.cookieEnabled));
  set('platform', str(c.platform, 60));
  set('connection', str(c.connection, 20));
  return r;
}

/** The browser said goodbye (tab closed / navigated away). */
export function markBye(vid) {
  const r = visitors.get(vid);
  if (r) { r.bye = true; r.lastSeen = Date.now(); }
}

function prune(now = Date.now()) {
  for (const [k, v] of visitors) {
    if (now - v.lastSeen > KEEP_MS) visitors.delete(k);
  }
}

/** True when this record counts as online right now. */
export function isOnline(r, now = Date.now()) {
  if (r.bye) return false;
  return now - r.lastSeen <= ONLINE_WINDOW_MS;
}

/** Everything the admin page shows, online first, then most recent. */
export function listVisitors(now = Date.now()) {
  prune(now);
  const out = [];
  for (const r of visitors.values()) {
    out.push({ ...r, online: isOnline(r, now) });
  }
  out.sort((a, b) => (Number(b.online) - Number(a.online)) || (b.lastSeen - a.lastSeen));
  return out;
}

export function onlineWindowSeconds() {
  return Math.round(ONLINE_WINDOW_MS / 1000);
}

/**
 * Restore records saved in the database, called once at boot. Restored
 * visitors come back as they were, and read as offline until their browser
 * beats again (its lastSeen is in the past, which is the truth). A record
 * already in memory wins over its stored copy.
 */
export function hydrate(records = []) {
  let loaded = 0;
  for (const r of records) {
    if (!r || !isVisitorId(r.id) || visitors.has(r.id)) continue;
    if (visitors.size >= MAX_VISITORS) break;
    visitors.set(r.id, {
      ...r,
      firstSeen: Number(r.firstSeen) || Date.now(),
      lastSeen: Number(r.lastSeen) || 0,
      hits: Number(r.hits) || 0,
    });
    loaded += 1;
  }
  return loaded;
}

/** The live record for one visitor id, or null. */
export function getVisitor(vid) {
  return visitors.get(vid) || null;
}

/** Test helper. */
export function clearVisitors() {
  visitors.clear();
}

/**
 * Small, honest user agent reader: names the common browsers and OSes and
 * says "Unknown" otherwise, rather than pretending to a full UA parser.
 */
export function parseUserAgent(ua = '') {
  let browser = 'Unknown browser';
  let m;
  if ((m = ua.match(/Edg(?:e|A|iOS)?\/([\d.]+)/))) browser = 'Edge ' + m[1].split('.')[0];
  else if ((m = ua.match(/OPR\/([\d.]+)/))) browser = 'Opera ' + m[1].split('.')[0];
  else if ((m = ua.match(/SamsungBrowser\/([\d.]+)/))) browser = 'Samsung Internet ' + m[1].split('.')[0];
  else if ((m = ua.match(/Firefox\/([\d.]+)/))) browser = 'Firefox ' + m[1].split('.')[0];
  else if ((m = ua.match(/CriOS\/([\d.]+)/))) browser = 'Chrome (iOS) ' + m[1].split('.')[0];
  else if ((m = ua.match(/Chrome\/([\d.]+)/))) browser = 'Chrome ' + m[1].split('.')[0];
  else if (/Safari\//.test(ua) && (m = ua.match(/Version\/([\d.]+)/))) browser = 'Safari ' + m[1].split('.')[0];

  let os = 'Unknown OS';
  if (/Windows NT 10/.test(ua)) os = 'Windows 10/11';
  else if (/Windows NT 6\.3/.test(ua)) os = 'Windows 8.1';
  else if (/Windows/.test(ua)) os = 'Windows';
  else if (/iPhone|iPad|iPod/.test(ua)) os = 'iOS';
  else if (/Mac OS X/.test(ua)) os = 'macOS';
  else if (/Android ([\d.]+)/.test(ua)) os = 'Android ' + ua.match(/Android ([\d.]+)/)[1].split('.')[0];
  else if (/Android/.test(ua)) os = 'Android';
  else if (/CrOS/.test(ua)) os = 'ChromeOS';
  else if (/Linux/.test(ua)) os = 'Linux';

  const device = /iPad|Tablet/.test(ua) ? 'Tablet'
    : /Mobi|iPhone|Android.*Mobile/.test(ua) ? 'Mobile'
    : 'Desktop';

  return { browser, os, device };
}
