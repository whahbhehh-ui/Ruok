/*
 * REAL HUB key server (no dependencies, Node 16+)
 *
 * Run:   node server.js
 * Env:   PORT         port (default 3000)
 *        ADMIN_KEY1   admin login layer 1 (required)
 *        ADMIN_KEY2   admin login layer 2 (required)
 *        PROXY_HOPS   proxies in front of this server (default 1; use 0 if exposed directly).
 *                     Only used for rate limiting - keys are locked by HWID, not IP.
 *        DATA_DIR     where data.json is saved (default: this folder)
 *
 * Files: index.html + logo.webp (admin page), payload.lua (your real script, only sent to valid keys)
 */
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = +process.env.PORT || 3000;
const ADMIN1 = process.env.ADMIN_KEY1;
const ADMIN2 = process.env.ADMIN_KEY2;
if (!ADMIN1 || !ADMIN2) {
  console.error('Set environment variables ADMIN_KEY1 and ADMIN_KEY2 (admin login layers 1 and 2).');
  process.exit(1);
}
const HOPS = process.env.PROXY_HOPS === undefined ? 1 : +process.env.PROXY_HOPS;
const DATA = path.join(process.env.DATA_DIR || __dirname, 'data.json');
const DAY = 86400000;

let db = { keys: [] };
try { db = JSON.parse(fs.readFileSync(DATA, 'utf8')); } catch (e) {}
if (!Array.isArray(db.keys)) db.keys = [];
// older IP-based locks are dropped: those keys can be activated again (and are then locked by HWID)
db.keys.forEach((k) => { if (k.lock && !k.lock.hwid) k.lock = null; });
function save() {
  const tmp = DATA + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DATA);
}

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const rnd = (n) => crypto.randomBytes(n).toString('hex');
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function genKey() {
  for (;;) {
    const b = crypto.randomBytes(16);
    let s = '';
    for (let i = 0; i < 16; i++) {
      s += ALPHA[b[i] % 32];
      if (i % 4 === 3 && i < 15) s += '-';
    }
    if (!db.keys.some((k) => k.key === s)) return s;
  }
}

function getIP(req) {
  let ip = req.socket.remoteAddress || '';
  if (HOPS > 0) {
    const xs = String(req.headers['x-forwarded-for'] || '').split(',').map((x) => x.trim()).filter(Boolean);
    if (xs.length) ip = xs[Math.max(0, xs.length - HOPS)];
  }
  return ip.replace(/^::ffff:/, '');
}

// simple rate limiter
const buckets = new Map();
function blocked(name, ip, max) {
  const b = buckets.get(name + '|' + ip);
  return !!b && Date.now() <= b.reset && b.n >= max;
}
function limited(name, ip, max, windowMs) {
  const id = name + '|' + ip, now = Date.now();
  let b = buckets.get(id);
  if (!b || now > b.reset) b = { n: 0, reset: now + windowMs };
  b.n++;
  buckets.set(id, b);
  return b.n > max;
}
setInterval(() => { const now = Date.now(); for (const [k, b] of buckets) if (now > b.reset) buckets.delete(k); }, 60000).unref();

// admin sessions
const tickets = new Map(); // after layer 1
const sessions = new Map(); // after layer 2
function cleanup() {
  const now = Date.now();
  for (const [k, v] of tickets) if (now > v) tickets.delete(k);
  for (const [k, v] of sessions) if (now > v) sessions.delete(k);
}
setInterval(cleanup, 60000).unref();
function isAdmin(req) {
  const t = req.headers['x-token'];
  const exp = t && sessions.get(t);
  return !!exp && Date.now() < exp;
}

function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve) => {
    let d = '';
    req.on('data', (c) => { d += c; if (d.length > 20000) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(d || '{}')); } catch (e) { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}
const clean = (k) => ({
  id: k.id, key: k.key, days: k.days, note: k.note, createdAt: k.createdAt, expiresAt: k.expiresAt,
  lock: k.lock ? { id: k.lock.hwid.slice(0, 12).toUpperCase(), boundAt: k.lock.boundAt } : null,
});
const expired = (k, now) => k.days > 0 && now >= k.expiresAt;

function payload() {
  try { return fs.readFileSync(path.join(__dirname, 'payload.lua'), 'utf8'); } catch (e) { return 'warn("payload.lua missing on server")'; }
}

// ---------- key check used by the Lua client ----------
function verify(req, body) {
  const key = String(body.key || '').trim().toUpperCase();
  const token = body.token ? String(body.token) : '';
  if (!key) return { ok: false, code: 'invalid' };
  const k = db.keys.find((x) => x.key === key);
  if (!k) return { ok: false, code: 'invalid' };
  const now = Date.now();
  if (expired(k, now)) return { ok: false, code: 'expired' };
  const raw = typeof body.hwid === 'string' ? body.hwid.trim() : '';
  if (raw.length < 6 || raw.length > 300) return { ok: false, code: 'nohwid' };
  const hwid = sha(raw).toString('hex'); // raw HWID is never stored

  if (!k.lock) {
    if (token) return { ok: false, code: 'reset' }; // admin reset this key: old local file is dead
    k.lock = { hwid, token: rnd(16), boundAt: now };  // first use: lock to this machine
    save();
  } else if (k.lock.hwid !== hwid) {
    return { ok: false, code: 'locked' };            // key already used on another machine
  }
  return { ok: true, token: k.lock.token, expiresAt: k.days ? k.expiresAt : null, script: payload() };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  const ip = getIP(req);

  if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
    fs.readFile(path.join(__dirname, 'index.html'), (err, buf) => {
      if (err) { res.writeHead(500); return res.end('index.html missing'); }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
      res.end(buf);
    });
    return;
  }
  if (req.method === 'GET' && p === '/logo.webp') {
    fs.readFile(path.join(__dirname, 'logo.webp'), (err, buf) => {
      if (err) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'Content-Type': 'image/webp', 'Cache-Control': 'public, max-age=86400' });
      res.end(buf);
    });
    return;
  }
  if (!p.startsWith('/api/')) { res.writeHead(404); return res.end('Not found'); }

  // ----- public: used by the Roblox script -----
  if (req.method === 'POST' && p === '/api/verify') {
    if (limited('verify', ip, 60, 60000)) return send(res, 429, { ok: false, code: 'rate' });
    return send(res, 200, verify(req, await readBody(req)));
  }

  if (req.method === 'GET' && p === '/api/ping') return send(res, 200, { ok: true });

  // ----- admin login (2 layers); only wrong attempts count toward the limit -----
  if (req.method === 'POST' && p === '/api/admin/step1') {
    if (blocked('login', ip, 10)) return send(res, 429, { ok: false, msg: 'ลองผิดหลายครั้ง รอ 10 นาที' });
    const b = await readBody(req);
    if (!same(b.k || '', ADMIN1)) { limited('login', ip, 10, 600000); return send(res, 401, { ok: false, msg: 'คีย์ไม่ถูกต้อง' }); }
    const ticket = rnd(24);
    tickets.set(ticket, Date.now() + 5 * 60000);
    return send(res, 200, { ok: true, ticket });
  }
  if (req.method === 'POST' && p === '/api/admin/step2') {
    if (blocked('login', ip, 10)) return send(res, 429, { ok: false, msg: 'ลองผิดหลายครั้ง รอ 10 นาที' });
    const b = await readBody(req);
    const exp = tickets.get(b.ticket);
    if (!exp || Date.now() > exp) return send(res, 401, { ok: false, msg: 'หมดเวลา กลับไปด่านที่ 1', restart: true });
    if (!same(b.k || '', ADMIN2)) { limited('login', ip, 10, 600000); return send(res, 401, { ok: false, msg: 'คีย์ไม่ถูกต้อง' }); }
    tickets.delete(b.ticket);
    const token = rnd(32);
    sessions.set(token, Date.now() + 12 * 3600000);
    return send(res, 200, { ok: true, token });
  }

  // ----- everything below needs admin -----
  if (!isAdmin(req)) return send(res, 401, { ok: false, msg: 'unauthorized' });

  if (req.method === 'POST' && p === '/api/admin/logout') {
    sessions.delete(req.headers['x-token']);
    return send(res, 200, { ok: true });
  }
  if (req.method === 'GET' && p === '/api/keys') {
    return send(res, 200, { ok: true, now: Date.now(), keys: db.keys.map(clean) });
  }
  if (req.method === 'POST' && p === '/api/keys') {
    const b = await readBody(req);
    const days = [0, 1, 2, 3, 4, 5, 7, 10, 30].includes(+b.days) ? +b.days : 1;
    const qty = Math.max(1, Math.min(100, parseInt(b.qty, 10) || 1));
    const note = String(b.note || '').slice(0, 60);
    const now = Date.now(), made = [];
    for (let i = 0; i < qty; i++) {
      const k = { id: rnd(8), key: genKey(), days, note, createdAt: now, expiresAt: days ? now + days * DAY : null, lock: null };
      db.keys.unshift(k);
      made.push(k.key);
    }
    save();
    return send(res, 200, { ok: true, made });
  }
  if (req.method === 'POST' && p === '/api/keys/delete-expired') {
    const now = Date.now(), before = db.keys.length;
    db.keys = db.keys.filter((k) => !expired(k, now));
    save();
    return send(res, 200, { ok: true, removed: before - db.keys.length });
  }
  if (req.method === 'DELETE' && p === '/api/keys') {
    db.keys = [];
    save();
    return send(res, 200, { ok: true });
  }
  const m = p.match(/^\/api\/keys\/([a-f0-9]+)(?:\/(reset-lock|reset-time))?$/);
  if (m) {
    const k = db.keys.find((x) => x.id === m[1]);
    if (!k) return send(res, 404, { ok: false, msg: 'not found' });
    if (req.method === 'DELETE' && !m[2]) {
      db.keys = db.keys.filter((x) => x !== k);
    } else if (req.method === 'POST' && m[2] === 'reset-lock') {
      k.lock = null; // the player's saved file stops working -> script asks for the key again
    } else if (req.method === 'POST' && m[2] === 'reset-time') {
      if (!k.days) return send(res, 400, { ok: false, msg: 'permanent key' });
      k.createdAt = Date.now();
      k.expiresAt = k.createdAt + k.days * DAY;
    } else return send(res, 405, { ok: false });
    save();
    return send(res, 200, { ok: true });
  }
  send(res, 404, { ok: false });
});

server.listen(PORT, () => console.log('REAL HUB key server on :' + PORT));
