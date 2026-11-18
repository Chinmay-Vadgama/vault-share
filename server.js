'use strict';
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { Pool } = require('pg');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

// ---------- config ----------
const PORT = process.env.PORT || 3000;
const MAX_MB = +process.env.MAX_UPLOAD_MB || 100;
const MAX_ATTEMPTS = +process.env.MAX_KEY_ATTEMPTS || 5;
const MAX_TTL_MIN = +process.env.MAX_TTL_MINUTES || 60;
const DEFAULT_TTL_MIN = 5;
// optional malware scanner (your other Render API service)
const SCAN_URL = process.env.SCAN_URL || '';
const SCAN_KEY = process.env.SCAN_API_KEY || '';
const SCAN_AUTH_HEADER = process.env.SCAN_AUTH_HEADER || ''; // e.g. X-API-Key; empty = "Authorization: Bearer <key>"
const SCAN_FIELD = process.env.SCAN_FILE_FIELD || 'file';
const SCAN_HEALTH_URL = process.env.SCAN_HEALTH_URL || '';   // optional GET endpoint used to wake a sleeping scanner
const SCAN_TIMEOUT = +process.env.SCAN_TIMEOUT_MS || 90_000; // free services can take ~60s to cold start
const SCAN_FAIL_OPEN = process.env.SCAN_FAIL_OPEN === 'true'; // default: reject uploads if the scanner is unavailable
if (!SCAN_URL) console.warn('SCAN_URL not set: malware scanning is DISABLED');
const TS_SITE = process.env.TURNSTILE_SITE_KEY || '', TS_SECRET = process.env.TURNSTILE_SECRET_KEY || '';
const TS_ON = !!(TS_SITE && TS_SECRET);
if (!TS_ON) console.warn('Turnstile keys not set: bot protection is DISABLED');
const E2E_POLICY = ['off', 'required'].includes(process.env.E2E_POLICY) ? process.env.E2E_POLICY : 'optional';
const BIND_IP = process.env.BIND_DOWNLOAD_IP !== 'false'; // download must come from the IP that entered the passphrase
const MIN_PASS = Math.max(8, +process.env.MIN_PASSPHRASE_LEN || 10);
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASS || ADMIN_PASS.length < 12) { console.error('ADMIN_PASSWORD (12+ chars) is required'); process.exit(1); }
if (!process.env.DATABASE_URL) { console.error('DATABASE_URL is required'); process.exit(1); }

const DIR = path.join(os.tmpdir(), 'vault-files');
fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL) ? false : { rejectUnauthorized: false } });

const ID_RE = /^[A-Za-z0-9_-]{22}$/;
const rid = (n = 16) => crypto.randomBytes(n).toString('base64url');
const sha = s => crypto.createHash('sha256').update(s).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const scrypt = (k, salt) => new Promise((ok, no) => crypto.scrypt(k, salt, 32, (e, d) => e ? no(e) : ok(d)));
const CODE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I
const genCode = () => Array.from({ length: 8 }, () => CODE_CHARS[crypto.randomInt(CODE_CHARS.length)]).join('');
const codeNorm = s => String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
const codeHash = c => crypto.createHash('sha256').update(c).digest('hex');
const passOk = p => typeof p === 'string' && p.length >= MIN_PASS && p.length <= 128 && new Set(p).size >= 6;

// ---------- db + logging ----------
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS transfers(
      id TEXT PRIMARY KEY, file_name TEXT, size BIGINT, mime TEXT,
      key_hash BYTEA, key_salt BYTEA, status TEXT NOT NULL, attempts INT DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT now(), expires_at TIMESTAMPTZ, sender_ip TEXT,
      downloaded_at TIMESTAMPTZ, downloaded_ip TEXT, purged_at TIMESTAMPTZ, purge_reason TEXT);
    CREATE TABLE IF NOT EXISTS events(
      id BIGSERIAL PRIMARY KEY, ts TIMESTAMPTZ DEFAULT now(), event TEXT NOT NULL,
      transfer_id TEXT, ip TEXT, user_agent TEXT, details JSONB);
    CREATE INDEX IF NOT EXISTS events_ts ON events(ts DESC);
    ALTER TABLE transfers ADD COLUMN IF NOT EXISTS code_hash TEXT;
    ALTER TABLE transfers ADD COLUMN IF NOT EXISTS e2e BOOLEAN DEFAULT false;
    CREATE UNIQUE INDEX IF NOT EXISTS transfers_code ON transfers(code_hash);`);
}
async function log(req, event, transferId, details) {
  try {
    await pool.query('INSERT INTO events(event,transfer_id,ip,user_agent,details) VALUES($1,$2,$3,$4,$5)',
      [event, transferId || null, req ? req.ip : 'system', req ? String(req.get('user-agent') || '').slice(0, 300) : null, details ? JSON.stringify(details) : null]);
  } catch (e) { console.error('log failed', e.message); }
}
async function purge(id, reason, req) {
  try { await fs.promises.unlink(path.join(DIR, id)); } catch (e) { if (e.code !== 'ENOENT') console.error(e.message); }
  const r = await pool.query("UPDATE transfers SET status='purged',purged_at=now(),purge_reason=$2 WHERE id=$1 AND status<>'purged' RETURNING id", [id, reason]);
  if (r.rowCount) await log(req, 'PURGED', id, { reason });
}

// ---------- strict video validation (magic bytes + extension must agree) ----------
const MP4_BRANDS = ['isom', 'iso2', 'iso4', 'iso5', 'iso6', 'mp41', 'mp42', 'avc1', 'M4V ', 'M4VH', 'M4VP', 'qt  ', 'dash', 'mmp4', '3gp4', '3gp5', '3gp6', '3g2a', 'MSNV', 'f4v '];
function sniffVideo(buf, ext) {
  const a = (s, e) => buf.subarray(s, e).toString('latin1');
  if (buf.length < 16) return null;
  if (a(4, 8) === 'ftyp' && MP4_BRANDS.includes(a(8, 12)))
    return ['mp4', 'm4v', '3gp', '3g2'].includes(ext) ? 'video/mp4' : ext === 'mov' ? 'video/quicktime' : null;
  if (buf.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3])))
    return ext === 'webm' ? 'video/webm' : ext === 'mkv' ? 'video/x-matroska' : null;
  if (a(0, 4) === 'RIFF' && a(8, 12) === 'AVI ') return ext === 'avi' ? 'video/x-msvideo' : null;
  return null;
}
const EXTS = ['mp4', 'm4v', 'mov', '3gp', '3g2', 'webm', 'mkv', 'avi'];
const extOf = n => path.extname(n || '').slice(1).toLowerCase();

// ---------- malware scanning ----------
// Adapt this function if your scanner replies differently. Only an explicit "clean" passes.
function verdict(j) {
  if (!j || typeof j !== 'object') return { error: 'unrecognised_response' };
  if (typeof j.infected === 'boolean') return { clean: !j.infected, reason: j.signature || j.virus || 'infected' };
  if (typeof j.clean === 'boolean') return { clean: j.clean, reason: j.reason || 'not_clean' };
  if (typeof j.malicious === 'number') return { clean: j.malicious === 0, reason: 'malicious_detections' };
  const st = String(j.status || j.result || j.verdict || '').toLowerCase();
  if (['ok', 'clean', 'safe', 'passed'].includes(st)) return { clean: true };
  if (['found', 'infected', 'malicious', 'unsafe', 'failed'].includes(st)) return { clean: false, reason: j.signature || j.virus || st };
  return { error: 'unrecognised_response' };
}
async function scanFile(file, name) {
  try {
    const fd = new FormData();
    fd.append(SCAN_FIELD, await fs.openAsBlob(file), name.replace(/[^A-Za-z0-9._-]/g, '_')); // streamed from disk, not loaded into RAM
    const headers = {};
    if (SCAN_KEY) { if (SCAN_AUTH_HEADER) headers[SCAN_AUTH_HEADER] = SCAN_KEY; else headers.Authorization = 'Bearer ' + SCAN_KEY; }
    const r = await fetch(SCAN_URL, { method: 'POST', body: fd, headers, signal: AbortSignal.timeout(SCAN_TIMEOUT) });
    if (!r.ok) return { error: 'http_' + r.status };
    return verdict(await r.json().catch(() => null));
  } catch (e) { return { error: e.name === 'TimeoutError' ? 'timeout' : 'network' }; }
}

// ---------- bot protection (Cloudflare Turnstile) ----------
async function human(req) {
  if (!TS_ON) return true;
  const token = String(req.get('x-turnstile-token') || '').slice(0, 2048);
  if (!token) return false;
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: new URLSearchParams({ secret: TS_SECRET, response: token, remoteip: req.ip }), signal: AbortSignal.timeout(8000) });
    return (await r.json()).success === true;
  } catch { return false; }
}
async function requireHuman(req, res, next) {
  if (await human(req)) return next();
  await log(req, 'TURNSTILE_FAIL');
  res.status(403).json({ error: 'Verification failed. Reload the page and try again.' });
}

// ---------- app ----------
const app = express();
app.set('trust proxy', +process.env.TRUST_PROXY || 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: {
  'default-src': ["'self'"], 'script-src': ["'self'", 'https://challenges.cloudflare.com'],
  'frame-src': ['https://challenges.cloudflare.com'], 'connect-src': ["'self'", 'https://challenges.cloudflare.com'],
  'style-src': ["'self'", "'unsafe-inline'"], 'img-src': ["'self'", 'data:', 'blob:'],
  'object-src': ["'none'"], 'base-uri': ["'self'"], 'frame-ancestors': ["'none'"] } } }));
app.use('/api', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
app.get('/healthz', (req, res) => res.send('ok'));

const apiLimit = rateLimit({ windowMs: 60_000, limit: 30, standardHeaders: true, legacyHeaders: false });
const uploadLimit = rateLimit({ windowMs: 3600_000, limit: 20, standardHeaders: true, legacyHeaders: false });
const unlockLimit = rateLimit({ windowMs: 60_000, limit: 10, standardHeaders: true, legacyHeaders: false });

const upload = multer({
  storage: multer.diskStorage({
    destination: DIR,
    filename: (req, f, cb) => { req.tid = rid(); cb(null, req.tid); }
  }),
  limits: { fileSize: Math.ceil(MAX_MB * 1024 * 1024 * 1.01) + 64, files: 1, fields: 6 }, // small allowance for E2E overhead
  fileFilter: (req, f, cb) => (E2E_POLICY !== 'off' && req.body.e2e === '1') || (E2E_POLICY !== 'required' && EXTS.includes(extOf(f.originalname))) ? cb(null, true) : cb(new Error('BAD_TYPE'))
});

app.get('/api/config', (req, res) => res.json({ maxMb: MAX_MB, e2e: E2E_POLICY, turnstileSiteKey: TS_ON ? TS_SITE : '', minPass: MIN_PASS, defaultTtl: DEFAULT_TTL_MIN, maxTtl: MAX_TTL_MIN }));

app.get('/api/warm', apiLimit, (req, res) => { // sender page calls this so a sleeping scanner wakes up early
  if (SCAN_HEALTH_URL) fetch(SCAN_HEALTH_URL, { signal: AbortSignal.timeout(60_000) }).catch(() => {});
  res.status(204).end();
});

app.post('/api/upload', uploadLimit, requireHuman, (req, res) => {
  upload.single('video')(req, res, async err => {
    const drop = () => req.file && fs.promises.unlink(req.file.path).catch(() => {});
    try {
      if (err) {
        await log(req, 'UPLOAD_REJECTED', null, { reason: err.code || err.message });
        return res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? `File exceeds ${MAX_MB} MB` : (E2E_POLICY === 'required' ? 'Uploads must be end-to-end encrypted' : 'Only video files (mp4, m4v, mov, 3gp, webm, mkv, avi) are allowed') });
      }
      const key = String(req.body.key || '');
      if (!req.file) return res.status(400).json({ error: 'Choose a video file' });
      if (!passOk(key)) { await drop(); return res.status(400).json({ error: `Passphrase must be ${MIN_PASS} to 128 characters with some variety` }); }
      const fh = await fs.promises.open(req.file.path, 'r');
      const head = Buffer.alloc(16); await fh.read(head, 0, 16, 0); await fh.close();
      const e2e = req.body.e2e === '1' && E2E_POLICY !== 'off';
      if (!e2e && (E2E_POLICY === 'required' || req.file.size > MAX_MB * 1048576)) { await drop(); return res.status(400).json({ error: E2E_POLICY === 'required' ? 'Uploads must be end-to-end encrypted' : `File exceeds ${MAX_MB} MB` }); }
      const mime = e2e ? (head.toString('latin1', 0, 4) === 'VSE1' ? 'application/octet-stream' : null) : sniffVideo(head, extOf(req.file.originalname));
      if (!mime) {
        await drop();
        await log(req, 'UPLOAD_REJECTED', null, { reason: 'content_mismatch', name: req.file.originalname.slice(0, 100) });
        return res.status(400).json({ error: 'File content is not a valid video matching its extension' });
      }
      let scan = e2e ? 'e2e_not_scanned' : 'disabled';
      if (SCAN_URL && !e2e) {
        const r = await scanFile(req.file.path, req.file.originalname);
        if (r.error) {
          await log(req, 'SCAN_ERROR', null, { reason: r.error });
          if (!SCAN_FAIL_OPEN) { await drop(); return res.status(503).json({ error: 'Malware scanner unavailable. Try again in a minute.' }); }
          scan = 'unscanned';
        } else if (!r.clean) {
          await drop();
          await log(req, 'UPLOAD_REJECTED', null, { reason: 'malware_scan', detail: String(r.reason || '').slice(0, 100) });
          return res.status(400).json({ error: 'File failed the malware scan and was deleted' });
        } else scan = 'clean';
      }
      const ttl = Math.min(Math.max(Math.round(+req.body.ttl) || DEFAULT_TTL_MIN, 1), MAX_TTL_MIN);
      const code = genCode();
      const salt = crypto.randomBytes(16);
      const name = e2e ? 'encrypted.bin' : req.file.originalname.replace(/[^A-Za-z0-9._-]/g, '_').slice(-80) || 'video';
      await pool.query(`INSERT INTO transfers(id,file_name,size,mime,key_hash,key_salt,status,expires_at,sender_ip,code_hash,e2e)
        VALUES($1,$2,$3,$4,$5,$6,'ready',now()+($7||' minutes')::interval,$8,$9,$10)`,
        [req.tid, name, req.file.size, mime, await scrypt(key, salt), salt, String(ttl), req.ip, codeHash(code), e2e]);
      await log(req, 'UPLOAD_OK', req.tid, { name, size: req.file.size, mime, ttl_minutes: ttl, scan, e2e });
      res.json({ code: code.slice(0, 4) + '-' + code.slice(4), page: `${req.protocol}://${req.get('host')}/get`, ttl, e2e });
    } catch (e) { console.error(e); await drop(); res.status(500).json({ error: 'Upload failed' }); }
  });
});

// ---------- single download page ----------
app.get('/get', async (req, res) => {
  await log(req, 'PAGE_VIEW');
  res.sendFile(path.join(__dirname, 'public', 'receive.html'));
});

const tokens = new Map(); // one-time download tokens, 60s lifetime
const fails = new Map();  // ip -> failure window; 10 failures in 15 min = 15 min block
const FAIL_MAX = 10, FAIL_WINDOW = 15 * 60_000, DUMMY_SALT = crypto.randomBytes(16);
setInterval(() => {
  const n = Date.now();
  for (const [k, v] of tokens) if (v.exp < n) tokens.delete(k);
  for (const [k, v] of fails) if (v.until < n && n - v.first > FAIL_WINDOW) fails.delete(k);
}, 30_000).unref();
function noteFail(ip) {
  const n = Date.now(); let f = fails.get(ip);
  if (!f || n - f.first > FAIL_WINDOW) { f = { n: 0, first: n, until: 0 }; fails.set(ip, f); }
  if (++f.n >= FAIL_MAX) f.until = n + FAIL_WINDOW;
}

app.post('/api/unlock', unlockLimit, express.json({ limit: '1kb' }), async (req, res) => {
  const GENERIC = { error: 'Invalid code or passphrase' };
  try {
    if (!(await human(req))) { await log(req, 'TURNSTILE_FAIL'); return res.status(403).json({ error: 'Verification failed. Reload the page and try again.' }); }
    const f = fails.get(req.ip);
    if (f && f.until > Date.now()) { await log(req, 'IP_BLOCKED'); return res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' }); }
    const code = codeNorm(req.body && req.body.code), key = String(req.body && req.body.key || ''), keyOk = passOk(key);
    const t = code.length === 8 ? (await pool.query("SELECT * FROM transfers WHERE code_hash=$1 AND status='ready' AND expires_at>now()", [codeHash(code)])).rows[0] : null;
    if (!t) { // same cost and same answer as a wrong key, so codes cannot be probed
      await scrypt(keyOk ? key : '000000', DUMMY_SALT); noteFail(req.ip);
      await log(req, 'UNLOCK_UNKNOWN_CODE');
      return res.status(403).json(GENERIC);
    }
    const ok = keyOk && crypto.timingSafeEqual(await scrypt(key, t.key_salt), t.key_hash);
    if (!ok) {
      noteFail(req.ip);
      const a = (await pool.query('UPDATE transfers SET attempts=attempts+1 WHERE id=$1 RETURNING attempts', [t.id])).rows[0].attempts;
      await log(req, 'UNLOCK_FAIL', t.id, { attempt: a });
      if (a >= MAX_ATTEMPTS) { await purge(t.id, 'too_many_key_attempts', req); return res.status(403).json({ error: 'Too many wrong keys. The file has been destroyed.' }); }
      return res.status(403).json(GENERIC);
    }
    const token = rid(24);
    tokens.set(token, { id: t.id, exp: Date.now() + 60_000, ip: req.ip });
    await log(req, 'UNLOCK_OK', t.id);
    res.json({ url: `/api/file?token=${token}`, e2e: !!t.e2e });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/file', async (req, res) => {
  const tkn = String(req.query.token || ''), tk = tokens.get(tkn);
  if (tk && BIND_IP && tk.ip !== req.ip) { // token only works from the IP that entered the passphrase
    await log(req, 'DOWNLOAD_DENIED', tk.id, { reason: 'ip_mismatch', unlock_ip: tk.ip });
    return res.status(403).send('This download must start from the device that entered the passphrase');
  }
  tokens.delete(tkn);
  if (!tk || tk.exp < Date.now()) { await log(req, 'DOWNLOAD_DENIED'); return res.status(403).send('Invalid or expired download token'); }
  const id = tk.id;
  // atomic claim: only one request can ever flip ready -> downloading
  const c = await pool.query("UPDATE transfers SET status='downloading',downloaded_at=now(),downloaded_ip=$2 WHERE id=$1 AND status='ready' AND expires_at>now() RETURNING *", [id, req.ip]);
  const t = c.rows[0];
  if (!t) return res.status(410).send('This file has already been downloaded or has expired');
  await log(req, 'DOWNLOAD_START', id, { size: t.size });
  res.set({ 'Content-Type': t.mime, 'Content-Length': t.size, 'Content-Disposition': `attachment; filename="${t.file_name}"`, 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' });
  const rs = fs.createReadStream(path.join(DIR, id));
  rs.on('error', async () => { await purge(id, 'read_error', req); res.destroy(); });
  res.on('close', async () => {
    const done = res.writableFinished;
    await log(req, done ? 'DOWNLOAD_COMPLETE' : 'DOWNLOAD_ABORTED', id);
    await purge(id, done ? 'downloaded' : 'download_aborted', req);
  });
  rs.pipe(res);
});

// ---------- admin ----------
const adminFailLimit = rateLimit({ windowMs: 15 * 60_000, limit: 10, skipSuccessfulRequests: true, standardHeaders: true, legacyHeaders: false });
async function adminAuth(req, res, next) {
  const m = /^Basic (.+)$/.exec(req.get('authorization') || '');
  const [u, ...p] = m ? Buffer.from(m[1], 'base64').toString().split(':') : [''];
  if (m && safeEq(u, ADMIN_USER) && safeEq(p.join(':'), ADMIN_PASS)) return next();
  await log(req, 'ADMIN_AUTH_FAIL', null, { user: String(u).slice(0, 40) });
  res.set('WWW-Authenticate', 'Basic realm="Vault admin"').status(401).send('Authentication required');
}
const csrf = (req, res, next) => req.get('x-requested-with') === 'vault' ? next() : res.status(403).json({ error: 'Forbidden' });

app.use('/admin', adminFailLimit, adminAuth);
app.use('/admin', express.static(path.join(__dirname, 'admin-ui'), { index: 'admin.html' }));

app.get('/admin/api/stats', async (req, res) => {
  const s = await pool.query('SELECT status, count(*)::int n FROM transfers GROUP BY status');
  const e = await pool.query("SELECT event, count(*)::int n FROM events WHERE ts>now()-interval '24 hours' GROUP BY event");
  res.json({ transfers: Object.fromEntries(s.rows.map(r => [r.status, r.n])), events24h: Object.fromEntries(e.rows.map(r => [r.event, r.n])) });
});
app.get('/admin/api/transfers', async (req, res) => {
  res.json((await pool.query('SELECT id,file_name,size,e2e,status,attempts,created_at,expires_at,sender_ip,downloaded_at,downloaded_ip,purged_at,purge_reason FROM transfers ORDER BY created_at DESC LIMIT 200')).rows);
});
app.get('/admin/api/events', async (req, res) => {
  res.json((await pool.query('SELECT id,ts,event,transfer_id,ip,user_agent,details FROM events ORDER BY id DESC LIMIT $1', [Math.min(+req.query.limit || 200, 1000)])).rows);
});
app.post('/admin/api/transfers/:id/purge', csrf, async (req, res) => {
  if (!ID_RE.test(req.params.id)) return res.status(400).json({ error: 'Bad id' });
  await log(req, 'ADMIN_PURGE', req.params.id);
  await purge(req.params.id, 'admin', req);
  res.json({ ok: true });
});
const csvCell = v => { let s = v == null ? '' : typeof v === 'object' && !(v instanceof Date) ? JSON.stringify(v) : v instanceof Date ? v.toISOString() : String(v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
app.get('/admin/api/logs.:fmt(csv|json)', async (req, res) => {
  const rows = (await pool.query('SELECT id,ts,event,transfer_id,ip,user_agent,details FROM events ORDER BY id')).rows;
  await log(req, 'ADMIN_LOGS_EXPORT', null, { format: req.params.fmt, rows: rows.length });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  res.set('Content-Disposition', `attachment; filename="vault-logs-${stamp}.${req.params.fmt}"`);
  if (req.params.fmt === 'json') return res.type('json').send(JSON.stringify(rows, null, 2));
  const cols = ['id', 'ts', 'event', 'transfer_id', 'ip', 'user_agent', 'details'];
  res.type('csv').send([cols.join(','), ...rows.map(r => cols.map(c => csvCell(r[c])).join(','))].join('\n'));
});

// ---------- static (public) ----------
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Server error' }); });

// ---------- housekeeping ----------
async function sweep() {
  try {
    const r = await pool.query("SELECT id FROM transfers WHERE status='ready' AND expires_at<now()");
    for (const { id } of r.rows) await purge(id, 'expired');
    for (const f of fs.readdirSync(DIR)) { // stray files (e.g. aborted uploads)
      const st = fs.statSync(path.join(DIR, f));
      if (Date.now() - st.mtimeMs > 3600_000 && !(await pool.query("SELECT 1 FROM transfers WHERE id=$1 AND status IN ('ready','downloading')", [f])).rowCount) fs.unlink(path.join(DIR, f), () => {});
    }
  } catch (e) { console.error('sweep', e.message); }
}
async function reconcile() { // free tier disk is ephemeral: records whose file vanished get closed out
  const r = await pool.query("SELECT id,status FROM transfers WHERE status IN ('ready','downloading')");
  for (const t of r.rows) if (t.status === 'downloading' || !fs.existsSync(path.join(DIR, t.id))) await purge(t.id, 'file_lost_on_restart');
}
initDb().then(reconcile).then(() => {
  setInterval(sweep, 15_000).unref();
  app.listen(PORT, () => console.log('Vault share on :' + PORT));
}).catch(e => { console.error(e); process.exit(1); });
