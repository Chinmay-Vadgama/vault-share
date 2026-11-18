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
const MAX_TTL_H = +process.env.MAX_TTL_HOURS || 48;
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
    CREATE INDEX IF NOT EXISTS events_ts ON events(ts DESC);`);
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

// ---------- app ----------
const app = express();
app.set('trust proxy', +process.env.TRUST_PROXY || 1);
app.disable('x-powered-by');
app.use(helmet());
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
  limits: { fileSize: MAX_MB * 1024 * 1024, files: 1, fields: 4 },
  fileFilter: (req, f, cb) => EXTS.includes(extOf(f.originalname)) ? cb(null, true) : cb(new Error('BAD_TYPE'))
});

app.post('/api/upload', uploadLimit, (req, res) => {
  upload.single('video')(req, res, async err => {
    const drop = () => req.file && fs.promises.unlink(req.file.path).catch(() => {});
    try {
      if (err) {
        await log(req, 'UPLOAD_REJECTED', null, { reason: err.code || err.message });
        return res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? `File exceeds ${MAX_MB} MB` : 'Only video files (mp4, m4v, mov, 3gp, webm, mkv, avi) are allowed' });
      }
      const key = String(req.body.key || '');
      if (!req.file) return res.status(400).json({ error: 'Choose a video file' });
      if (!/^\d{6}$/.test(key)) { await drop(); return res.status(400).json({ error: 'Key must be exactly 6 digits' }); }
      const fh = await fs.promises.open(req.file.path, 'r');
      const head = Buffer.alloc(16); await fh.read(head, 0, 16, 0); await fh.close();
      const mime = sniffVideo(head, extOf(req.file.originalname));
      if (!mime) {
        await drop();
        await log(req, 'UPLOAD_REJECTED', null, { reason: 'content_mismatch', name: req.file.originalname.slice(0, 100) });
        return res.status(400).json({ error: 'File content is not a valid video matching its extension' });
      }
      const ttl = Math.min(Math.max(+req.body.ttl || 24, 1), MAX_TTL_H);
      const salt = crypto.randomBytes(16);
      const name = req.file.originalname.replace(/[^A-Za-z0-9._-]/g, '_').slice(-80) || 'video';
      await pool.query(`INSERT INTO transfers(id,file_name,size,mime,key_hash,key_salt,status,expires_at,sender_ip)
        VALUES($1,$2,$3,$4,$5,$6,'ready',now()+($7||' hours')::interval,$8)`,
        [req.tid, name, req.file.size, mime, await scrypt(key, salt), salt, String(ttl), req.ip]);
      await log(req, 'UPLOAD_OK', req.tid, { name, size: req.file.size, mime, ttl_hours: ttl });
      res.json({ id: req.tid, link: `${req.protocol}://${req.get('host')}/d/${req.tid}`, ttl });
    } catch (e) { console.error(e); await drop(); res.status(500).json({ error: 'Upload failed' }); }
  });
});

app.get('/d/:id', async (req, res) => {
  await log(req, 'LINK_VIEW', ID_RE.test(req.params.id) ? req.params.id : null);
  res.sendFile(path.join(__dirname, 'public', 'receive.html'));
});

app.get('/api/d/:id/info', apiLimit, async (req, res) => {
  const { id } = req.params;
  if (!ID_RE.test(id)) return res.json({ available: false });
  const r = await pool.query("SELECT 1 FROM transfers WHERE id=$1 AND status='ready' AND expires_at>now()", [id]);
  res.json({ available: r.rowCount === 1 });
});

const tokens = new Map(); // one-time download tokens, 60s lifetime
setInterval(() => { const n = Date.now(); for (const [k, v] of tokens) if (v.exp < n) tokens.delete(k); }, 30_000).unref();

app.post('/api/d/:id/unlock', unlockLimit, express.json({ limit: '1kb' }), async (req, res) => {
  const { id } = req.params, key = String(req.body && req.body.key || '');
  try {
    if (!ID_RE.test(id)) return res.status(404).json({ error: 'This link is no longer available' });
    const t = (await pool.query("SELECT * FROM transfers WHERE id=$1 AND status='ready' AND expires_at>now()", [id])).rows[0];
    if (!t) { await log(req, 'UNLOCK_UNAVAILABLE', id); return res.status(404).json({ error: 'This link is no longer available' }); }
    const ok = /^\d{6}$/.test(key) && crypto.timingSafeEqual(await scrypt(key, t.key_salt), t.key_hash);
    if (!ok) {
      const a = (await pool.query('UPDATE transfers SET attempts=attempts+1 WHERE id=$1 RETURNING attempts', [id])).rows[0].attempts;
      await log(req, 'UNLOCK_FAIL', id, { attempt: a });
      if (a >= MAX_ATTEMPTS) { await purge(id, 'too_many_key_attempts', req); return res.status(403).json({ error: 'Too many wrong keys. The file has been destroyed.' }); }
      return res.status(403).json({ error: `Wrong key. ${MAX_ATTEMPTS - a} attempt(s) left.` });
    }
    const token = rid(24);
    tokens.set(token, { id, exp: Date.now() + 60_000 });
    await log(req, 'UNLOCK_OK', id);
    res.json({ url: `/api/d/${id}/file?token=${token}` });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/d/:id/file', async (req, res) => {
  const { id } = req.params, tk = tokens.get(String(req.query.token || ''));
  tokens.delete(String(req.query.token || ''));
  if (!tk || tk.id !== id || tk.exp < Date.now()) { await log(req, 'DOWNLOAD_DENIED', ID_RE.test(id) ? id : null); return res.status(403).send('Invalid or expired download token'); }
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
  res.json((await pool.query('SELECT id,file_name,size,status,attempts,created_at,expires_at,sender_ip,downloaded_at,downloaded_ip,purged_at,purge_reason FROM transfers ORDER BY created_at DESC LIMIT 200')).rows);
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
  setInterval(sweep, 60_000).unref();
  app.listen(PORT, () => console.log('Vault share on :' + PORT));
}).catch(e => { console.error(e); process.exit(1); });
