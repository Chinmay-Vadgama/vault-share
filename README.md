# Vault share (Render free tier)

One-time video transfer: one fixed download page (`/get`). The sender gets a random transfer code and sets a passphrase; the recipient enters both; the first download destroys the file. Default expiry: 5 minutes.

## Deploy
1. Push this folder to a GitHub repo.
2. Render dashboard > New > Blueprint > pick the repo (uses `render.yaml`: free web service + free Postgres).
3. In the service's Environment tab, copy the generated `ADMIN_PASSWORD`. Admin URL: `/admin` (HTTP Basic auth, user `admin`).

## Env vars
`ADMIN_USER`, `ADMIN_PASSWORD` (12+ chars), `DATABASE_URL`, `MAX_UPLOAD_MB` (100), `MAX_KEY_ATTEMPTS` (5), `MAX_TTL_MINUTES` (60; default expiry is 5), `TRUST_PROXY` (1; raise if logs show a proxy IP instead of the visitor IP).

## Malware scanning (optional)
Set `SCAN_URL` (full URL of your scanner's upload endpoint) and `SCAN_API_KEY`. Optional: `SCAN_AUTH_HEADER` (e.g. `X-API-Key`; default is `Authorization: Bearer`), `SCAN_FILE_FIELD` (default `file`), `SCAN_HEALTH_URL` (GET endpoint to wake it), `SCAN_TIMEOUT_MS` (90000), `SCAN_FAIL_OPEN` (default false = reject uploads when scanner is down). Edit `verdict()` in server.js if your scanner's JSON differs. Needs Node 20+.

## Extra protections
- **Turnstile** (bot protection on upload and unlock): create a free widget in Cloudflare (Turnstile), add your onrender.com hostname, then set `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY`. Unset = disabled. Fails closed if Cloudflare can't be reached.
- **End-to-end encryption** (`E2E_POLICY` = optional | required | off): the browser encrypts with AES-256-GCM; the key lives in the URL fragment (`/get#CODE.KEY.NAME`) and never reaches the server. The server cannot validate or malware-scan encrypted files, so the recipient's browser verifies the decrypted file is a real video before saving it. Use `required` only if you accept losing server-side scanning for everything.
- **IP binding** (`BIND_DOWNLOAD_IP`, default true): the download token only works from the IP that entered the passphrase. Set to false if users on switching IPv4/IPv6 networks are rejected.
- `MIN_PASSPHRASE_LEN` (10).

## Free-tier caveats
- Free web services sleep after ~15 min idle and have an ephemeral disk. A restart wipes un-downloaded files; the app marks them `file_lost_on_restart`. Logs live in Postgres and survive.
- Render's free Postgres has size and lifetime limits. Download logs regularly and check Render's current free-tier terms.
- The instance has 512 MB RAM; uploads stream to disk, not memory.

## Security behaviour
- Video check: extension allowlist AND magic bytes must agree (MP4/MOV/3GP via `ftyp` brand, WebM/MKV via EBML, AVI via RIFF). Mismatches are deleted and logged.
- Passphrase (10+ chars, 'Generate' gives ~70 bits): scrypt-hashed with per-file salt; 5 wrong attempts destroy the file; rate-limited per IP.
- Link ID is 128-bit random. Download needs a one-time 60s token; the DB claim is atomic so only one download can start. The file is purged when the stream ends or aborts (an interrupted download also consumes the file).
- Logged: UPLOAD_OK/REJECTED, LINK_VIEW, UNLOCK_OK/FAIL/UNAVAILABLE, DOWNLOAD_START/COMPLETE/ABORTED/DENIED, PURGED, ADMIN_AUTH_FAIL, ADMIN_PURGE, ADMIN_LOGS_EXPORT, each with IP, user agent and timestamp.
- TLS is provided by Render; files are not encrypted at rest on the instance disk.
- Lookup is by an 8-character random transfer code (stored only as a hash) plus the key, so keys cannot be swept across all active files. An IP is blocked for 15 minutes after 10 failed attempts. Unknown codes and wrong keys return the same message and take the same time.
