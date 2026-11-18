# Vault share (Render free tier)

One-time video transfer: sender sets a 6-digit key, recipient enters it, first download destroys the file.

## Deploy
1. Push this folder to a GitHub repo.
2. Render dashboard > New > Blueprint > pick the repo (uses `render.yaml`: free web service + free Postgres).
3. In the service's Environment tab, copy the generated `ADMIN_PASSWORD`. Admin URL: `/admin` (HTTP Basic auth, user `admin`).

## Env vars
`ADMIN_USER`, `ADMIN_PASSWORD` (12+ chars), `DATABASE_URL`, `MAX_UPLOAD_MB` (100), `MAX_KEY_ATTEMPTS` (5), `MAX_TTL_HOURS` (48), `TRUST_PROXY` (1; raise if logs show a proxy IP instead of the visitor IP).

## Free-tier caveats
- Free web services sleep after ~15 min idle and have an ephemeral disk. A restart wipes un-downloaded files; the app marks them `file_lost_on_restart`. Logs live in Postgres and survive.
- Render's free Postgres has size and lifetime limits. Download logs regularly and check Render's current free-tier terms.
- The instance has 512 MB RAM; uploads stream to disk, not memory.

## Security behaviour
- Video check: extension allowlist AND magic bytes must agree (MP4/MOV/3GP via `ftyp` brand, WebM/MKV via EBML, AVI via RIFF). Mismatches are deleted and logged.
- Key: scrypt-hashed with per-file salt; 5 wrong attempts destroy the file; rate-limited per IP.
- Link ID is 128-bit random. Download needs a one-time 60s token; the DB claim is atomic so only one download can start. The file is purged when the stream ends or aborts (an interrupted download also consumes the file).
- Logged: UPLOAD_OK/REJECTED, LINK_VIEW, UNLOCK_OK/FAIL/UNAVAILABLE, DOWNLOAD_START/COMPLETE/ABORTED/DENIED, PURGED, ADMIN_AUTH_FAIL, ADMIN_PURGE, ADMIN_LOGS_EXPORT, each with IP, user agent and timestamp.
- TLS is provided by Render; files are not encrypted at rest on the instance disk.
