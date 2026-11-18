const $ = id => document.getElementById(id);
const CH = 1 << 20; // 1 MiB encryption chunks
const enc = new TextEncoder(), dec = new TextDecoder();
const b64u = b => btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const extOf = n => (String(n).split('.').pop() || '').toLowerCase();
const safeName = n => String(n).replace(/[^A-Za-z0-9._-]/g, '_').slice(-80) || 'video';

// same rules as the server: magic bytes must agree with the extension
const MP4B = ['isom', 'iso2', 'iso4', 'iso5', 'iso6', 'mp41', 'mp42', 'avc1', 'M4V ', 'M4VH', 'M4VP', 'qt  ', 'dash', 'mmp4', '3gp4', '3gp5', '3gp6', '3g2a', 'MSNV', 'f4v '];
function sniffVideo(b, ext) {
  if (b.length < 16) return null;
  const a = (s, e) => String.fromCharCode(...b.slice(s, e));
  if (a(4, 8) === 'ftyp' && MP4B.includes(a(8, 12))) return ['mp4', 'm4v', '3gp', '3g2'].includes(ext) ? 'video/mp4' : ext === 'mov' ? 'video/quicktime' : null;
  if (b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3) return ext === 'webm' ? 'video/webm' : ext === 'mkv' ? 'video/x-matroska' : null;
  if (a(0, 4) === 'RIFF' && a(8, 12) === 'AVI ') return ext === 'avi' ? 'video/x-msvideo' : null;
  return null;
}

// random passphrase, 12 chars from a 56-symbol alphabet (about 70 bits)
function genPass() {
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  return Array.from(crypto.getRandomValues(new Uint32Array(12)), v => A[v % A.length]).join('').match(/.{4}/g).join('-');
}

// end-to-end encryption: AES-256-GCM in 1 MiB chunks. Format: "VSE1" + 8-byte IV prefix + chunks.
// IV = prefix + chunk counter; the AAD marks the last chunk so truncation or reordering is detected.
const ivFor = (prefix, i) => { const v = new Uint8Array(12); v.set(prefix); new DataView(v.buffer).setUint32(8, i); return v; };
async function e2eEncrypt(file, keyBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const prefix = crypto.getRandomValues(new Uint8Array(8));
  const parts = [enc.encode('VSE1'), prefix], n = Math.max(1, Math.ceil(file.size / CH));
  for (let i = 0; i < n; i++) {
    const plain = await file.slice(i * CH, (i + 1) * CH).arrayBuffer();
    parts.push(new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivFor(prefix, i), additionalData: Uint8Array.of(i === n - 1 ? 1 : 0) }, key, plain)));
  }
  return new Blob(parts);
}
async function e2eDecrypt(blob, keyBytes) {
  try {
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    const head = new Uint8Array(await blob.slice(0, 12).arrayBuffer());
    if (head.length < 12 || dec.decode(head.slice(0, 4)) !== 'VSE1') throw new Error('format');
    const prefix = head.slice(4, 12), step = CH + 16, n = Math.max(1, Math.ceil((blob.size - 12) / step)), out = [];
    for (let i = 0; i < n; i++) {
      const c = await blob.slice(12 + i * step, 12 + (i + 1) * step).arrayBuffer();
      out.push(new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivFor(prefix, i), additionalData: Uint8Array.of(i === n - 1 ? 1 : 0) }, key, c)));
    }
    return new Blob(out);
  } catch { throw new Error('Decryption failed. The link may be incomplete or altered. This transfer has been consumed.'); }
}

// server config + Cloudflare Turnstile
let cfg = {}, tsToken = '';
async function initPage() {
  cfg = await (await fetch('/api/config')).json();
  if (cfg.turnstileSiteKey) {
    await new Promise(res => { const s = document.createElement('script'); s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'; s.onload = res; s.onerror = res; document.head.append(s); });
    if (window.turnstile) window.turnstile.render('#ts', { sitekey: cfg.turnstileSiteKey, callback: t => tsToken = t, 'expired-callback': () => tsToken = '', 'error-callback': () => tsToken = '' });
  }
  return cfg;
}
const humanHeaders = () => cfg.turnstileSiteKey ? { 'X-Turnstile-Token': tsToken } : {};
const humanMissing = () => !!cfg.turnstileSiteKey && !tsToken;
const resetHuman = () => { tsToken = ''; if (window.turnstile && cfg.turnstileSiteKey) window.turnstile.reset(); };
