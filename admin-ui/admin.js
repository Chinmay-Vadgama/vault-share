const H = { 'X-Requested-With': 'vault' };
const get = u => fetch(u, { headers: H }).then(r => r.json());
const fmt = v => v ? new Date(v).toLocaleString() : '';
function el(tag, text, cls) { const e = document.createElement(tag); if (text != null) e.textContent = text; if (cls) e.className = cls; return e; }
function table(t, cols, rows, extra) {
  const head = el('tr'); cols.forEach(c => head.append(el('th', c[0]))); if (extra) head.append(el('th', ''));
  t.replaceChildren(head);
  rows.forEach(r => {
    const tr = el('tr');
    cols.forEach(c => { const v = c[1](r); tr.append(el('td', v == null ? '' : String(v), c[2])); });
    if (extra) { const td = el('td'); const b = extra(r); if (b) td.append(b); tr.append(td); }
    t.append(tr);
  });
}
async function refresh() {
  const [s, tr, ev] = await Promise.all([get('/admin/api/stats'), get('/admin/api/transfers'), get('/admin/api/events?limit=200')]);
  const st = document.getElementById('stats'); st.replaceChildren();
  const add = (n, l) => { const d = el('div', null, 'stat'); d.append(el('b', n), el('span', l)); st.append(d); };
  ['ready', 'downloading', 'purged'].forEach(k => add(s.transfers[k] || 0, k + ' transfers'));
  [['UPLOAD_OK', 'uploads (24h)'], ['DOWNLOAD_COMPLETE', 'downloads (24h)'], ['UNLOCK_FAIL', 'wrong keys (24h)'], ['UPLOAD_REJECTED', 'rejected uploads (24h)'], ['ADMIN_AUTH_FAIL', 'admin login fails (24h)'], ['TURNSTILE_FAIL', 'bot checks failed (24h)']].forEach(([k, l]) => add(s.events24h[k] || 0, l));
  table(document.getElementById('tt'), [
    ['Created', r => fmt(r.created_at)], ['File', r => r.file_name], ['MB', r => (r.size / 1048576).toFixed(1)], ['E2E', r => r.e2e ? 'yes' : 'no'], ['Status', r => r.status],
    ['Wrong keys', r => r.attempts], ['Sender IP', r => r.sender_ip], ['Downloaded', r => fmt(r.downloaded_at)], ['Recipient IP', r => r.downloaded_ip],
    ['Expires', r => fmt(r.expires_at)], ['Purge reason', r => r.purge_reason], ['ID', r => r.id]
  ], tr, r => {
    if (r.status !== 'ready') return null;
    const b = el('button', 'Purge now', 'btn');
    b.onclick = async () => { if (confirm('Delete this file now?')) { await fetch(`/admin/api/transfers/${r.id}/purge`, { method: 'POST', headers: H }); refresh(); } };
    return b;
  });
  table(document.getElementById('et'), [
    ['Time', r => fmt(r.ts)], ['Event', r => r.event], ['IP', r => r.ip], ['Transfer', r => r.transfer_id],
    ['Details', r => r.details ? JSON.stringify(r.details) : ''], ['User agent', r => r.user_agent, 'ua']
  ], ev);
}
refresh(); setInterval(refresh, 15000);
