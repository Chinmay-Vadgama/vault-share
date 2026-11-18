const id = location.pathname.split('/').pop();
const f = document.getElementById('f'), msg = document.getElementById('msg'), go = document.getElementById('go');
const show = (t, c) => { msg.className = 'msg ' + c; msg.textContent = t; };
fetch(`/api/d/${encodeURIComponent(id)}/info`).then(r => r.json()).then(d => {
  if (d.available) f.classList.remove('hidden'); else show('This link is no longer available. It was already downloaded, expired, or never existed.', 'bad');
}).catch(() => show('Could not reach the server. Reload to try again.', 'bad'));
f.addEventListener('submit', async e => {
  e.preventDefault(); go.disabled = true;
  try {
    const r = await fetch(`/api/d/${encodeURIComponent(id)}/unlock`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key: document.getElementById('key').value }) });
    const d = await r.json();
    if (!r.ok) {
      show(d.error || 'Could not unlock', 'bad');
      if (r.status === 404 || /destroyed/.test(d.error || '')) f.classList.add('hidden'); else go.disabled = false;
      return;
    }
    f.classList.add('hidden'); show('Key accepted. Your download is starting. This link is now single-use and will stop working.', 'ok');
    location.href = d.url;
  } catch { show('Network error. Try again.', 'bad'); go.disabled = false; }
});
