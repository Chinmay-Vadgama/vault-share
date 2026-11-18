const f = document.getElementById('f'), msg = document.getElementById('msg'), p = document.getElementById('p'), go = document.getElementById('go');
const show = (t, c) => { msg.className = 'msg ' + c; msg.replaceChildren(t); };
f.addEventListener('submit', e => {
  e.preventDefault();
  const x = new XMLHttpRequest();
  x.open('POST', '/api/upload');
  x.upload.onprogress = ev => { if (ev.lengthComputable) p.value = ev.loaded / ev.total * 100; };
  x.onloadstart = () => { go.disabled = true; p.classList.remove('hidden'); msg.className = 'msg hidden'; };
  x.onerror = () => { go.disabled = false; show('Network error. Try again.', 'bad'); };
  x.onload = () => {
    go.disabled = false;
    let r = {}; try { r = JSON.parse(x.responseText); } catch {}
    if (x.status !== 200) return show(r.error || 'Upload failed', 'bad');
    const box = document.createElement('div');
    const a = document.createElement('div'); a.textContent = 'Uploaded. Send this link to your recipient:';
    const l = document.createElement('div'); l.className = 'link'; l.textContent = r.link;
    const b = document.createElement('button'); b.type = 'button'; b.textContent = 'Copy link';
    b.onclick = () => navigator.clipboard.writeText(r.link).then(() => b.textContent = 'Copied');
    const n = document.createElement('div'); n.className = 'hint'; n.textContent = `Tell them your key separately. The link expires in ${r.ttl} hour(s) if unused.`;
    box.append(a, l, b, n); show(box, 'ok'); f.reset();
  };
  x.send(new FormData(f));
});
