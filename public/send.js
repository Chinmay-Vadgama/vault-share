const f = $('f'), msg = $('msg'), p = $('p'), go = $('go');
const show = (t, c) => { msg.className = 'msg ' + c; msg.replaceChildren(t); };
const mk = (tag, text, cls) => { const e = document.createElement(tag); e.textContent = text; if (cls) e.className = cls; return e; };
fetch('/api/warm').catch(() => {});
initPage().then(c => {
  $('minp').textContent = c.minPass; $('pass').minLength = c.minPass;
  if (c.e2e === 'off') $('e2ewrap').hidden = true;
  if (c.e2e === 'required') { $('e2e').checked = true; $('e2e').disabled = true; }
});
$('gen').onclick = () => { $('pass').value = genPass(); $('pass').type = 'text'; };

function upload(fd, e2e) {
  return new Promise((ok, no) => {
    const x = new XMLHttpRequest();
    x.open('POST', '/api/upload');
    const h = humanHeaders(); for (const k in h) x.setRequestHeader(k, h[k]);
    x.upload.onprogress = ev => { if (ev.lengthComputable) p.value = ev.loaded / ev.total * 100; };
    x.upload.onload = () => show(e2e ? 'Uploaded. Finishing up.' : 'Scanning for malware. This can take a minute.', 'ok');
    x.onerror = () => no(new Error('Network error, or the verification check failed. Reload and try again.'));
    x.onload = () => { let r = {}; try { r = JSON.parse(x.responseText); } catch {} x.status === 200 ? ok(r) : no(new Error(r.error || 'Upload failed')); };
    x.send(fd);
  });
}

f.addEventListener('submit', async e => {
  e.preventDefault();
  const file = $('video').files[0], e2e = $('e2e').checked && !$('e2e').hidden;
  if (humanMissing()) return show('Complete the verification check first.', 'bad');
  go.disabled = true; msg.className = 'msg hidden'; p.value = 0; p.classList.remove('hidden');
  try {
    if (file.size > cfg.maxMb * 1048576) throw new Error(`File exceeds ${cfg.maxMb} MB`);
    if (!sniffVideo(new Uint8Array(await file.slice(0, 16).arrayBuffer()), extOf(file.name))) throw new Error('This is not a recognised video file matching its extension');
    const fd = new FormData(); let keyB64 = '';
    if (e2e) fd.append('e2e', '1'); // must come before the file field
    fd.append('key', $('pass').value); fd.append('ttl', $('ttl').value);
    if (e2e) {
      show('Encrypting in your browser.', 'ok');
      const kb = crypto.getRandomValues(new Uint8Array(32)); keyB64 = b64u(kb);
      fd.append('video', await e2eEncrypt(file, kb), 'encrypted.bin');
    } else fd.append('video', file);
    const r = await upload(fd, e2e);
    const link = `${r.page}#${r.code}` + (e2e ? `.${keyB64}.${b64u(enc.encode(safeName(file.name)))}` : '');
    const box = document.createElement('div');
    const b = mk('button', 'Copy link'); b.type = 'button';
    b.onclick = () => navigator.clipboard.writeText(link).then(() => b.textContent = 'Copied');
    box.append(mk('div', 'Uploaded. Send the recipient this link:'), mk('div', link, 'link'), b,
      mk('div', `Send your passphrase separately. Everything is deleted in ${r.ttl} minute(s) if not downloaded.` + (e2e ? ' The decryption key is inside the link and never reaches the server.' : ''), 'hint'));
    show(box, 'ok'); f.reset();
  } catch (err) { show(err.message || 'Upload failed', 'bad'); }
  finally { go.disabled = false; resetHuman(); }
});
