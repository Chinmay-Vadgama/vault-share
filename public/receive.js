const f = $('f'), msg = $('msg'), go = $('go');
const show = (t, c) => { msg.className = 'msg ' + c; msg.textContent = t; };
const [code, keyB64 = '', nameB64 = ''] = location.hash.slice(1).split('.');
if (code) $('code').value = code;
initPage();
f.addEventListener('submit', async e => {
  e.preventDefault();
  if (humanMissing()) return show('Complete the verification check first.', 'bad');
  go.disabled = true; let finished = false;
  try {
    const r = await fetch('/api/unlock', { method: 'POST', headers: { 'Content-Type': 'application/json', ...humanHeaders() }, body: JSON.stringify({ code: $('code').value, key: $('pass').value }) });
    const d = await r.json();
    if (!r.ok) { show(d.error || 'Could not unlock', 'bad'); finished = /destroyed|Too many failed/.test(d.error || ''); return; }
    if (!d.e2e) { f.classList.add('hidden'); show('Accepted. Your download is starting. This transfer is now single-use and will be deleted.', 'ok'); finished = true; location.href = d.url; return; }
    if (!keyB64) return show('This transfer is end-to-end encrypted. Open the full share link from the sender, which contains the decryption key. Nothing was downloaded.', 'bad');
    show('Downloading and decrypting in your browser.', 'ok'); finished = true;
    const fr = await fetch(d.url);
    if (!fr.ok) throw new Error(`Download failed (${fr.status}). ${fr.status === 403 ? 'It must start from the device that entered the passphrase.' : ''}`);
    const plain = await e2eDecrypt(await fr.blob(), unb64u(keyB64));
    const name = safeName(nameB64 ? dec.decode(unb64u(nameB64)) : 'video.mp4');
    const mime = sniffVideo(new Uint8Array(await plain.slice(0, 16).arrayBuffer()), extOf(name));
    if (!mime) throw new Error('The decrypted file is not a valid video matching its name, so it was not saved.');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([plain], { type: mime })); a.download = name; document.body.append(a); a.click(); a.remove();
    f.classList.add('hidden'); show('Decrypted and saved. The transfer has been deleted from the server.', 'ok');
  } catch (err) { show(err.message || 'Something went wrong', 'bad'); }
  finally { go.disabled = finished; resetHuman(); }
});
