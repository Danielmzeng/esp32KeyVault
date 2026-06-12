const $ = s => document.querySelector(s);
async function api(path, opts={}) {
  const r = await fetch(path, {credentials:'same-origin', headers:{'Content-Type':'application/json'}, ...opts});
  if (!r.ok) throw new Error((await r.json().catch(()=>({}))).error || r.statusText);
  return r.status === 204 ? null : r.json();
}
async function boot() {
  const st = await api('/api/state');
  if (!st.initialized) return renderSetup();
  if (!st.unlocked) return renderLogin();
  return renderVault();
}
function renderSetup() {
  $('#app').innerHTML = `<h2>Set up vault</h2>
    <input id=pw type=password placeholder="Master password (daily unlock)">
    <input id=tpw type=password placeholder="Transfer password (import/export)">
    <button id=go>Create vault</button><div class=err id=e></div>`;
  $('#go').onclick = async () => {
    try { await api('/api/setup',{method:'POST',body:JSON.stringify(
      {password:$('#pw').value, transfer_password:$('#tpw').value})}); boot(); }
    catch(e){ $('#e').textContent = e.message; }
  };
}
function renderLogin() {
  $('#app').innerHTML = `<h2>Unlock</h2>
    <input id=pw type=password placeholder="Master password">
    <button id=go>Unlock</button><div class=err id=e></div>`;
  $('#go').onclick = async () => {
    try { await api('/api/login',{method:'POST',body:JSON.stringify({password:$('#pw').value})}); boot(); }
    catch(e){ $('#e').textContent = e.message; }
  };
}
async function renderVault() {
  const {entries} = await api('/api/entries');
  $('#app').innerHTML = `<h2>Vault</h2>
    <div id=list></div><h3>Add</h3>
    <input id=t placeholder=Title><input id=u placeholder=Username>
    <input id=s placeholder=Secret>
    <div class=row><button id=add>Add</button>
    <button id=xfer>Transfer</button><button id=lock>Lock</button></div>`;
  $('#list').innerHTML = entries.map(e=>`<div class=entry data-id=${e.id}>
    <b>${esc(e.title)}</b> — ${esc(e.username)}
    <div class=row><button class=rev>Reveal</button>
    <button class=del>Delete</button></div><div class=sec></div></div>`).join('') || '<p>No entries.</p>';
  document.querySelectorAll('.rev').forEach(b=>b.onclick=async ev=>{
    const d=ev.target.closest('.entry'); const {secret}=await api(`/api/entries/${d.dataset.id}/secret`);
    d.querySelector('.sec').textContent=secret;
  });
  document.querySelectorAll('.del').forEach(b=>b.onclick=async ev=>{
    const d=ev.target.closest('.entry'); await api(`/api/entries/${d.dataset.id}`,{method:'DELETE'}); renderVault();
  });
  $('#add').onclick=async()=>{ await api('/api/entries',{method:'POST',body:JSON.stringify(
    {title:$('#t').value,username:$('#u').value,secret:$('#s').value})}); renderVault(); };
  $('#xfer').onclick = renderTransfer;
  $('#lock').onclick=async()=>{ await api('/api/logout',{method:'POST'}); boot(); };
}
function renderTransfer() {
  $('#app').innerHTML = `<h2>Transfer</h2>
    <h3>Export</h3>
    <input id=epw type=password placeholder="Transfer password">
    <button id=exp>Download export file</button>
    <h3>Import</h3>
    <input id=ipw type=password placeholder="Transfer password (of the file)">
    <input id=file type=file>
    <button id=imp>Import file</button>
    <div class=row><button id=back>Back</button></div>
    <div class=err id=e></div>`;
  $('#back').onclick = renderVault;
  $('#exp').onclick = async () => {
    try {
      const r = await fetch('/api/export', {method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({transfer_password:$('#epw').value})});
      if (!r.ok) throw new Error((await r.json().catch(()=>({}))).error || r.statusText);
      const blob = await r.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = 'esp32key-export.bin'; a.click();
      URL.revokeObjectURL(a.href);
    } catch(e){ $('#e').textContent = e.message; }
  };
  $('#imp').onclick = async () => {
    try {
      const f = $('#file').files[0];
      if (!f) throw new Error('choose a file');
      const buf = new Uint8Array(await f.arrayBuffer());
      let bin = ''; buf.forEach(b => bin += String.fromCharCode(b));
      const b64 = btoa(bin);
      await api('/api/import',{method:'POST',body:JSON.stringify(
        {transfer_password:$('#ipw').value, bundle:b64})});
      renderVault();
    } catch(e){ $('#e').textContent = e.message; }
  };
}
const esc = s => s.replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
boot();
