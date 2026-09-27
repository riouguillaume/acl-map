'use strict';
/* Profils de domaine, Quick Connect, Paramètres, sauvegardes */

function activeProfile() {
  const s = S.settings; if (!s) return null;
  return s.profiles.find(p => p.id === s.activeProfileId) || s.profiles[0] || null;
}

function newProfile() {
  const sys = S.init?.system || {};
  return { id: crypto.randomUUID().replace(/-/g, ''), name: '', domainName: sys.domain || '', domainController: '', connectionMode: sys.joined ? 'CurrentUser' : 'AlternateAccount',
    accountName: '', fileServers: [], outputFolder: '', writeAccountName: '', groupsOu: '' };
}

/* ---------- éditeur de profil (réutilisé par Quick Connect et Paramètres) ---------- */
function profileForm(p, parts = ['identity', 'connection', 'servers', 'advanced']) {
  const f = el('<div></div>');
  const serverRows = () => p.fileServers.map((s, i) => `<div class="srvrow" data-i="${i}"><input type="text" data-srv="${i}" value="${esc(s.server)}" placeholder="FS01.contoso.local" aria-label="Serveur ${i + 1}">
      <input type="text" data-fav="${i}" value="${esc((s.favorites || []).join(' ; '))}" placeholder="Chemins favoris (\\\\FS01\\Donnees ; …)" aria-label="Favoris">
      <label class="check" title="Inclure les files d'impression"><input type="checkbox" data-print="${i}" ${s.includePrintShares ? 'checked' : ''}> imprimantes</label>
      <button class="btn small" data-shares="${i}" title="Lister les partages de ce serveur">Partages…</button><button class="btn small" data-delsrv="${i}" aria-label="Retirer">✕</button></div>`).join('');
  const draw = () => {
    f.innerHTML = `<div class="form">
      ${parts.includes('identity') ? `<label for="pfName">Nom du profil</label><input type="text" id="pfName" value="${esc(p.name)}" placeholder="Contoso – production"><div class="err" data-err="name"></div>` : ''}
      ${parts.includes('connection') ? `
      <label for="pfDomain">Domaine (FQDN)</label><input type="text" id="pfDomain" value="${esc(p.domainName || '')}" placeholder="contoso.local"><div class="err" data-err="domainName"></div>
      <label for="pfDc">Contrôleur de domaine</label><input type="text" id="pfDc" value="${esc(p.domainController || '')}" placeholder="DC01.contoso.local (vide = découverte automatique)"><div class="err" data-err="domainController"></div>
      <label>Connexion</label><div class="row-flex"><label class="check"><input type="radio" name="pfMode" value="CurrentUser" ${p.connectionMode === 'CurrentUser' ? 'checked' : ''}> Session Windows actuelle</label>
        <label class="check"><input type="radio" name="pfMode" value="AlternateAccount" ${p.connectionMode === 'AlternateAccount' ? 'checked' : ''}> Autre compte du domaine</label></div>
      <label for="pfAccount">Compte</label><input type="text" id="pfAccount" value="${esc(p.accountName || '')}" placeholder="CONTOSO\\audit ou audit@contoso.local" ${p.connectionMode === 'AlternateAccount' ? '' : 'disabled'}><div class="err" data-err="accountName"></div>
      <div class="full hint">Le mot de passe est demandé dans une fenêtre Windows au premier accès, gardé en mémoire jusqu'à la fermeture d'ACL Map, jamais enregistré. Un contrôleur indiqué par son adresse IP est converti en nom DNS (Kerberos).</div>` : ''}
      ${parts.includes('servers') ? `<div class="full"><b>Serveurs de fichiers</b> <span class="hint">— nom court, FQDN ou IP ; favoris séparés par « ; »</span><div id="pfServers" style="margin-top:8px">${serverRows()}</div><div class="err" data-err="servers" style="grid-column:1"></div>
        <div class="actions" style="margin-top:6px"><button class="btn small" id="pfAddSrv">＋ Ajouter un serveur</button><button class="btn small" id="pfDiscover">Proposer depuis l'AD…</button></div><div id="pfDiscoverRes"></div></div>` : ''}
      ${parts.includes('advanced') ? `
      <label for="pfOut">Dossier des instantanés</label><div class="row-flex"><input type="text" id="pfOut" value="${esc(p.outputFolder || '')}" placeholder="Documents\\AclMap (par défaut)"><button class="btn small" data-pick="pfOut">Parcourir…</button></div><div class="err" data-err="outputFolder"></div>
      <label for="pfWrite">Compte délégué (modifications)</label><input type="text" id="pfWrite" value="${esc(p.writeAccountName || '')}" placeholder="CONTOSO\\adm-acl (vide = compte de connexion)"><div class="err" data-err="writeAccountName"></div>
      <label for="pfOu">OU des groupes créés</label><div class="row-flex"><input type="text" id="pfOu" list="pfOuList" value="${esc(p.groupsOu || '')}" placeholder="OU=Groupes,DC=contoso,DC=local"><datalist id="pfOuList"></datalist><button class="btn small" id="pfListOu">Lister les OU</button></div>` : ''}
    </div>`;
    bind();
  };
  const read = () => {
    const v = id => f.querySelector('#' + id)?.value.trim();
    if (f.querySelector('#pfName')) p.name = v('pfName');
    if (f.querySelector('#pfDomain')) { p.domainName = v('pfDomain'); p.domainController = v('pfDc'); p.connectionMode = f.querySelector('input[name=pfMode]:checked').value; p.accountName = v('pfAccount'); }
    if (f.querySelector('#pfOut')) { p.outputFolder = v('pfOut'); p.writeAccountName = v('pfWrite'); p.groupsOu = v('pfOu'); }
    $$('[data-srv]', f).forEach(i => { const k = +i.dataset.srv; p.fileServers[k].server = i.value.trim(); });
    $$('[data-fav]', f).forEach(i => { const k = +i.dataset.fav; p.fileServers[k].favorites = i.value.split(/[;\n]/).map(x => x.trim()).filter(Boolean); });
    $$('[data-print]', f).forEach(i => { p.fileServers[+i.dataset.print].includePrintShares = i.checked; });
    return p;
  };
  const bind = () => {
    f.querySelectorAll('input[name=pfMode]').forEach(r => r.onchange = () => { read(); f.querySelector('#pfAccount').disabled = p.connectionMode !== 'AlternateAccount'; });
    const add = f.querySelector('#pfAddSrv'); if (add) add.onclick = () => { read(); p.fileServers.push({ server: '', favorites: [], includePrintShares: false, includeSpecialShares: false }); draw(); f.querySelector(`[data-srv="${p.fileServers.length - 1}"]`)?.focus(); };
    f.onclick = async e => {
      const del = e.target.closest('[data-delsrv]'); if (del) { read(); p.fileServers.splice(+del.dataset.delsrv, 1); draw(); return; }
      const sh = e.target.closest('[data-shares]'); if (sh) { read(); discoverShares(p, +sh.dataset.shares, () => draw()); return; }
      const pk = e.target.closest('[data-pick]'); if (pk) { read(); const r = await new Promise(res => { const fn = m => { if (m.field === pk.dataset.pick) { listeners.folderPicked.splice(listeners.folderPicked.indexOf(fn), 1); res(m); } }; on('folderPicked', fn); send('pickOutputFolder', { field: pk.dataset.pick, initial: p.outputFolder }); }); if (r.path) { f.querySelector('#' + pk.dataset.pick).value = r.path; read(); } return; }
      if (e.target.closest('#pfDiscover')) { read(); discoverServers(p, f.querySelector('#pfDiscoverRes'), () => draw()); return; }
      if (e.target.closest('#pfListOu')) {
        read(); const b = e.target.closest('#pfListOu'); b.disabled = true; b.textContent = 'Lecture…';
        const r = await request('listOus', 'ous', { profile: p }); b.disabled = false; b.textContent = 'Lister les OU';
        if (!r.ok) { toast(r.error, true); return; }
        f.querySelector('#pfOuList').innerHTML = r.data.ous.map(o => `<option value="${esc(o)}">`).join('');
        toast(`${r.data.ous.length} OU trouvées : choisissez dans la liste du champ.`);
      }
    };
  };
  const showErrors = errs => {
    $$('[data-err]', f).forEach(d => d.textContent = '');
    $$('input.invalid', f).forEach(i => i.classList.remove('invalid'));
    for (const [k, msg] of Object.entries(errs || {})) {
      const key = k.startsWith('servers') ? 'servers' : k;
      const d = f.querySelector(`[data-err="${key}"]`); if (d) d.textContent = msg;
      const map = { name: 'pfName', domainName: 'pfDomain', domainController: 'pfDc', accountName: 'pfAccount', outputFolder: 'pfOut', writeAccountName: 'pfWrite' };
      if (map[k]) f.querySelector('#' + map[k])?.classList.add('invalid');
      const m = /^servers\.(\d+)/.exec(k); if (m) f.querySelector(`[data-srv="${m[1]}"]`)?.classList.add('invalid');
    }
  };
  draw();
  return { el: f, read, showErrors, redraw: draw };
}

async function discoverServers(p, box, redraw) {
  box.innerHTML = '<div class="progress indet"><i></i></div><span class="small muted">Recherche des serveurs dans l\'annuaire…</span>';
  const r = await request('discoverServers', 'servers', { profile: p });
  if (!r.ok) { box.innerHTML = `<div class="banner bad">${esc(r.error)}</div>`; return; }
  const known = new Set(p.fileServers.map(s => s.server.toLowerCase()));
  box.innerHTML = `<div class="card" style="margin-top:8px"><div class="small muted">${r.data.servers.length} serveur(s) Windows Server actifs dans ${esc(r.data.domain)} :</div>
    <div style="max-height:200px;overflow:auto;margin:6px 0">${r.data.servers.map((s, i) => `<label class="check" style="display:flex"><input type="checkbox" data-d="${i}" ${known.has(s.name.toLowerCase()) ? 'checked disabled' : ''}> ${esc(s.name)} <span class="faint small">${esc(s.os || '')}</span></label>`).join('')}</div>
    <button class="btn small primary" id="dAdd">Ajouter la sélection</button></div>`;
  box.querySelector('#dAdd').onclick = () => {
    $$('input[data-d]:checked:not(:disabled)', box).forEach(c => p.fileServers.push({ server: r.data.servers[+c.dataset.d].name, favorites: [], includePrintShares: false, includeSpecialShares: false }));
    redraw();
  };
}

async function discoverShares(p, i, redraw) {
  const srv = p.fileServers[i]; if (!srv?.server) { toast('Saisissez d\'abord le nom du serveur.', true); return; }
  const m = modal({ title: `Partages de ${srv.server}`, body: '<div class="progress indet"><i></i></div><div class="muted small">Lecture des partages…</div>' });
  const r = await request('listShares', 'shares', { profile: p, server: srv.server });
  if (!r.ok) { m.body.innerHTML = `<div class="banner bad">${esc(r.error)}</div>`; return; }
  const disks = r.data.shares.filter(s => s.kind === 'Disk' && !s.special);
  const fav = new Set((srv.favorites || []).map(x => x.toLowerCase()));
  m.body.innerHTML = `<p class="small muted">Cochez les partages à garder en favoris (proposés dans la barre de chemin). Droits de partage : ${r.data.shares.some(s => s.rightsKnown) ? 'lisibles' : 'illisibles sans droits d\'administrateur du serveur'}.</p>
    ${disks.map((s, k) => `<label class="check" style="display:flex;margin:4px 0"><input type="checkbox" data-k="${k}" ${fav.has(s.unc.toLowerCase()) ? 'checked' : ''}> <b>${esc(s.unc)}</b> <span class="faint small mono">${esc(s.localPath || '')}</span></label>`).join('') || '<div class="muted">Aucun partage disque.</div>'}
    ${r.data.shares.some(s => s.kind === 'Print') ? `<p class="hint">${r.data.shares.filter(s => s.kind === 'Print').length} file(s) d'impression non affichée(s) (exclues des analyses par défaut).</p>` : ''}`;
  m.footer?.remove();
  const ft = el('<footer><button class="btn" data-close>Annuler</button><button class="btn primary" id="shOk">Garder en favoris</button></footer>');
  m.root.appendChild(ft);
  ft.querySelector('#shOk').onclick = () => { srv.favorites = $$('input[data-k]:checked', m.body).map(c => disks[+c.dataset.k].unc); m.close(); redraw(); };
}

function checksHtml(r) {
  if (!r) return '';
  if (r.error && !r.data) return `<div class="banner bad">${esc(r.error)}</div>`;
  return `<div class="check-list">${(r.data?.checks || []).map(c => `<div class="check-item ${c.ok ? 'ok' : 'bad'}"><span class="st-ic">${c.ok ? '✔' : '✖'}</span><div><b>${esc(c.name)}</b><div class="small">${esc(c.message)}</div></div></div>`).join('')}</div>`;
}

/* ---------- Quick Connect ---------- */
function openQuickConnect({ addMode = false } = {}) {
  const p = newProfile();
  const steps = ['Bienvenue', 'Ce poste', 'Domaine', 'Serveurs de fichiers', 'Test', 'Terminé'];
  let step = addMode ? 2 : 0, form = null, test = null;
  const m = modal({ title: addMode ? 'Nouveau domaine' : 'Quick Connect — première connexion', wide: true, body: '', footer: '<button class="btn" id="qcBack">Précédent</button><div class="spacer"></div><button class="btn" id="qcSkip">Plus tard</button><button class="btn primary" id="qcNext">Suivant</button>', onClose: () => { if (!addMode && !S.settings.quickConnectDone) send('quickConnectDone'); } });
  const sys = S.init?.system || {};
  const render = () => {
    const head = `<div class="steps">${steps.map((s, i) => `<span class="${i === step ? 'on' : i < step ? 'done' : ''}">${i + 1}. ${esc(s)}</span>`).join('')}</div>`;
    let body = '';
    if (step === 0) body = `<h3>Bienvenue dans ACL Map</h3><p>ACL Map cartographie les droits NTFS et de partage d'un serveur de fichiers : qui a accès à quoi, et pourquoi (groupes imbriqués, héritage, refus, droits de partage).</p>
      <ul><li><b>Lecture seule par défaut</b> : aucune modification sans activation explicite, aperçu, Dry Run et confirmation.</li><li>Aucun mot de passe enregistré.</li><li>Le domaine, le contrôleur et les serveurs de fichiers se configurent en quelques étapes, et d'autres domaines s'ajoutent ensuite dans les Paramètres.</li></ul>`;
    else if (step === 1) body = `<h3>Ce poste</h3><dl class="kv"><dt>Poste</dt><dd>${esc(sys.machine)}</dd><dt>Session</dt><dd>${esc(sys.user)}</dd>
      <dt>Domaine</dt><dd>${sys.joined ? `<span class="tag ok">joint à ${esc(sys.domain || '?')}</span>` : '<span class="tag warn">hors domaine</span>'}</dd>
      <dt>WebView2</dt><dd>${esc(sys.webView2 || 'présent')}</dd><dt>.NET</dt><dd>${esc(sys.dotnet || '')}</dd></dl>
      ${sys.joined ? '<p>La session Windows actuelle peut être utilisée directement, ou un autre compte du domaine.</p>' : '<div class="banner">Poste hors domaine : choisissez « Autre compte du domaine » à l\'étape suivante et indiquez le contrôleur de domaine (FQDN de préférence). Ports nécessaires : 53, 88, 389 vers le contrôleur ; 445 vers les serveurs de fichiers.</div>'}
      <p class="hint">Aucun module RSAT n'est nécessaire : ACL Map interroge l'annuaire (LDAP) et les serveurs (SMB) directement.</p>`;
    else if (step === 2) { body = '<h3>Domaine</h3>'; }
    else if (step === 3) { body = '<h3>Serveurs de fichiers</h3><p class="small muted">Ajoutez les serveurs à analyser, ou laissez ACL Map les proposer depuis l\'annuaire. « Partages… » liste les partages d\'un serveur pour les garder en favoris.</p>'; }
    else if (step === 4) body = `<h3>Test de connexion</h3><p class="small muted">Liaison LDAP et lecture des groupes du compte, liste des partages de chaque serveur, lecture de l'ACL d'un partage.</p><div id="qcTest">${test ? checksHtml(test) : '<div class="progress indet"><i></i></div>'}</div>`;
    else body = `<h3>Terminé</h3><p>Le domaine <b>${esc(p.name)}</b> est enregistré et actif.</p><p>Choisissez maintenant un serveur et un partage dans la barre du haut (ou saisissez un chemin), puis cliquez sur <b>Analyser</b>.</p>`;
    m.body.innerHTML = head + body;
    if (step === 2) { form = profileForm(p, ['identity', 'connection']); m.body.appendChild(form.el); }
    if (step === 3) { form = profileForm(p, ['servers']); m.body.appendChild(form.el); }
    $('#qcBack', m.root).disabled = step === 0 || (addMode && step === 2) || step === 5;
    $('#qcNext', m.root).textContent = step === 5 ? 'Choisir un chemin et lancer l\'analyse' : step === 4 ? (test?.ok ? 'Enregistrer' : 'Enregistrer quand même') : 'Suivant';
    $('#qcSkip', m.root).hidden = step === 5;
    if (step === 4 && !test) runTest();
  };
  const runTest = async () => {
    const r = await request('testConnection', 'testResult', { profile: p });
    test = r; if (step === 4) render();
  };
  const onValidation = v => { if (v.context === 'profile' || v.context === 'test') { if (step >= 2 && step <= 4) { step = v.errors.accountName || v.errors.domainName || v.errors.domainController || v.errors.name ? 2 : 3; render(); form?.showErrors(v.errors); } } };
  on('validation', onValidation);
  $('#qcBack', m.root).onclick = () => { form?.read(); step = Math.max(0, step - 1); if (step < 4) test = null; render(); };
  $('#qcSkip', m.root).onclick = () => { if (!addMode) send('quickConnectDone'); m.close(); };
  $('#qcNext', m.root).onclick = async () => {
    if (step === 2) {
      form.read();
      const errs = {};
      if (!p.name) errs.name = 'Donnez un nom au profil.';
      if (p.connectionMode === 'AlternateAccount' && !p.domainName) errs.domainName = 'Le domaine est obligatoire en mode « autre compte ».';
      if (p.connectionMode === 'AlternateAccount' && !/^[^\\]+\\.+$|^.+@.+$/.test(p.accountName || '')) errs.accountName = 'Compte attendu : DOMAINE\\compte ou compte@domaine.';
      if (Object.keys(errs).length) { form.showErrors(errs); return; }
    }
    if (step === 3) form.read();
    if (step === 4) {
      const r = await new Promise(res => { const fn = x => { listeners.profileSaved.splice(listeners.profileSaved.indexOf(fn), 1); res(x); }; on('profileSaved', fn); send('saveProfile', { profile: p, activate: true }); setTimeout(() => res(null), 4000); });
      if (!r) return; // erreurs de validation affichées
      if (!addMode) send('quickConnectDone');
    }
    if (step === 5) { m.close(); fillPathBar(); $('#pbServer').focus(); return; }
    step++; if (step === 4) test = null; render();
  };
  render();
}
on('profileSaved', () => {});

/* ---------- Paramètres ---------- */
function openSettings(tab = 'domains') {
  const m = modal({ title: 'Paramètres', wide: true, body: '' });
  let current = tab, editing = null, form = null;
  const render = () => {
    const s = S.settings;
    m.body.innerHTML = `<div class="subtabs">${[['domains', 'Domaines'], ['scan', 'Analyse'], ['write', 'Modifications'], ['machine', 'Ce poste']].map(([k, l]) => `<button data-tab="${k}" class="${k === current ? 'on' : ''}">${l}</button>`).join('')}</div><div id="stBody"></div>`;
    const b = m.body.querySelector('#stBody');
    if (current === 'domains') {
      if (editing) {
        form = profileForm(editing);
        b.innerHTML = `<div class="row-flex" style="margin-bottom:10px"><b class="grow">${esc(editing.name || 'Nouveau domaine')}</b></div>`;
        b.appendChild(form.el);
        b.appendChild(el(`<div><div class="actions"><button class="btn primary" id="pfSave">Enregistrer</button><button class="btn" id="pfTest">Tester la connexion</button><button class="btn" id="pfCancel">Annuler</button></div><div id="pfTestRes" style="margin-top:10px"></div></div>`));
        b.querySelector('#pfSave').onclick = () => { form.read(); send('saveProfile', { profile: editing, activate: false }); };
        b.querySelector('#pfCancel').onclick = () => { editing = null; render(); };
        b.querySelector('#pfTest').onclick = async () => { form.read(); const box = b.querySelector('#pfTestRes'); box.innerHTML = '<div class="progress indet"><i></i></div>'; const r = await request('testConnection', 'testResult', { profile: editing }); box.innerHTML = checksHtml(r); };
      } else {
        b.innerHTML = `<table class="data"><thead><tr><th>Profil</th><th>Domaine / contrôleur</th><th>Connexion</th><th>Serveurs</th><th>Dernière analyse</th><th></th></tr></thead><tbody>
          ${s.profiles.map(p => `<tr><td><b>${esc(p.name)}</b> ${p.id === activeProfile()?.id ? '<span class="tag ok">actif</span>' : ''}</td><td class="small">${esc(p.domainName || '(domaine du poste)')}<br><span class="muted">${esc(p.domainController || 'découverte auto')}</span></td>
            <td class="small">${p.connectionMode === 'AlternateAccount' ? esc(p.accountName) : 'session actuelle'}${p.writeAccountName ? `<br><span class="muted">modifications : ${esc(p.writeAccountName)}</span>` : ''}</td><td class="small">${p.fileServers.map(f => esc(f.server)).join('<br>') || '<span class="muted">aucun</span>'}</td>
            <td class="small">${p.lastCollectedUtc ? esc(fmtDate(p.lastCollectedUtc)) : '—'}</td>
            <td><div class="row-flex"><button class="btn small" data-edit="${p.id}">Modifier</button>${p.id !== activeProfile()?.id ? `<button class="btn small" data-active="${p.id}">Activer</button>` : ''}<button class="btn small" data-del="${p.id}">Supprimer</button></div></td></tr>`).join('') || '<tr><td colspan="6" class="muted">Aucun domaine.</td></tr>'}
          </tbody></table><div class="actions"><button class="btn primary" id="stAdd">＋ Ajouter un domaine</button><button class="btn" id="stQc">Assistant Quick Connect</button></div>`;
      }
    } else if (current === 'scan') {
      const d = s.defaultScan;
      b.innerHTML = `<div class="form">
        <label for="scDepth">Profondeur maximale</label><input type="number" id="scDepth" min="0" max="64" value="${d.maxDepth}">
        <label for="scPar">Requêtes simultanées</label><input type="number" id="scPar" min="1" max="64" value="${d.parallelism}"><div class="full hint">8 par défaut. Plus élevé = plus rapide mais plus de charge sur le serveur de fichiers.</div>
        <label for="scMax">Limite d'éléments</label><input type="number" id="scMax" min="1000" max="10000000" value="${d.maxNodes}">
        <label>Options</label><div><label class="check"><input type="checkbox" id="scFiles" ${d.includeFiles ? 'checked' : ''}> Analyser aussi les fichiers (beaucoup plus long)</label><br>
          <label class="check"><input type="checkbox" id="scBackup" ${d.backupMode ? 'checked' : ''}> Mode sauvegarde (SeBackupPrivilege) : lire les dossiers verrouillés sans en prendre possession</label><br>
          <label class="check"><input type="checkbox" id="scGroups" ${d.expandGroups ? 'checked' : ''}> Développer les groupes AD et locaux</label></div>
        <div class="full hint">Le mode sauvegarde exige un compte membre de « Opérateurs de sauvegarde » (ou administrateur) du serveur, et une session élevée en local. Son usage est noté dans l'instantané et le journal.</div></div>
        <div class="actions"><button class="btn primary" id="scSave">Enregistrer</button></div>`;
      b.querySelector('#scSave').onclick = () => send('saveSettings', { defaultScan: { maxDepth: +$('#scDepth', b).value, parallelism: +$('#scPar', b).value, maxNodes: +$('#scMax', b).value, includeFiles: $('#scFiles', b).checked, backupMode: $('#scBackup', b).checked, expandGroups: $('#scGroups', b).checked, includePrintShares: false, includeSpecialShares: false } });
    } else if (current === 'write') {
      b.innerHTML = `<div class="banner ${s.writeEnabled ? 'bad' : 'info'}">${s.writeEnabled ? '⚠ Les modifications sont autorisées. Chaque opération reste soumise à un aperçu, un Dry Run facultatif et une confirmation explicite, avec sauvegarde de l\'état précédent.' : 'ACL Map est en lecture seule : aucune ACL ni aucun groupe ne peut être modifié.'}</div>
        <label class="check" style="font-size:14px"><input type="checkbox" id="wrEnable" ${s.writeEnabled ? 'checked' : ''}> Autoriser les modifications (ajout de groupes sur un dossier, membres de groupes, création de groupes)</label>
        <div class="form" style="margin-top:14px">
          <label for="wrGg">Modèle de groupe global</label><input type="text" id="wrGg" value="${esc(s.ggTemplate)}"><div class="full hint">Variables : {Metier}. Exemple : GG_{Metier} → GG_Compta</div>
          <label for="wrDl">Modèle de groupe domaine local</label><input type="text" id="wrDl" value="${esc(s.dlTemplate)}"><div class="full hint">Variables : {Partage}, {Dossier}, {Droit} (RW ou RO). Exemple : DL_{Partage}-{Dossier}_{Droit} → DL_Donnees-Compta_RW</div>
          <label for="wrBk">Dossier des sauvegardes</label><div class="row-flex"><input type="text" id="wrBk" value="${esc(s.backupFolder || '')}" placeholder="%LOCALAPPDATA%\\AclMap\\backups (par défaut)"><button class="btn small" data-pick="wrBk">Parcourir…</button></div></div>
        <div class="actions"><button class="btn primary" id="wrSave">Enregistrer</button><button class="btn" id="wrBackups">Sauvegardes et restauration…</button></div>
        <p class="hint">Moindre privilège : utilisez un compte de lecture pour les analyses et un compte délégué distinct (Paramètres › Domaines) pour les modifications. Ce compte n'est jamais mémorisé : son mot de passe est demandé à chaque application.</p>`;
      b.querySelector('#wrSave').onclick = async () => {
        const en = $('#wrEnable', b).checked;
        if (en && !s.writeEnabled && !(await confirmBox('Autoriser les modifications', 'ACL Map pourra modifier des ACL et des groupes Active Directory après aperçu et confirmation. Continuer ?', 'Autoriser'))) return;
        send('saveSettings', { writeEnabled: en, ggTemplate: $('#wrGg', b).value.trim(), dlTemplate: $('#wrDl', b).value.trim(), backupFolder: $('#wrBk', b).value.trim() });
      };
      b.querySelector('#wrBackups').onclick = () => send('listBackups');
      b.querySelector('[data-pick]').onclick = async () => { const r = await new Promise(res => { const fn = x => { if (x.field === 'wrBk') { listeners.folderPicked.splice(listeners.folderPicked.indexOf(fn), 1); res(x); } }; on('folderPicked', fn); send('pickOutputFolder', { field: 'wrBk' }); }); if (r.path) $('#wrBk', b).value = r.path; };
    } else {
      const sys = S.init?.system || {};
      b.innerHTML = `<dl class="kv"><dt>Poste</dt><dd>${esc(sys.machine)}</dd><dt>Session</dt><dd>${esc(sys.user)}</dd><dt>Domaine du poste</dt><dd>${sys.joined ? esc(sys.domain) : 'hors domaine'}</dd><dt>WebView2</dt><dd>${esc(sys.webView2 || '')}</dd><dt>.NET</dt><dd>${esc(sys.dotnet || '')}</dd><dt>Version</dt><dd>ACL Map ${esc(S.init?.version || '')}</dd>
        <dt>Mots de passe en mémoire</dt><dd>${S.sessionCreds.length ? S.sessionCreds.map(k => esc(k.split('|')[1])).join(', ') : 'aucun'}</dd></dl>
        <div class="actions"><button class="btn" id="mcForget" ${S.sessionCreds.length ? '' : 'disabled'}>Oublier les mots de passe de la session</button><button class="btn" id="mcQc">Relancer Quick Connect</button><button class="btn" id="mcLog">Journal</button></div>`;
      b.querySelector('#mcForget').onclick = () => send('forgetCredentials');
      b.querySelector('#mcQc').onclick = () => { m.close(); openQuickConnect({}); };
      b.querySelector('#mcLog').onclick = () => { m.close(); showView('journal'); };
    }
  };
  m.body.onclick = e => {
    const t = e.target.closest('[data-tab]'); if (t) { current = t.dataset.tab; editing = null; render(); return; }
    const ed = e.target.closest('[data-edit]'); if (ed) { editing = structuredClone(S.settings.profiles.find(p => p.id === ed.dataset.edit)); render(); return; }
    const ac = e.target.closest('[data-active]'); if (ac) { send('setActiveProfile', { id: ac.dataset.active }); return; }
    const dl = e.target.closest('[data-del]'); if (dl) { const p = S.settings.profiles.find(x => x.id === dl.dataset.del); confirmBox('Supprimer le domaine', `Supprimer le profil « ${p.name} » ? Les instantanés déjà produits restent sur le disque.`, 'Supprimer').then(ok => ok && send('deleteProfile', { id: p.id })); return; }
    if (e.target.closest('#stAdd')) { editing = newProfile(); render(); return; }
    if (e.target.closest('#stQc')) { m.close(); openQuickConnect({ addMode: true }); }
  };
  const onSettings = () => { if (document.body.contains(m.root)) { if (current !== 'domains' || !editing) render(); } };
  on('settings', onSettings);
  const onSaved = () => { if (document.body.contains(m.root) && editing) { editing = null; render(); toast('Domaine enregistré.'); } };
  on('profileSaved', onSaved);
  on('validation', v => { if (v.context === 'profile' && form && editing && document.body.contains(m.root)) form.showErrors(v.errors); });
  render();
}

/* ---------- Sauvegardes ---------- */
function openBackups(b) {
  const m = modal({ title: 'Sauvegardes et restauration', wide: true, body: `<p class="small muted">Chaque modification appliquée par ACL Map est précédée d'une sauvegarde (ACL explicite d'avant, ou appartenance). Dossier : <span class="mono">${esc(b.folder)}</span></p>
    <table class="data"><thead><tr><th>Date</th><th>Opération</th><th>Cible</th><th></th></tr></thead><tbody>${b.items.map((x, i) => `<tr><td class="small">${esc(fmtDate(x.timestampUtc))}</td><td class="small">${esc(x.description)}</td><td class="small mono">${esc(x.target)}</td><td><button class="btn small" data-r="${i}">Restaurer…</button></td></tr>`).join('') || '<tr><td colspan="4" class="muted">Aucune sauvegarde.</td></tr>'}</tbody></table>` });
  m.body.onclick = e => { const r = e.target.closest('[data-r]'); if (r) { m.close(); openRestore(b.items[+r.dataset.r]); } };
}

function openRestore(item) {
  const m = modal({ title: 'Restaurer une sauvegarde', body: `<p><b>${esc(item.description)}</b></p><p class="small mono">${esc(item.target)}</p>
    <p class="small">La restauration réécrit l'état d'avant la modification (ACL explicite, ou appartenance). Vérifiez d'abord avec le Dry Run.</p><div id="rsRes"></div>
    <div class="form" style="margin-top:10px"><label for="rsConfirm">Saisissez ${esc(S.init?.confirmWord || 'APPLIQUER')}</label><input type="text" id="rsConfirm" autocomplete="off"></div>`,
    footer: `<button class="btn" data-close>Fermer</button><button class="btn" id="rsDry">Dry Run</button><button class="btn danger" id="rsGo" ${S.settings.writeEnabled ? '' : 'disabled title="Activez les modifications"'}>Restaurer</button>` });
  const box = m.body.querySelector('#rsRes');
  const fn = r => { if (r.file !== item.file || !document.body.contains(m.root)) return; box.innerHTML = r.ok ? `<div class="banner info">${r.dryRun ? 'Dry Run : ' : ''}${esc(r.data.message)}</div>` : `<div class="banner bad">${esc(r.error)}</div>`; };
  on('restoreDone', fn);
  m.root.querySelector('#rsDry').onclick = () => { box.innerHTML = '<div class="progress indet"><i></i></div>'; send('restoreBackup', { file: item.file, dryRun: true }); };
  m.root.querySelector('#rsGo').onclick = () => { box.innerHTML = '<div class="progress indet"><i></i></div>'; send('restoreBackup', { file: item.file, dryRun: false, confirm: m.body.querySelector('#rsConfirm').value.trim() }); };
}
