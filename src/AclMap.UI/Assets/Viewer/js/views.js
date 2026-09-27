'use strict';
/* Onglets : Arborescence et ACL, Partages, Identités, Alertes, Comparaison, Journal */

/* ------------------------------------------------------------ Arborescence et ACL */
let tree = null;
const treeFilter = new Set();

function treeFlags(id) {
  let s = '';
  const sd = S.sd.get(S.sdOf[id]);
  const fl = S.flagsOf[id];
  if (S.shareRoots.has(id)) s += `<span class="fl blue" title="Racine de partage">⇄ ${esc(S.shareRoots.get(id).join(', '))}</span>`;
  if (fl & (NF.ListDenied | NF.SecUnreadable)) s += '<span class="fl bad" title="Inaccessible au compte de collecte">inaccessible</span>';
  if (fl & NF.Reparse) s += '<span class="fl" title="Point de jonction : non suivi">jonction</span>';
  if (fl & NF.DepthLimit) s += '<span class="fl" title="Profondeur maximale atteinte : sous-dossiers non analysés">…</span>';
  if (sd) {
    if (sd.protected && id !== 0) s += '<span class="fl warn" title="Héritage désactivé">héritage rompu</span>';
    if (sd.explicit) s += `<span class="fl" title="ACE explicites">${sd.explicit} ACE</span>`;
    if (sd.deny) s += '<span class="fl bad" title="Refus">refus</span>';
    if (sd.orphan) s += '<span class="fl warn" title="SID orphelin">orphelin</span>';
  }
  const f = S.findingsByFolder.get(id);
  if (f) { const worst = SEV_ORDER.find(sv => f.some(x => x.sev === sv)); s += `<span class="badge sev-${worst}" title="${esc(f.map(x => x.rule + ' ' + x.title).join('\n'))}">${f.length}</span>`; }
  return s;
}

function treePredicate() {
  if (!treeFilter.size) return null;
  return id => {
    const sd = S.sd.get(S.sdOf[id]); const fl = S.flagsOf[id];
    for (const f of treeFilter) {
      if (f === 'protected' && !(sd?.protected && id !== 0)) return false;
      if (f === 'explicit' && !(sd?.explicit > 0)) return false;
      if (f === 'deny' && !sd?.deny) return false;
      if (f === 'orphan' && !sd?.orphan) return false;
      if (f === 'inaccessible' && !(fl & (NF.ListDenied | NF.SecUnreadable))) return false;
      if (f === 'findings' && !S.findingsByFolder.has(id)) return false;
    }
    return true;
  };
}

function initTreeView() {
  tree = createTree($('#tree'), {
    flags: treeFlags,
    onSelect: id => { S.selFolder = id; send('folder', { id }); },
    onCount: (n, m) => { $('#treeFoot').textContent = m == null ? `${fmt(S.snap?.folders.length || 0)} éléments` : `${fmt(m)} correspondance(s)`; },
  });
  let t = null;
  $('#treeSearch').addEventListener('input', () => { clearTimeout(t); t = setTimeout(applyTreeFilter, 200); });
  $('#treeFilters').addEventListener('click', e => {
    const c = e.target.closest('.chip'); if (!c) return;
    c.classList.toggle('on'); if (c.classList.contains('on')) treeFilter.add(c.dataset.f); else treeFilter.delete(c.dataset.f);
    applyTreeFilter();
  });
}
function applyTreeFilter() { tree.setFilter(treePredicate(), $('#treeSearch').value); }
function setTreeFilter(f) {
  treeFilter.clear(); if (f) treeFilter.add(f);
  $$('#treeFilters .chip').forEach(c => c.classList.toggle('on', treeFilter.has(c.dataset.f)));
  applyTreeFilter();
}

function aceTable(aces, { folderId = null, share = false, removable = false } = {}) {
  if (!aces.length) return '<div class="muted small">Aucune ACE.</div>';
  return `<table class="data"><thead><tr><th>Type</th><th>Identité</th><th>Droits</th>${share ? '' : '<th>S\'applique à</th><th>Origine</th>'}${removable ? '<th></th>' : ''}</tr></thead><tbody>
    ${aces.map(a => `<tr class="${a.inherited ? 'inherited' : ''} ${a.kind.startsWith('Refuser') ? 'deny' : ''}">
      <td>${esc(a.kind)}</td>
      <td><a data-sid="${esc(a.sid)}">${esc(a.name)}</a> ${kindTag(a.principalKind)}${a.orphan ? ' <span class="tag warn">orphelin</span>' : ''}</td>
      <td title="${esc(a.details.join('\n'))}\n${esc(a.mask)}">${esc(a.rights)}${a.inheritOnly ? ' <span class="tag">modèle</span>' : ''}</td>
      ${share ? '' : `<td class="small">${esc(a.appliesTo)}</td><td class="small">${a.inherited ? (a.originFolderId != null ? `héritée de <a data-folder="${a.originFolderId}">${esc(a.originPath)}</a>` : esc('héritée ' + (a.originPath || ''))) : '<b>explicite</b>'}</td>`}
      ${removable ? `<td>${!a.inherited && (a.kind === 'Autoriser' || a.kind === 'Refuser') ? `<button class="btn small" data-remove="${a.index}" title="Retirer cette ACE (avec aperçu et confirmation)">Retirer…</button>` : ''}</td>` : ''}
    </tr>`).join('')}</tbody></table>`;
}

on('folder', d => {
  if (d.id !== S.selFolder) return;
  const p = $('#folderPanel');
  const write = !!S.settings?.writeEnabled;
  const fl = d.flags;
  p.innerHTML = `<div class="dhead"><div class="grow"><h2>${esc(d.path)}</h2>
      <div class="chips" style="margin-top:6px">${d.protected ? '<span class="tag warn">héritage désactivé</span>' : '<span class="tag ok">hérite du parent</span>'}
      ${!d.daclPresent ? '<span class="tag bad">DACL nulle</span>' : ''}${!d.canonical ? '<span class="tag bad">ordre non canonique</span>' : ''}
      ${fl & (NF.ListDenied | NF.SecUnreadable) ? '<span class="tag bad">inaccessible</span>' : ''}${fl & NF.Reparse ? '<span class="tag">point de jonction (non suivi)</span>' : ''}
      ${d.shareRoots.map(s => `<span class="tag blue">⇄ ${esc(s)}</span>`).join('')}</div></div>
      <div class="row-flex"><button class="btn small" data-act="who">Qui a accès ?</button><button class="btn small" data-act="map">Voir sur la carte</button></div></div>
    <dl class="kv"><dt>Propriétaire</dt><dd>${d.owner ? `<a data-sid="${esc(d.owner.sid)}">${esc(d.owner.name)}</a> ${kindTag(d.owner.kind)} <span class="muted small">(le propriétaire peut toujours modifier les autorisations)</span>` : '<span class="muted">inconnu</span>'}</dd>
      <dt>Contenu</dt><dd>${fmt(d.children)} élément(s) direct(s), ${fmt(d.descendants)} au total</dd></dl>
    ${d.findings.length ? `<h4 class="sec">Constats</h4>${d.findings.map(f => `<div class="row-flex small" style="margin:4px 0"><span class="badge sev-${f.severity}">${SEV[f.severity]}</span><a data-rule="${esc(f.ruleId)}">${esc(f.ruleId)}</a> ${esc(f.title)} — <span class="muted">${esc(f.detail)}</span></div>`).join('')}` : ''}
    <h4 class="sec">Autorisations (${d.aces.length} ACE, dans l'ordre d'évaluation)</h4>
    ${d.sddl == null ? '<div class="banner bad">Autorisations illisibles avec le compte de collecte.</div>' : aceTable(d.aces, { folderId: d.id, removable: write })}
    <div class="actions">
      <button class="btn" data-act="add" ${write && d.sddl ? '' : 'disabled'} title="${write ? '' : 'Activez les modifications dans Paramètres › Modifications'}">＋ Ajouter un groupe…</button>
      <button class="btn" data-act="agdlp" ${write && d.sddl ? '' : 'disabled'} title="${write ? 'Créer GG_Métier et DL_Partage-Dossier_RW/RO et poser les droits' : 'Activez les modifications dans Paramètres › Modifications'}">Assistant AGDLP…</button>
      ${write ? '' : '<span class="muted small">Lecture seule : les modifications s\'activent dans Paramètres › Modifications.</span>'}
    </div>
    ${d.sddl ? `<details class="fold"><summary>SDDL</summary><pre class="code">${esc(d.sddl)}</pre></details>` : ''}`;
  p.onclick = e => {
    const sid = e.target.closest('[data-sid]'); if (sid) { showPrincipal(sid.dataset.sid); return; }
    const f = e.target.closest('[data-folder]'); if (f) { tree.select(+f.dataset.folder, true); return; }
    const r = e.target.closest('[data-rule]'); if (r) { showView('findings'); openFinding(r.dataset.rule); return; }
    const rm = e.target.closest('[data-remove]'); if (rm) { send('planRemoveAce', { folderId: d.id, index: +rm.dataset.remove }); return; }
    const a = e.target.closest('[data-act]')?.dataset.act;
    if (a === 'who') showWhoHasAccess(d.id);
    if (a === 'map') { showView('map'); mapSelectFolder(d.id); }
    if (a === 'add') openAddAce(d.id);
    if (a === 'agdlp') openAgdlp(d.id);
  };
});

function showWhoHasAccess(folderId) {
  const m = modal({ title: 'Qui a accès ?', wide: true, body: '<div class="empty">Calcul…</div>' });
  const paths = S.snap.accessPaths;
  const run = path => send('whoHasAccess', { folderId, path });
  const handler = w => {
    if (w.folderId !== folderId || !document.body.contains(m.root)) return;
    m.body.innerHTML = `<div class="toolbar"><div class="grow"><b>${esc(w.path)}</b></div><label class="pb"><span>Chemin d'accès</span><select id="whoPath">${paths.map(p => `<option value="${esc(p.id)}" ${p.id === (m.path || S.accessPath) ? 'selected' : ''}>${esc(p.label)}</option>`).join('')}</select></label></div>
      ${w.broadGroupPresent ? '<div class="banner">Un groupe large (Tout le monde, Utilisateurs authentifiés, Utilisateurs du domaine…) a accès : pratiquement tous les comptes du domaine, y compris ceux absents de la liste ci-dessous.</div>' : ''}
      <h4 class="sec">Entrées de l'ACL qui s'appliquent au dossier</h4>
      <table class="data"><thead><tr><th>Identité</th><th>Type</th><th>Droits</th><th>Membres directs</th></tr></thead><tbody>${w.entries.map(e => `<tr class="${e.deny ? 'deny' : ''}"><td><a data-sid="${esc(e.sid)}">${esc(e.name)}</a> ${kindTag(e.kind)}</td><td>${e.deny ? 'Refuser' : 'Autoriser'}</td><td>${esc(e.rights)}</td><td class="num">${e.memberCount ?? ''}</td></tr>`).join('')}</tbody></table>
      <h4 class="sec">Utilisateurs ayant un accès effectif (${fmt(w.users.length)} sur ${fmt(w.usersEvaluated)} connus de l'instantané)</h4>
      <table class="data"><thead><tr><th>Utilisateur</th><th>Accès effectif</th><th></th></tr></thead><tbody>${w.users.map(u => `<tr class="clickable" data-map="${esc(u.sid)}"><td>${esc(u.name)} ${u.displayName ? `<span class="muted small">${esc(u.displayName)}</span>` : ''}${u.disabled ? ' <span class="tag">désactivé</span>' : ''}${u.privileged ? ' <span class="tag warn">privilégié</span>' : ''}</td><td>${levelChip(u.level, u.flags)} ${statusChips(u.flags)}</td><td class="small"><a>carte de droits →</a></td></tr>`).join('') || '<tr><td colspan="3" class="muted">Aucun utilisateur connu n\'a accès.</td></tr>'}</tbody></table>
      <p class="hint">Les utilisateurs connus sont ceux rencontrés en développant les groupes des ACL. L'accès via un partage est l'intersection des droits NTFS et des droits du partage.</p>`;
    m.body.querySelector('#whoPath').onchange = e => { m.path = e.target.value; run(m.path); };
  };
  on('whoHasAccess', handler);
  m.body.onclick = e => {
    const r = e.target.closest('[data-map]'); if (r) { m.close(); showView('map'); setMapPrincipal(r.dataset.map); mapSelectFolder(folderId); return; }
    const s = e.target.closest('[data-sid]'); if (s) { m.close(); showPrincipal(s.dataset.sid); }
  };
  run(S.accessPath);
}

/* ------------------------------------------------------------ Partages */
function renderShares() {
  const v = $('#view-shares');
  if (!S.snap) { v.innerHTML = '<div class="empty">Aucun instantané ouvert.</div>'; return; }
  const shares = S.snap.shares;
  v.innerHTML = `<div class="toolbar"><div class="grow muted small">Partages lus sur ${esc(S.snap.manifest.server || '')}. L'accès réseau est l'intersection des droits de partage et des droits NTFS : le plus restrictif l'emporte.</div>
    <button class="btn" data-act="live">Lister les partages d'un serveur…</button></div>
    <table class="data"><thead><tr><th>Partage</th><th>Chemin local</th><th>Type</th><th>Droits de partage</th><th>Dans l'analyse</th></tr></thead><tbody>
    ${shares.map(s => `<tr><td><b>${esc(s.unc)}</b>${s.special ? ' <span class="tag">spécial</span>' : ''}${s.nestedIn ? `<div class="small muted">imbriqué dans ${esc(s.nestedIn)}</div>` : ''}${s.remark ? `<div class="small muted">${esc(s.remark)}</div>` : ''}</td>
      <td class="mono small">${esc(s.localPath || '')}</td><td>${esc({ Disk: 'Disque', Print: 'Imprimante', Device: 'Périphérique', Ipc: 'IPC', Other: 'Autre' }[s.kind] || s.kind)}</td>
      <td>${s.rightsKnown ? aceTable(s.aces, { share: true }) : `<span class="muted small">${esc(s.rightsError || 'illisibles')}</span>`}</td>
      <td>${s.rootFolderId != null ? `<a data-folder="${s.rootFolderId}">ouvrir dans l'arbre</a><br><a data-mappath="${esc(s.name)}">carte via ce partage</a>` : '<span class="muted small">hors de l\'arborescence analysée</span>'}</td></tr>`).join('') || '<tr><td colspan="5" class="muted">Aucun partage lu (droits d\'administrateur du serveur requis).</td></tr>'}
    </tbody></table>`;
  v.onclick = e => {
    const f = e.target.closest('[data-folder]'); if (f) { showView('tree'); tree.select(+f.dataset.folder, true); return; }
    const mp = e.target.closest('[data-mappath]'); if (mp) { S.accessPath = mp.dataset.mappath; showView('map'); refreshMapPaths(); if (S.mapSid) loadMap(); return; }
    const s = e.target.closest('[data-sid]'); if (s) { showPrincipal(s.dataset.sid); return; }
    if (e.target.closest('[data-act=live]')) openLiveShares();
  };
}

async function openLiveShares(server) {
  const p = activeProfile();
  const servers = p?.fileServers.map(f => f.server) || [];
  const m = modal({ title: 'Partages d\'un serveur', wide: true, body: `<div class="toolbar"><input type="text" id="lsServer" list="lsList" value="${esc(server || servers[0] || '')}" placeholder="FS01.contoso.local" style="min-width:300px"><datalist id="lsList">${servers.map(s => `<option value="${esc(s)}">`).join('')}</datalist><button class="btn primary" id="lsGo">Lister</button></div><div id="lsRes" class="muted">Choisissez un serveur.</div>` });
  const go = async () => {
    const srv = m.body.querySelector('#lsServer').value.trim(); if (!srv) return;
    const res = m.body.querySelector('#lsRes'); res.innerHTML = '<div class="progress indet"><i></i></div>Lecture des partages…';
    const r = await request('listShares', 'shares', { server: srv });
    if (!r.ok) { res.innerHTML = `<div class="banner bad">${esc(r.error)}</div>`; return; }
    res.innerHTML = `<table class="data"><thead><tr><th>Partage</th><th>Chemin local</th><th>Type</th><th>Droits de partage</th><th></th></tr></thead><tbody>${r.data.shares.map(s => `<tr><td><b>${esc(s.unc)}</b>${s.special ? ' <span class="tag">spécial</span>' : ''}</td><td class="mono small">${esc(s.localPath || '')}</td><td>${esc(s.kind)}</td>
      <td class="small">${s.rightsKnown ? (s.rights || []).map(a => `${esc(a.name)} : ${a.deny ? 'refus ' : ''}${esc(a.rights)}`).join('<br>') : `<span class="muted">${esc(s.rightsError || '')}</span>`}</td>
      <td>${s.kind === 'Disk' ? `<button class="btn small" data-scan="${esc(s.unc)}">Analyser</button>` : ''}</td></tr>`).join('')}</tbody></table>`;
  };
  m.body.querySelector('#lsGo').onclick = go;
  m.body.onclick = e => { const b = e.target.closest('[data-scan]'); if (b) { m.close(); $('#pbPath').value = b.dataset.scan; startScan(); } };
  if (server || servers[0]) go();
}

/* ------------------------------------------------------------ Identités */
let prKind = 'all';
function renderPrincipalList() {
  const box = $('#prList');
  if (!S.snap) { box.innerHTML = '<div class="empty">Aucun instantané ouvert.</div>'; return; }
  const q = $('#prSearch').value.trim().toLowerCase();
  const list = S.snap.principals.filter(p => {
    if (prKind === 'acl' && !p.explicitFolders) return false;
    if (prKind === 'priv' && !p.privileged) return false;
    if (prKind === 'orphan' && !p.orphan) return false;
    if (!['all', 'acl', 'priv', 'orphan'].includes(prKind) && p.kind !== prKind) return false;
    return !q || p.name.toLowerCase().includes(q) || (p.displayName || '').toLowerCase().includes(q) || p.sid.toLowerCase().includes(q);
  });
  box.innerHTML = list.slice(0, 2000).map(p => `<div class="row${p.sid === S.selPrincipal ? ' sel' : ''}" data-sid="${esc(p.sid)}">${kindTag(p.kind)}<span class="grow ellipsis" title="${esc(p.name)}">${esc(p.name)}${p.displayName ? ` <span class="muted small">${esc(p.displayName)}</span>` : ''}</span>
    ${p.privileged ? '<span class="tag warn">privilégié</span>' : ''}${p.orphan ? '<span class="tag bad">orphelin</span>' : ''}${p.disabled ? '<span class="tag">désactivé</span>' : ''}${p.explicitFolders ? `<span class="tag" title="Dossiers avec ACE explicite">${fmt(p.explicitFolders)} ACL</span>` : ''}</div>`).join('')
    + (list.length > 2000 ? `<div class="muted small" style="padding:8px 12px">${fmt(list.length - 2000)} autres : affinez la recherche.</div>` : '') || '<div class="empty">Aucune identité.</div>';
}

function showPrincipal(sid) {
  showView('principals');
  S.selPrincipal = sid;
  renderPrincipalList();
  $('#principalPanel').innerHTML = '<div class="empty">Chargement…</div>';
  send('principal', { sid });
}

function prRows(list, removableFrom = null) {
  if (!list.length) return '<div class="muted small">Aucun.</div>';
  return `<div class="list">${list.map(p => `<div class="row" data-sid="${esc(p.sid)}">${kindTag(p.kind)}<span class="grow ellipsis">${esc(p.name)}${p.displayName ? ` <span class="muted small">${esc(p.displayName)}</span>` : ''}</span>${p.privileged ? '<span class="tag warn">privilégié</span>' : ''}${p.disabled ? '<span class="tag">désactivé</span>' : ''}${p.orphan ? '<span class="tag bad">orphelin</span>' : ''}
    ${removableFrom ? `<button class="btn small" data-rmember="${esc(p.sid)}" data-name="${esc(p.name)}" data-dn="${esc(p.dn || '')}">Retirer…</button>` : ''}</div>`).join('')}</div>`;
}

on('principal', d => {
  if (d.info.sid !== S.selPrincipal) return;
  const i = d.info;
  const write = !!S.settings?.writeEnabled;
  const isAdGroup = i.kind === 'Group' && i.dn;
  const p = $('#principalPanel');
  p.innerHTML = `<div class="dhead"><div class="grow"><h2>${esc(i.name)}</h2><div class="chips" style="margin-top:6px">${kindTag(i.kind)}${i.scope && i.scope !== 'None' ? `<span class="tag">étendue ${esc(SCOPE[i.scope] || i.scope)}</span>` : ''}${i.privileged ? '<span class="tag warn">privilégié</span>' : ''}${i.orphan ? '<span class="tag bad">SID orphelin</span>' : ''}${i.disabled ? '<span class="tag">désactivé</span>' : ''}</div></div>
    <button class="btn small primary" data-act="map">Carte de droits</button></div>
    <dl class="kv"><dt>SID</dt><dd class="mono">${esc(i.sid)}</dd>${i.dn ? `<dt>DN</dt><dd class="mono small">${esc(i.dn)}</dd>` : ''}${i.displayName ? `<dt>Nom complet</dt><dd>${esc(i.displayName)}</dd>` : ''}${i.description ? `<dt>Description</dt><dd>${esc(i.description)}</dd>` : ''}
      <dt>Dans les ACL</dt><dd>${fmt(d.aceTotal)} ACE explicite(s)</dd>${d.nestingDepth ? `<dt>Imbrication</dt><dd>${d.nestingCycle ? '<span class="tag bad">boucle</span>' : d.nestingDepth + ' niveau(x) de groupes sous celui-ci'}</dd>` : ''}</dl>
    ${d.notes.length ? `<div class="banner info">${d.notes.map(esc).join('<br>')}</div>` : ''}
    ${d.findings.length ? `<h4 class="sec">Constats</h4>${d.findings.slice(0, 20).map(f => `<div class="row-flex small" style="margin:4px 0"><span class="badge sev-${f.severity}">${SEV[f.severity]}</span><a data-rule="${esc(f.ruleId)}">${esc(f.ruleId)}</a> ${esc(f.detail)}</div>`).join('')}` : ''}
    ${['Group', 'LocalGroup', 'Foreign'].includes(i.kind) ? `<h4 class="sec">Membres directs (${i.membersKnown ? fmt(d.members.length) : 'inconnus'})</h4>
      ${i.membersKnown ? prRows(d.members, write && isAdGroup ? i : null) : `<div class="banner">${esc(d.membersError || 'Membres non lus.')}</div>`}
      ${isAdGroup ? `<div class="actions"><button class="btn" data-act="addmember" ${write ? '' : 'disabled'} title="${write ? '' : 'Activez les modifications dans Paramètres'}">＋ Ajouter un membre…</button></div>` : ''}
      <h4 class="sec">Utilisateurs membres, directs ou par imbrication (${fmt(d.transitiveUsers)})</h4>${prRows(d.transitiveUserSample)}` : ''}
    <h4 class="sec">Membre de (direct)</h4>${prRows(d.parents)}
    ${d.allGroups.length > d.parents.length ? `<details class="fold"><summary>Tous les groupes du jeton (${d.allGroups.length}, imbrication et SID implicites compris)</summary>${prRows(d.allGroups)}</details>` : ''}
    <h4 class="sec">ACE explicites (${fmt(d.aceTotal)})</h4>
    ${d.aces.length ? `<table class="data"><thead><tr><th>Dossier</th><th>Type</th><th>Droits</th><th>S'applique à</th></tr></thead><tbody>${d.aces.map(a => `<tr class="clickable ${a.deny ? 'deny' : ''}" data-folder="${a.folderId}"><td class="small">${esc(a.path)}</td><td>${a.deny ? 'Refuser' : 'Autoriser'}</td><td>${esc(a.rights)}${a.inheritOnly ? ' <span class="tag">modèle</span>' : ''}</td><td class="small">${esc(a.appliesTo)}</td></tr>`).join('')}</tbody></table>` : '<div class="muted small">Aucune ACE explicite pour cette identité (ses droits viennent éventuellement de ses groupes).</div>'}`;
  p.onclick = e => {
    const rm = e.target.closest('[data-rmember]'); if (rm) { send('planMembership', { group: { sid: i.sid, name: i.name, dn: i.dn }, member: { sid: rm.dataset.rmember, name: rm.dataset.name, dn: rm.dataset.dn || null }, add: false }); return; }
    const s = e.target.closest('[data-sid]'); if (s) { showPrincipal(s.dataset.sid); return; }
    const f = e.target.closest('[data-folder]'); if (f) { showView('tree'); tree.select(+f.dataset.folder, true); return; }
    const r = e.target.closest('[data-rule]'); if (r) { showView('findings'); openFinding(r.dataset.rule); return; }
    const a = e.target.closest('[data-act]')?.dataset.act;
    if (a === 'map') { showView('map'); setMapPrincipal(i.sid); }
    if (a === 'addmember') openAddMember(i);
  };
});

/* ------------------------------------------------------------ Alertes */
let sevFilter = new Set(SEV_ORDER);
function renderFindings() {
  const v = $('#view-findings');
  if (!S.snap) { v.innerHTML = '<div class="empty">Aucun instantané ouvert.</div>'; return; }
  const q = (v.querySelector('#fSearch')?.value || '').toLowerCase();
  const list = S.snap.findings.filter(f => sevFilter.has(f.severity) && (!q || (f.ruleId + ' ' + f.title + ' ' + f.description).toLowerCase().includes(q) || f.items.some(i => i.detail.toLowerCase().includes(q))));
  const keepQ = v.querySelector('#fSearch')?.value || '';
  v.innerHTML = `<div class="toolbar"><input type="search" id="fSearch" placeholder="Filtrer les alertes…" value="${esc(keepQ)}" style="min-width:300px">
    <div class="chips">${SEV_ORDER.map(s => `<button class="chip ${sevFilter.has(s) ? 'on' : ''}" data-sev="${s}">${SEV[s]} (${fmt(S.snap.findings.filter(f => f.severity === s).reduce((a, f) => a + f.count, 0))})</button>`).join('')}</div></div>
    ${list.map(f => `<details class="finding ${f.severity}" data-rule="${esc(f.ruleId)}"><summary><span class="badge sev-${f.severity}">${SEV[f.severity]}</span><b>${esc(f.ruleId)}</b><span class="grow">${esc(f.title)}</span><span class="tag">${esc(f.category)}</span><b>${fmt(f.count)}</b></summary>
      <div class="body"><p>${esc(f.description)}</p><p><b>Recommandation :</b> ${esc(f.recommendation)}</p>
      <table class="data"><thead><tr><th>Emplacement</th><th>Identité</th><th>Détail</th></tr></thead><tbody>${f.items.map(it => `<tr><td class="small">${it.folderId != null ? `<a data-folder="${it.folderId}">${esc(fullPath(it.folderId))}</a>` : it.share ? `<a data-share="${esc(it.share)}">partage ${esc(it.share)}</a>` : ''}</td><td class="small">${it.sid ? `<a data-sid="${esc(it.sid)}">${esc(principalName(it.sid))}</a>` : ''}</td><td class="small">${esc(it.detail)}</td></tr>`).join('')}</tbody></table>
      ${f.count > f.items.length ? `<p class="hint">${fmt(f.count - f.items.length)} autres éléments : export CSV des constats.</p>` : ''}</div></details>`).join('') || '<div class="empty">Aucune alerte pour ces critères.</div>'}`;
  const input = v.querySelector('#fSearch');
  let t = null; input.oninput = () => { clearTimeout(t); t = setTimeout(() => { renderFindings(); const i2 = $('#fSearch'); i2.focus(); i2.setSelectionRange(i2.value.length, i2.value.length); }, 250); };
  v.onclick = e => {
    const c = e.target.closest('[data-sev]'); if (c) { const s = c.dataset.sev; sevFilter.has(s) ? sevFilter.delete(s) : sevFilter.add(s); renderFindings(); return; }
    const f = e.target.closest('[data-folder]'); if (f) { e.preventDefault(); showView('tree'); tree.select(+f.dataset.folder, true); return; }
    const s = e.target.closest('[data-sid]'); if (s) { e.preventDefault(); showPrincipal(s.dataset.sid); return; }
    const sh = e.target.closest('[data-share]'); if (sh) { e.preventDefault(); showView('shares'); }
  };
}
function openFinding(rule) {
  sevFilter = new Set(SEV_ORDER); renderFindings();
  const d = $(`#view-findings details[data-rule="${CSS.escape(rule)}"]`);
  if (d) { d.open = true; d.scrollIntoView({ block: 'start' }); }
}

/* ------------------------------------------------------------ Comparaison */
let lastDiff = null;
function renderDiff() {
  const v = $('#view-diff');
  if (!S.snap) { v.innerHTML = '<div class="empty">Ouvrez d\'abord l\'instantané le plus récent.</div>'; return; }
  const d = lastDiff;
  const list = (items, cls = '') => items.length ? `<ul class="small ${cls}" style="margin:4px 0;padding-left:18px">${items.map(x => `<li>${esc(x)}</li>`).join('')}</ul>` : '<div class="muted small">Aucun.</div>';
  v.innerHTML = `<div class="toolbar"><div class="grow muted">Comparez l'instantané ouvert à une analyse précédente du même chemin : dossiers ajoutés/supprimés, ACE explicites ajoutées/retirées, héritage, propriétaire, partages et constats.</div><button class="btn primary" id="diffPick">Choisir l'instantané de référence…</button></div>
    ${!d ? '' : `${d.sameRoot ? '' : `<div class="banner">Les deux instantanés ne portent pas sur le même chemin (${esc(d.oldRoot)} / ${esc(d.newRoot)}) : la comparaison se fait sur les chemins relatifs.</div>`}
    <div class="muted small" style="margin-bottom:10px">Référence : ${esc(fmtDate(d.oldCreated))} → Actuel : ${esc(fmtDate(d.newCreated))}</div>
    <div class="grid kpis"><div class="card kpi"><div class="value">${fmt(d.changedCount)}</div><div class="label">dossiers aux ACL modifiées</div></div><div class="card kpi"><div class="value">${fmt(d.addedCount)}</div><div class="label">dossiers ajoutés</div></div>
      <div class="card kpi"><div class="value">${fmt(d.removedCount)}</div><div class="label">dossiers supprimés</div></div><div class="card kpi"><div class="value">${fmt(d.newFindings.length)}</div><div class="label">nouveaux constats</div></div><div class="card kpi"><div class="value">${fmt(d.resolvedFindings.length)}</div><div class="label">constats résolus</div></div></div>
    <h4 class="sec">ACL modifiées</h4>
    ${d.changed.length ? `<table class="data"><thead><tr><th>Dossier</th><th>ACE ajoutées</th><th>ACE retirées</th><th>Autres</th></tr></thead><tbody>${d.changed.map(c => `<tr><td class="small">${c.folderId != null ? `<a data-folder="${c.folderId}">${esc(c.path)}</a>` : esc(c.path)}</td><td>${list(c.added)}</td><td>${list(c.removed)}</td><td class="small">${c.protectionChanged != null ? (c.protectionChanged ? 'héritage désactivé' : 'héritage réactivé') + '<br>' : ''}${c.ownerAfter ? `propriétaire : ${esc(c.ownerBefore || '?')} → ${esc(c.ownerAfter)}` : ''}</td></tr>`).join('')}</tbody></table>` : '<div class="muted small">Aucune.</div>'}
    <div class="grid two"><div class="card"><h3>Nouveaux constats</h3>${list(d.newFindings)}</div><div class="card"><h3>Constats résolus</h3>${list(d.resolvedFindings)}</div></div>
    <div class="grid two"><div class="card"><h3>Dossiers ajoutés</h3>${list(d.addedFolders)}</div><div class="card"><h3>Dossiers supprimés</h3>${list(d.removedFolders)}</div></div>
    <div class="card" style="margin-top:14px"><h3>Partages</h3>${list(d.shareChanges)}</div>`}`;
  v.querySelector('#diffPick').onclick = () => send('compare');
  v.onclick = e => { const f = e.target.closest('[data-folder]'); if (f) { showView('tree'); tree.select(+f.dataset.folder, true); } };
}
on('diff', d => { lastDiff = d; showView('diff'); renderDiff(); });

/* ------------------------------------------------------------ Journal */
let lastLog = null, lastBackups = null;
function renderJournal() {
  const v = $('#view-journal');
  const errs = S.snap?.errors || [];
  v.innerHTML = `<div class="toolbar"><div class="grow muted small">Journal des opérations d'ACL Map${lastLog ? ` (${esc(lastLog.folder)})` : ''}. Aucun mot de passe n'y est jamais écrit.</div><button class="btn" id="jRefresh">Actualiser</button><button class="btn" id="jBackups">Sauvegardes et restauration…</button></div>
    <table class="data"><thead><tr><th style="width:150px">Date</th><th>Niveau</th><th>Événement</th><th>Message</th></tr></thead><tbody>
    ${(lastLog?.entries || []).map(e => `<tr><td class="small">${esc(fmtDate(e.timestamp))}</td><td><span class="tag ${e.level === 'error' ? 'bad' : e.level === 'audit' ? 'warn' : e.level === 'warning' ? 'warn' : ''}">${esc(e.level)}</span></td><td class="mono small">${esc(e.event)}</td><td class="small">${esc(e.message)}${e.data ? `<div class="muted">${Object.entries(e.data).filter(([, x]) => x).map(([k, x]) => esc(k + ' = ' + x)).join(' · ')}</div>` : ''}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">Journal vide.</td></tr>'}
    </tbody></table>
    ${S.snap ? `<h4 class="sec">Erreurs de collecte de l'instantané (${fmt(errs.length)})</h4><table class="data"><thead><tr><th>Étape</th><th>Cible</th><th>Code</th><th>Message</th></tr></thead><tbody>${errs.map(e => `<tr><td>${esc(e.stage)}</td><td class="small mono">${esc(e.target || '')}</td><td>${e.code || ''}</td><td class="small">${esc(e.message)}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">Aucune erreur.</td></tr>'}</tbody></table>` : ''}`;
  v.querySelector('#jRefresh').onclick = () => send('getLog');
  v.querySelector('#jBackups').onclick = () => { send('listBackups'); };
}
on('log', l => { lastLog = l; if (S.view === 'journal') renderJournal(); });
on('backups', b => { lastBackups = b; openBackups(b); });
