'use strict';
/* Démarrage, navigation, barre de chemin, analyse */

function showView(name) {
  S.view = name;
  $$('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.view === name));
  $$('section.view').forEach(s => s.classList.toggle('active', s.id === 'view-' + name));
  if (name === 'home') renderHome();
  if (name === 'tree') { tree.redraw(); if (S.snap && tree.selected == null) tree.select(0); }
  if (name === 'map') { refreshMapPaths(); mapTree.redraw(); if (cy) setTimeout(() => cy.resize(), 0); if (!S.mapSid && S.snap) $('#mapWho').focus(); }
  if (name === 'shares') renderShares();
  if (name === 'principals') renderPrincipalList();
  if (name === 'findings') renderFindings();
  if (name === 'diff') renderDiff();
  if (name === 'journal') { renderJournal(); send('getLog'); }
}

function navigate(go) {
  const [view, arg] = go.split(':');
  showView(view);
  if (view === 'tree') setTreeFilter(arg || null);
  if (view === 'principals' && arg) { prKind = arg; $$('#prFilters .chip').forEach(c => c.classList.toggle('on', c.dataset.k === arg)); renderPrincipalList(); }
}

function updateMode() {
  const w = !!S.settings?.writeEnabled;
  const b = $('#modeBadge');
  b.textContent = w ? 'Modifications autorisées' : 'Lecture seule';
  b.classList.toggle('write', w);
  b.title = w ? 'Les modifications sont possibles (avec aperçu, Dry Run et confirmation). Paramètres › Modifications pour revenir en lecture seule.' : 'Aucune modification possible. Paramètres › Modifications pour les autoriser.';
}

/* ---------- barre de chemin ---------- */
function fillPathBar() {
  const s = S.settings; if (!s) return;
  const ap = activeProfile();
  $('#pbProfile').innerHTML = s.profiles.length ? s.profiles.map(p => `<option value="${esc(p.id)}" ${p.id === ap?.id ? 'selected' : ''}>${esc(p.name)}</option>`).join('') + '<option value="__add">＋ Ajouter un domaine…</option><option value="__manage">Gérer les domaines…</option>'
    : '<option value="">(aucun domaine)</option><option value="__add">＋ Ajouter un domaine…</option>';
  const servers = ap?.fileServers || [];
  const cur = $('#pbServer').value;
  $('#pbServer').innerHTML = servers.map(f => `<option value="${esc(f.server)}">${esc(f.server)}</option>`).join('') + '<option value="">(saisie libre)</option>';
  if (servers.some(f => f.server === cur)) $('#pbServer').value = cur;
  fillShares();
  if (!$('#pbPath').value && ap?.lastPath) $('#pbPath').value = ap.lastPath;
}

function fillShares(live = null) {
  const ap = activeProfile();
  const srv = $('#pbServer').value;
  const f = ap?.fileServers.find(x => x.server === srv);
  const favs = live || f?.favorites || [];
  $('#pbShare').innerHTML = `<option value="">${favs.length ? '— choisir —' : '(aucun favori)'}</option>` + favs.map(u => `<option value="${esc(u)}">${esc(u.replace(/^\\\\[^\\]+\\/, ''))}</option>`).join('') + (srv ? '<option value="__list">Lister les partages du serveur…</option>' : '');
}

async function listServerShares() {
  const srv = $('#pbServer').value; if (!srv) return;
  $('#pbShare').innerHTML = '<option>Lecture des partages…</option>';
  const r = await request('listShares', 'shares', { server: srv });
  if (!r.ok) { toast(r.error, true); fillShares(); return; }
  fillShares(r.data.shares.filter(s => s.kind === 'Disk' && !s.special).map(s => s.unc));
  $('#pbShare').focus();
}

function openBrowser() {
  let path = $('#pbPath').value.trim() || $('#pbShare').value || '';
  if (!path.startsWith('\\\\') || path.split('\\').filter(Boolean).length < 2) { toast('Choisissez d\'abord un partage (ou saisissez \\\\serveur\\partage).', true); return; }
  const m = modal({ title: 'Choisir le dossier à analyser', wide: true, body: '<div id="brPath" class="mono small" style="margin-bottom:8px"></div><div id="brList" class="list" style="max-height:55vh;overflow:auto;border:1px solid var(--border);border-radius:8px"></div>',
    footer: '<span class="small muted grow">Double-cliquez pour ouvrir un dossier.</span><button class="btn" data-close>Annuler</button><button class="btn primary" id="brOk">Choisir ce dossier</button>' });
  const load = async p => {
    path = p;
    const parts = p.replace(/^\\\\/, '').split('\\');
    $('#brPath', m.root).innerHTML = parts.map((x, i) => `<a data-to="${esc('\\\\' + parts.slice(0, i + 1).join('\\'))}">${esc(i === 0 ? '\\\\' + x : x)}</a>`).join(' \\ ');
    $('#brList', m.root).innerHTML = '<div class="progress indet" style="margin:10px"><i></i></div>';
    const r = await request('browse', 'browse', { path: p });
    if (path !== p) return;
    if (!r.ok) { $('#brList', m.root).innerHTML = `<div class="banner bad" style="margin:8px">${esc(r.error)}</div>`; return; }
    $('#brList', m.root).innerHTML = (parts.length > 2 ? `<div class="row" data-to="${esc('\\\\' + parts.slice(0, -1).join('\\'))}">↰ <span class="muted">dossier parent</span></div>` : '')
      + (r.data.folders.map(f => `<div class="row" data-open="${esc(p.replace(/\\+$/, '') + '\\' + f.name)}">${f.reparse ? '↪' : '📁'} <span class="grow">${esc(f.name)}</span>${f.reparse ? '<span class="tag">jonction</span>' : ''}</div>`).join('') || '<div class="muted small" style="padding:10px">Aucun sous-dossier.</div>');
  };
  m.root.addEventListener('click', e => { const t = e.target.closest('[data-to]'); if (t) load(t.dataset.to); const o = e.target.closest('[data-open]'); if (o) { $$('#brList .row', m.root).forEach(r => r.classList.remove('sel')); o.classList.add('sel'); } });
  m.root.addEventListener('dblclick', e => { const o = e.target.closest('[data-open]'); if (o && !o.textContent.includes('jonction')) load(o.dataset.open); });
  $('#brOk', m.root).onclick = () => { const sel = $('#brList .row.sel', m.root); $('#pbPath').value = sel ? sel.dataset.open : path; m.close(); };
  load(path.replace(/\\+$/, ''));
}

/* ---------- analyse ---------- */
let scanModal = null;
function startScan() {
  const path = $('#pbPath').value.trim();
  if (!path) { toast('Indiquez le chemin à analyser (\\\\serveur\\partage\\dossier).', true); $('#pbPath').focus(); return; }
  if (!activeProfile() && !S.init?.system?.joined) { toast('Configurez d\'abord un domaine (Quick Connect).', true); openQuickConnect({}); return; }
  send('scan', { path, profileId: activeProfile()?.id });
}
on('scanStarted', m => {
  scanModal = modal({ title: 'Analyse en cours', dismissable: false, body: `<div class="mono small ellipsis" title="${esc(m.path)}">${esc(m.path)}</div><div class="progress indet" id="scBar"><i></i></div><div id="scMsg" class="small">Démarrage du collecteur…</div><div id="scLog" class="small muted" style="margin-top:8px;max-height:140px;overflow:auto"></div>`,
    footer: '<span class="small muted grow">Lecture seule. Vous pouvez arrêter : l\'instantané partiel sera enregistré.</span><button class="btn" id="scStop">Arrêter</button>' });
  $('#scStop', scanModal.root).onclick = () => { send('cancelScan'); $('#scStop', scanModal.root).disabled = true; $('#scMsg', scanModal.root).textContent = 'Arrêt demandé…'; };
});
on('progress', p => {
  if (p.context !== 'scan' || !scanModal) return;
  $('#scMsg', scanModal.root).textContent = p.message || p.stage;
  const bar = $('#scBar', scanModal.root);
  if (p.total > 0 && p.stage === 'scan') { bar.classList.remove('indet'); bar.firstElementChild.style.width = Math.min(100, p.current / p.total * 100) + '%'; }
  else { bar.classList.add('indet'); bar.firstElementChild.style.width = '30%'; }
});
on('collectorLog', l => { if (l.context === 'scan' && scanModal) $('#scLog', scanModal.root).insertAdjacentHTML('beforeend', `<div>⚠ ${esc(l.message)}</div>`); });
on('scanDone', () => { scanModal?.close(); scanModal = null; toast('Analyse terminée.'); });
on('scanError', e => {
  if (!scanModal) { toast(e.message, true); return; }
  scanModal.body.insertAdjacentHTML('beforeend', `<div class="banner bad" style="margin-top:10px">${esc(e.message)}</div><p class="hint">Pistes : chemin et nom du serveur, droits du compte de collecte, port 445 (SMB), contrôleur de domaine joignable (389/88), mot de passe. Le test de connexion (Paramètres › Domaines) détaille chaque point.</p>`);
  scanModal.footer.innerHTML = '<button class="btn primary" id="scClose">Fermer</button>';
  $('#scClose', scanModal.root).onclick = () => { scanModal.close(); scanModal = null; };
});

/* ---------- messages de l'hôte ---------- */
on('init', m => { S.init = m; });
on('settings', m => {
  const first = !S.settings;
  S.settings = m.settings; S.sessionCreds = m.sessionCredentials || [];
  updateMode(); fillPathBar();
  if (S.view === 'home' && !S.snap) renderHome();
  if (first && !m.settings.quickConnectDone && !m.settings.profiles.length) openQuickConnect({});
  if (S.selFolder != null && S.view === 'tree') send('folder', { id: S.selFolder });
});
on('snapshot', snap => {
  indexSnapshot(snap);
  $('#cntShares').textContent = snap.shares.filter(s => s.kind === 'Disk').length || '';
  $('#cntPrincipals').textContent = fmt(snap.principals.length);
  $('#cntFindings').textContent = fmt(snap.findings.reduce((a, f) => a + f.count, 0));
  $('#btnExport').disabled = false;
  document.title = 'ACL Map — ' + snap.manifest.rootPath;
  tree.reset(); tree.expandAll(1); mapTree.reset();
  $('#folderPanel').innerHTML = '<div class="empty">Sélectionnez un dossier pour afficher ses autorisations.</div>';
  $('#principalPanel').innerHTML = '<div class="empty">Sélectionnez une identité.</div>';
  $('#explainPanel').innerHTML = '<div class="empty">Choisissez une identité puis cliquez sur un dossier.</div>';
  $('#mapHead').innerHTML = ''; $('#mapLegend').innerHTML = ''; $('#mapWho').value = ''; mapLevels = null; mapFlags = null; maxBelow = null; mapSelected = null;
  if (cy) { cy.destroy(); cy = null; }
  lastDiff = null;
  refreshMapPaths();
  showView(S.view === 'journal' || S.view === 'diff' ? 'home' : S.view);
});
on('exported', e => toast(`Export enregistré : ${e.file}`, false, 6000));

/* ---------- liaisons ---------- */
function bind() {
  $('#tabs').onclick = e => { const b = e.target.closest('button[data-view]'); if (b) showView(b.dataset.view); };
  $('#pbProfile').onchange = e => {
    const v = e.target.value;
    if (v === '__add') { openQuickConnect({ addMode: true }); fillPathBar(); return; }
    if (v === '__manage') { openSettings('domains'); fillPathBar(); return; }
    if (v) send('setActiveProfile', { id: v });
  };
  $('#pbServer').onchange = () => { fillShares(); if (!$('#pbServer').value) $('#pbPath').focus(); };
  $('#pbShare').onchange = e => { const v = e.target.value; if (v === '__list') listServerShares(); else if (v) $('#pbPath').value = v; };
  $('#pbPath').onkeydown = e => { if (e.key === 'Enter') startScan(); };
  $('#pbBrowse').onclick = openBrowser;
  $('#pbScan').onclick = startScan;
  $('#btnOpen').onclick = () => send('openSnapshot');
  $('#btnSettings').onclick = () => openSettings();
  $('#modeBadge').onclick = () => openSettings('write');
  $('#btnExport').onclick = e => { e.stopPropagation(); $('#exportMenu').hidden = !$('#exportMenu').hidden; };
  document.addEventListener('click', () => { $('#exportMenu').hidden = true; });
  $('#exportMenu').onclick = e => { const b = e.target.closest('[data-export]'); if (b) send('export', { kind: b.dataset.export }); };
  $('#prSearch').oninput = () => renderPrincipalList();
  $('#prFilters').onclick = e => { const c = e.target.closest('.chip'); if (!c) return; prKind = c.dataset.k; $$('#prFilters .chip').forEach(x => x.classList.toggle('on', x === c)); renderPrincipalList(); };
  $('#prList').onclick = e => { const r = e.target.closest('[data-sid]'); if (r) showPrincipal(r.dataset.sid); };
  const tools = $('#view-principals .pane-tools');
  const cg = el('<div class="row-flex"><button class="btn small" id="prCreate" title="Créer un groupe de sécurité (modifications autorisées)">＋ Créer un groupe…</button><span class="muted small">Groupes créés dans l\'OU du profil.</span></div>');
  tools.appendChild(cg);
  $('#prCreate').onclick = openCreateGroup;
  document.addEventListener('keydown', e => {
    if (e.ctrlKey && e.key.toLowerCase() === 'o') { e.preventDefault(); send('openSnapshot'); }
    if (e.ctrlKey && e.key.toLowerCase() === 'f' && S.view === 'tree') { e.preventDefault(); $('#treeSearch').focus(); }
  });
}

bind();
initTreeView();
initMapView();
renderHome();
send('ready');
