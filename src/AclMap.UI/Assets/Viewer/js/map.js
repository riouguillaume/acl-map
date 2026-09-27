'use strict';
/* Carte de droits : arbre coloré par niveau d'accès effectif + graphe d'origine + explication ACE par ACE */

let mapTree = null, cy = null, mapLevels = null, mapFlags = null, maxBelow = null, mapSelected = null;

function b64(s) { const bin = atob(s || ''); const a = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }

function initMapView() {
  mapTree = createTree($('#mapTree'), {
    before: id => mapLevels ? levelChip(mapLevels[id], mapFlags[id]) : '',
    flags: id => {
      if (!mapLevels) return '';
      let s = statusChips(mapFlags[id]);
      if (maxBelow && maxBelow[id] > mapLevels[id] && !(mapFlags[id] & F.Outside)) s += `<span class="st up" title="Un sous-dossier donne davantage : ${esc(LEVELS[maxBelow[id]])}">↑ ${esc(LEVELS[maxBelow[id]])}</span>`;
      if (S.shareRoots.has(id)) s += `<span class="fl blue">⇄ ${esc(S.shareRoots.get(id).join(', '))}</span>`;
      return s;
    },
    dim: id => mapLevels && ((mapFlags[id] & F.Outside) || (mapLevels[id] === 0 && !(mapFlags[id] & (F.Ambiguous | F.Unknown)))),
    onSelect: id => { mapSelected = id; if (S.mapSid) send('explain', { sid: S.mapSid, folderId: id, path: S.accessPath, implicit: $('#mapImplicit').checked }); },
  });
  principalPicker($('#mapWho'), $('#mapSuggest'), p => setMapPrincipal(p.sid));
  $('#mapPath').onchange = e => { S.accessPath = e.target.value; loadMap(); };
  $('#mapImplicit').onchange = () => loadMap();
  $('#mapHideNone').onchange = () => applyMapFilter();
  $('#mapExport').onclick = () => S.mapSid && send('export', { kind: 'AccessCsv', sid: S.mapSid, path: S.accessPath });
}

function refreshMapPaths() {
  if (!S.snap) return;
  $('#mapPath').innerHTML = S.snap.accessPaths.map(p => `<option value="${esc(p.id)}" ${p.id === S.accessPath ? 'selected' : ''}>${esc(p.label)}${p.shareRightsKnown ? '' : ' (droits de partage illisibles)'}</option>`).join('');
}

function setMapPrincipal(sid) {
  S.mapSid = sid;
  const p = S.principals.get(sid);
  $('#mapWho').value = p?.name || sid;
  $('#mapImplicitWrap').hidden = !p || ['User', 'Computer', 'Unknown'].includes(p.kind);
  if ($('#mapImplicitWrap').hidden) $('#mapImplicit').checked = false;
  loadMap();
}

function loadMap() {
  if (!S.mapSid || !S.snap) return;
  $('#mapHead').innerHTML = '<span class="muted">Calcul de la carte…</span>';
  const implicit = $('#mapImplicit').checked;
  send('accessMap', { sid: S.mapSid, path: S.accessPath, implicit });
  send('graph', { sid: S.mapSid, implicit });
}

function applyMapFilter() {
  const hide = $('#mapHideNone').checked && mapLevels;
  mapTree.setFilter(hide ? (id => mapLevels[id] > 0 || (mapFlags[id] & (F.Ambiguous | F.Unknown | F.Denied))) : null, '');
}

on('accessMap', m => {
  if (m.sid !== S.mapSid) return;
  S.map = m;
  mapLevels = b64(m.levels); mapFlags = b64(m.flags);
  const n = mapLevels.length;
  maxBelow = new Uint8Array(n);
  for (let i = n - 1; i > 0; i--) {
    const p = S.parent[i];
    if (mapFlags[i] & F.Outside) continue;
    const v = Math.max(mapLevels[i], maxBelow[i]);
    if (v > maxBelow[p]) maxBelow[p] = v;
  }
  const tierCount = [0, 0, 0, 0, 0, 0];
  m.counts.forEach((c, lvl) => { tierCount[TIER[lvl]] += c; });
  const p = S.principals.get(m.sid);
  $('#mapHead').innerHTML = `<div class="row-flex" style="flex-wrap:wrap"><b>${esc(m.name)}</b> ${kindTag(p?.kind)} ${m.groupMode ? '<span class="tag blue">droits accordés via ce groupe</span>' : '<span class="tag blue">accès effectif (jeton reconstitué)</span>'}
    ${m.shareLevel ? `<span class="tag">droit de partage : ${esc(m.shareLevel)}</span>` : ''}
    <span class="muted small">${fmt(m.groups.length)} groupe(s) dans le jeton</span><a class="small" data-act="groups">voir</a>
    ${m.denied ? `<span class="st deny">✖ ${fmt(m.denied)} refus</span>` : ''}${m.ambiguous ? `<span class="st amb">? ${fmt(m.ambiguous)} ambigu(s)</span>` : ''}${m.canChangePermissions ? `<span class="st dac">⚿ ${fmt(m.canChangePermissions)} où il peut modifier les autorisations</span>` : ''}
    ${m.unknown ? `<span class="tag">${fmt(m.unknown)} inconnu(s)</span>` : ''}</div>
    ${m.notes.length ? `<div class="small muted" style="margin-top:4px">ℹ ${m.notes.map(esc).join(' · ')}</div>` : ''}`;
  $('#mapHead').onclick = e => { if (e.target.closest('[data-act=groups]')) modal({ title: `Groupes du jeton de ${m.name}`, body: prRows(m.groups.map(g => Object.assign({ kind: g.kind }, S.principals.get(g.sid) || {}, { sid: g.sid, name: g.name }))) }).body.onclick = ev => { const s = ev.target.closest('[data-sid]'); if (s) { $$('.modal-back').forEach(x => x.remove()); showPrincipal(s.dataset.sid); } }; };
  const labels = ['Aucun', 'Liste / spécial', 'Lecture', 'Lecture et écriture', 'Modification', 'Contrôle total'];
  $('#mapLegend').innerHTML = labels.map((l, t) => `<span><span class="lv lv-${t}" style="min-width:0">${esc(l)}</span> ${fmt(tierCount[t])}</span>`).join('')
    + '<span><span class="st deny">✖</span> refus</span><span><span class="st amb">?</span> ambigu</span><span><span class="st up">↑</span> un sous-dossier donne plus</span>';
  $('#mapExport').disabled = false;
  applyMapFilter();
  mapTree.refresh();
  if (mapSelected != null) mapTree.onSelectAgain?.();
  if (mapSelected != null) send('explain', { sid: S.mapSid, folderId: mapSelected, path: S.accessPath, implicit: $('#mapImplicit').checked });
});

function mapSelectFolder(id) { mapTree.select(id, true); }

function resultCard(title, r, extra = '') {
  if (!r) return `<div class="card"><div class="small muted">${esc(title)}</div><div class="muted">—</div></div>`;
  return `<div class="card"><div class="small muted">${esc(title)}</div><div style="margin:4px 0">${levelChip(r.level, r.flags)}</div><div>${statusChips(r.flags)}</div>${extra}</div>`;
}

on('explain', x => {
  if (x.sid !== S.mapSid || x.folderId !== mapSelected) return;
  const effIcon = { Grants: '✔', Denies: '✖', NoEffect: '–', InheritOnly: '↓', Conditional: '?', Uncertain: '?', NotApplicable: '·' };
  const effText = { Grants: 'accorde', Denies: 'refuse', NoEffect: 'sans effet', InheritOnly: 'modèle d\'héritage', Conditional: 'conditionnelle', Uncertain: 'appartenance inconnue', NotApplicable: 'non applicable' };
  const chain = path => `<span class="chain">${path.map((n, i) => `${i ? '<span class="arrow">→</span>' : ''}<span class="node" title="${esc(KIND[n.kind] || n.kind)}">${esc(n.name)}</span>`).join('')}</span>`;
  const rows = list => list.length ? `<table class="data"><thead><tr><th></th><th>Via</th><th>ACE</th><th>Droits</th><th>Origine</th></tr></thead><tbody>${list.map(a => `<tr>
    <td class="effect ${a.effect}" title="${esc(effText[a.effect] || a.effect)}">${effIcon[a.effect] || ''}</td>
    <td>${a.path.length ? chain(a.path) : `<span class="muted small">${esc(a.name)}</span>`}</td>
    <td class="small">${esc(a.kind === 'Deny' || a.kind === 'DenyCallback' ? 'Refuser' : 'Autoriser')} · ${esc(a.name)}</td>
    <td class="small">${esc(a.rights)}${a.bits.length && a.effect !== 'Grants' && a.effect !== 'Denies' ? '' : a.bits.length && a.bits.length < 13 ? `<div class="muted">${esc((a.effect === 'Denies' ? 'retire : ' : 'ajoute : ') + a.bits.join(', '))}</div>` : ''}${a.note ? `<div class="muted">${esc(a.note)}</div>` : ''}</td>
    <td class="small">${a.inherited ? (a.originFolderId != null ? `héritée de <a data-folder="${a.originFolderId}">${esc(a.originPath)}</a>${a.originCertain ? '' : ' (probable)'}` : esc('héritée (' + (a.originPath || '') + ')')) : (a.originPath === null && a.appliesTo === 'Partage' ? 'partage' : '<b>explicite</b>')}</td></tr>`).join('')}</tbody></table>`
    : '<div class="muted small">Aucune ACE ne concerne cette identité (ni ses groupes).</div>';
  const p = $('#explainPanel');
  p.innerHTML = `<div class="row-flex"><b class="grow ellipsis" title="${esc(x.path)}">${esc(x.path)}</b><button class="btn small" data-act="tree">ACL complète</button><button class="btn small" data-act="authz" title="Vérifier avec Windows (API AuthZ, comme l'onglet « Accès effectif »)">Vérifier avec Windows</button></div>
    <div class="result3">${x.shareName ? resultCard('NTFS', x.ntfs) + resultCard('Partage ' + x.shareName, x.share) + resultCard('Accès obtenu (le plus restrictif)', x.final) : resultCard('Accès NTFS obtenu', x.final, '<div class="small muted" style="margin-top:4px">Droits de partage ignorés (choisissez un partage dans « Chemin d\'accès » pour l\'accès réseau).</div>')}</div>
    ${x.outsideShare ? '<div class="banner">Ce dossier n\'est pas sous le partage choisi : il n\'est pas accessible par ce chemin réseau.</div>' : ''}
    ${x.ownerIsPrincipal ? `<div class="banner info">L'identité est propriétaire du dossier (${esc(x.owner?.name || '')}) : elle peut lire et modifier les autorisations quoi que dise l'ACL.</div>` : ''}
    ${x.final.granted.length ? `<details class="fold"><summary>Droits élémentaires accordés (${x.final.granted.length})</summary><div class="small">${x.final.granted.map(esc).join(' · ')}</div></details>` : ''}
    <h4 class="sec">D'où vient le droit : ACE NTFS dans l'ordre d'évaluation</h4>${rows(x.aces)}
    ${x.shareName ? `<h4 class="sec">Droits du partage ${esc(x.shareName)}</h4>${rows(x.shareAces)}` : ''}
    ${x.notes.length ? `<p class="hint">ℹ ${x.notes.map(esc).join(' · ')}</p>` : ''}
    <div id="authzRes"></div>`;
  p.onclick = e => {
    const f = e.target.closest('[data-folder]'); if (f) { mapSelectFolder(+f.dataset.folder); return; }
    const a = e.target.closest('[data-act]')?.dataset.act;
    if (a === 'tree') { showView('tree'); tree.select(x.folderId, true); }
    if (a === 'authz') { $('#authzRes').innerHTML = '<div class="progress indet"><i></i></div>'; send('authz', { folderId: x.folderId, sid: x.sid }); }
  };
});

on('authz', r => {
  const box = $('#authzRes'); if (!box) return;
  if (!r.ok) { box.innerHTML = `<div class="banner bad">Vérification Windows impossible : ${esc(r.error)}</div>`; return; }
  const ntfs = S.map && mapSelected === r.folderId ? LEVELS[mapLevels[r.folderId]] : null;
  box.innerHTML = `<div class="banner info">Windows (AuthZ, NTFS seul) : <b>${esc(r.data.level)}</b> (${esc(r.data.mask)})${ntfs ? ` — ACL Map : <b>${esc(ntfs)}</b>` : ''}. AuthZ utilise les groupes locaux du poste qui exécute la vérification, pas ceux du serveur de fichiers.</div>`;
});

function cssVar(n) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim() || '#888'; }

on('graph', g => {
  if (!window.cytoscape) return;
  const els = [];
  for (const n of g.nodes) els.push({ data: { id: n.id, label: n.label, type: n.type, folderId: n.folderId } });
  g.edges.forEach((e, i) => els.push({ data: { id: 'e' + i, source: e.source, target: e.target, label: e.type === 'member' ? '' : e.label, type: e.type } }));
  if (cy) cy.destroy();
  cy = cytoscape({
    container: $('#cy'), elements: els, wheelSensitivity: 0.25, minZoom: 0.2, maxZoom: 2.5,
    style: [
      { selector: 'node', style: { 'label': 'data(label)', 'font-size': 11, 'color': cssVar('--text'), 'text-valign': 'bottom', 'text-margin-y': 4, 'text-wrap': 'ellipsis', 'text-max-width': 150, 'width': 18, 'height': 18, 'background-color': cssVar('--surface-2'), 'border-width': 2, 'border-color': cssVar('--border-strong') } },
      { selector: 'node[type="principal"]', style: { 'background-color': cssVar('--accent'), 'border-color': cssVar('--accent'), 'width': 26, 'height': 26, 'font-weight': 700 } },
      { selector: 'node[type="group"]', style: { 'shape': 'round-rectangle', 'background-color': cssVar('--accent-soft'), 'border-color': cssVar('--accent') } },
      { selector: 'node[type="implicit"]', style: { 'shape': 'diamond', 'background-color': cssVar('--surface-2'), 'border-style': 'dashed' } },
      { selector: 'node[type="folder"]', style: { 'shape': 'round-tag', 'background-color': cssVar('--lv2'), 'border-color': cssVar('--lv3') } },
      { selector: 'node:selected', style: { 'border-width': 4, 'border-color': cssVar('--high') } },
      { selector: 'edge', style: { 'width': 2, 'curve-style': 'bezier', 'target-arrow-shape': 'triangle', 'line-color': cssVar('--border-strong'), 'target-arrow-color': cssVar('--border-strong'), 'label': 'data(label)', 'font-size': 9, 'color': cssVar('--muted'), 'text-rotation': 'autorotate', 'text-background-color': cssVar('--surface'), 'text-background-opacity': 1, 'text-background-padding': 2 } },
      { selector: 'edge[type="deny"]', style: { 'line-color': cssVar('--st-deny'), 'target-arrow-color': cssVar('--st-deny'), 'line-style': 'dashed' } },
      { selector: 'edge[type="inheritOnly"]', style: { 'line-style': 'dotted' } },
      { selector: 'edge[type="member"]', style: { 'line-color': cssVar('--accent'), 'target-arrow-color': cssVar('--accent') } },
    ],
    layout: { name: 'breadthfirst', directed: true, roots: [g.nodes.find(n => n.type === 'principal')?.id].filter(Boolean), spacingFactor: 0.9, padding: 24, transform: (n, pos) => ({ x: pos.y * 2.2, y: pos.x * 0.55 }) },
  });
  cy.on('tap', 'node[type="folder"]', e => mapSelectFolder(e.target.data('folderId')));
  cy.on('tap', 'node[type="group"]', e => showPrincipal(e.target.id()));
  $('#graphNote').textContent = g.folderTotal > g.folderShown ? `${g.folderShown} dossiers affichés sur ${g.folderTotal} portant une ACE explicite de ces identités` : `${g.folderTotal} dossier(s) portant une ACE explicite · cliquez sur un dossier pour l'explication`;
});
