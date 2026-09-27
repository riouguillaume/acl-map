'use strict';
/* Tableau de bord (accueil) */

function renderHome() {
  const v = $('#view-home');
  if (!S.snap) { v.innerHTML = welcomeHtml(); bindWelcome(v); return; }
  const snap = S.snap, m = snap.manifest, st = snap.stats;
  const sevCount = Object.fromEntries(SEV_ORDER.map(s => [s, snap.findings.filter(f => f.severity === s).reduce((a, f) => a + f.count, 0)]));
  const totalFind = Object.values(sevCount).reduce((a, b) => a + b, 0);
  const rule = id => snap.findings.find(f => f.ruleId === id);
  const banners = [];
  if (m.truncated) banners.push(['bad', 'Analyse incomplète : interrompue avant la fin (annulation ou limite du nombre d\'éléments). Les résultats ne couvrent qu\'une partie de l\'arborescence.']);
  if (rule('ACL-010')) banners.push(['', `${fmt(rule('ACL-010').count)} dossier(s) n'ont pas pu être lus avec le compte de collecte : leurs droits sont « inconnus ». Relancez en mode sauvegarde (Paramètres › Analyse) plutôt que de prendre possession des dossiers.`]);
  if (rule('ACL-032')) banners.push(['', `Appartenance inconnue pour ${fmt(rule('ACL-032').count)} groupe(s) (groupes locaux du serveur non lisibles, ou groupes d'un autre domaine) : les accès passant par eux sont marqués « ambigus ».`]);
  if (rule('ACL-024')) banners.push(['info', `Droits de partage illisibles pour ${fmt(rule('ACL-024').count)} partage(s) : il faut être administrateur du serveur de fichiers pour les lire.`]);
  if (snap.errors.length) banners.push(['info', `${fmt(m.errorCount || snap.errors.length)} erreur(s) de collecte — voir l'onglet Journal.`]);
  const topPrincipals = snap.principals.filter(p => p.explicitFolders > 0 && !['WellKnown'].includes(p.kind) && !/^S-1-5-(18|32-544)$/.test(p.sid)).sort((a, b) => b.explicitFolders - a.explicitFolders).slice(0, 10);
  const maxTop = Math.max(1, ...topPrincipals.map(p => p.explicitFolders));
  const kpi = (value, label, go, cls = '') => `<div class="card kpi${go ? ' clickable' : ''} ${cls}" ${go ? `data-go="${go}"` : ''} tabindex="${go ? 0 : -1}"><div class="value">${fmt(value)}</div><div class="label">${esc(label)}</div></div>`;

  v.innerHTML = `
  <div class="toolbar"><div class="grow"><div style="font-size:18px;font-weight:700" class="ellipsis" title="${esc(m.rootPath)}">${esc(m.rootPath)}</div>
    <div class="muted small">Analyse du ${esc(fmtDate(m.createdUtc))} · compte ${esc(m.collectedBy || '?')} · depuis ${esc(m.machine || '?')}${m.domain?.dnsName ? ' · domaine ' + esc(m.domain.dnsName) : ''} · ${fmt(Math.round((m.durationMs || 0) / 1000))} s${m.options?.backupMode ? ' · <b>mode sauvegarde</b>' : ''} · profondeur ${m.options?.maxDepth ?? '?'}</div></div>
    <button class="btn" data-act="rescan">Relancer l'analyse</button><button class="btn" data-act="compare">Comparer…</button></div>
  ${banners.map(([c, t]) => `<div class="banner ${c}"><span>${c === 'bad' ? '⚠' : 'ℹ'}</span><span>${esc(t)}</span></div>`).join('')}
  <div class="grid kpis">
    ${kpi(st.folders, 'dossiers analysés' + (st.files ? ` (+ ${fmt(st.files)} fichiers)` : ''), 'tree')}
    ${kpi(st.descriptors, 'jeux de droits distincts', null)}
    ${kpi(st.protected, 'héritages désactivés', 'tree:protected')}
    ${kpi(st.foldersWithExplicit, 'dossiers avec ACE explicites', 'tree:explicit')}
    ${kpi(st.inaccessible, 'dossiers inaccessibles', 'tree:inaccessible')}
    ${kpi(st.principals, 'identités (utilisateurs, groupes)', 'principals')}
    ${kpi(st.orphans, 'SID orphelins', 'principals:orphan')}
    ${kpi(st.shares, 'partages (disque)', 'shares')}
  </div>
  <div class="grid two">
    <div class="card"><h3>Constats par gravité</h3>
      <div class="sevbar" role="img" aria-label="Répartition des constats par gravité">${SEV_ORDER.filter(s => sevCount[s]).map(s => `<span style="flex:${sevCount[s]};background:${SEV_COLOR[s]}" title="${SEV[s]} : ${fmt(sevCount[s])}"></span>`).join('')}</div>
      <div class="legend">${SEV_ORDER.map(s => `<span><span class="dot" style="background:${SEV_COLOR[s]}"></span>${SEV[s]} <b>${fmt(sevCount[s])}</b></span>`).join('')}</div>
      <div class="list" style="margin-top:10px">${snap.findings.slice(0, 8).map(f => `<div class="row" data-rule="${esc(f.ruleId)}"><span class="badge sev-${f.severity}">${SEV[f.severity]}</span><span class="grow ellipsis">${esc(f.ruleId)} · ${esc(f.title)}</span><b>${fmt(f.count)}</b></div>`).join('') || '<div class="muted">Aucun constat.</div>'}</div>
      ${totalFind ? '<div class="small" style="margin-top:8px"><a data-go="findings">Toutes les alertes →</a></div>' : ''}
    </div>
    <div class="card"><h3>Identités les plus présentes dans les ACL</h3>
      <div class="small muted" style="margin-bottom:8px">Nombre de dossiers où l'identité est nommée explicitement (hors SYSTEM et Administrateurs).</div>
      ${topPrincipals.map(p => `<div class="row-flex" style="margin:6px 0;cursor:pointer" data-sid="${esc(p.sid)}" title="${esc(p.name)}"><span class="ellipsis" style="width:42%">${esc(p.name)}</span>${kindTag(p.kind)}
        <span class="grow" style="height:8px;background:var(--surface-2);border-radius:999px;overflow:hidden"><span style="display:block;height:100%;width:${Math.max(3, p.explicitFolders / maxTop * 100)}%;background:var(--accent);border-radius:999px"></span></span><span class="small" style="width:44px;text-align:right">${fmt(p.explicitFolders)}</span></div>`).join('') || '<div class="muted">Aucune ACE explicite.</div>'}
    </div>
  </div>
  <div class="grid two">
    <div class="card"><h3>Partages du serveur</h3>
      <table class="data"><thead><tr><th>Partage</th><th>Droits de partage</th><th>Dans l'analyse</th></tr></thead><tbody>
      ${snap.shares.filter(s => s.kind === 'Disk').map(s => `<tr class="clickable" data-share="${esc(s.name)}"><td>${esc(s.unc)}${s.nestedIn ? ` <span class="tag">dans ${esc(s.nestedIn)}</span>` : ''}</td><td class="small">${s.rightsKnown ? s.aces.map(a => `${esc(a.name)} : ${esc(a.rights)}`).join('<br>') : `<span class="muted">${esc(s.rightsError || 'illisibles')}</span>`}</td><td>${s.rootFolderId != null ? '<span class="tag ok">oui</span>' : '<span class="tag">non</span>'}</td></tr>`).join('') || '<tr><td colspan="3" class="muted">Aucun partage lu.</td></tr>'}
      </tbody></table></div>
    <div class="card"><h3>Pour commencer</h3>
      <ul class="small" style="margin:0;padding-left:18px;line-height:1.8">
        <li><a data-go="map">Carte de droits</a> : choisissez un utilisateur ou un groupe pour colorer l'arborescence selon son accès réel, et voir d'où vient chaque droit.</li>
        <li><a data-go="tree">Arborescence et ACL</a> : autorisations de chaque dossier, héritées ou explicites, et « Qui a accès ? ».</li>
        <li><a data-go="findings">Alertes</a> : écriture ouverte à tous, SID orphelins, comptes à privilèges, héritage rompu…</li>
        <li>Exports : rapport HTML, CSV des ACL, des constats et de la carte de droits.</li>
      </ul></div>
  </div>`;
  v.onclick = e => {
    const go = e.target.closest('[data-go]'); if (go) { navigate(go.dataset.go); return; }
    const r = e.target.closest('[data-rule]'); if (r) { showView('findings'); openFinding(r.dataset.rule); return; }
    const sid = e.target.closest('[data-sid]'); if (sid) { showPrincipal(sid.dataset.sid); return; }
    const sh = e.target.closest('[data-share]'); if (sh) { showView('shares'); return; }
    const a = e.target.closest('[data-act]');
    if (a?.dataset.act === 'rescan') { $('#pbPath').value = m.rootPath; startScan(); }
    if (a?.dataset.act === 'compare') send('compare');
  };
  v.onkeydown = e => { if (e.key === 'Enter') e.target.closest('[data-go]')?.click(); };
}

function welcomeHtml() {
  const p = activeProfile();
  const recent = S.settings?.recentSnapshots || [];
  const srv = p ? p.fileServers.map(f => esc(f.server)).join(', ') : '';
  return `<div class="hero">
    <h1>ACL Map</h1>
    <p class="muted">Cartographie des droits NTFS et des partages : qui a accès à quoi, et pourquoi. Lecture seule par défaut.</p>
    <div class="card" style="margin-top:18px">
      ${p ? `<h3>Domaine actif</h3>
        <dl class="kv"><dt>Profil</dt><dd><b>${esc(p.name)}</b></dd><dt>Domaine</dt><dd>${esc(p.domainName || (S.init?.system?.domain ? S.init.system.domain + ' (domaine du poste)' : '—'))}</dd>
        <dt>Contrôleur</dt><dd>${esc(p.domainController || 'découverte automatique')}</dd><dt>Connexion</dt><dd>${p.connectionMode === 'AlternateAccount' ? 'Autre compte : ' + esc(p.accountName) : 'Session Windows actuelle'}</dd>
        <dt>Serveurs de fichiers</dt><dd>${srv || '<span class="muted">aucun — ajoutez-en dans Paramètres › Domaines</span>'}</dd>
        <dt>Dernière analyse</dt><dd>${p.lastCollectedUtc ? esc(fmtDate(p.lastCollectedUtc)) + ' — ' + esc(p.lastPath || '') : '<span class="muted">jamais</span>'}</dd></dl>
        <div class="actions"><button class="btn primary" data-act="scan">▶ Lancer une analyse</button>
          <button class="btn" data-act="last" ${p.lastSnapshotPath ? '' : 'disabled'}>Ouvrir le dernier instantané</button>
          <button class="btn" data-act="open">Ouvrir un fichier…</button><button class="btn" data-act="new">＋ Nouveau domaine</button></div>`
      : `<h3>Premier démarrage</h3><p>Aucun domaine n'est configuré. L'assistant Quick Connect vous guide : domaine, contrôleur, compte, serveurs de fichiers, test.</p>
        <div class="actions"><button class="btn primary" data-act="qc">Lancer Quick Connect</button><button class="btn" data-act="open">Ouvrir un fichier…</button></div>`}
    </div>
    ${recent.length ? `<div class="card" style="margin-top:14px"><h3>Instantanés récents</h3><div class="list">${recent.map(f => `<div class="row" data-file="${esc(f)}"><span>📄</span><span class="grow ellipsis" title="${esc(f)}">${esc(f)}</span></div>`).join('')}</div></div>` : ''}
  </div>`;
}

function bindWelcome(v) {
  v.onclick = e => {
    const f = e.target.closest('[data-file]'); if (f) { send('openFile', { path: f.dataset.file }); return; }
    const a = e.target.closest('[data-act]')?.dataset.act;
    const p = activeProfile();
    if (a === 'scan') { $('#pbPath').focus(); if ($('#pbPath').value) startScan(); else toast('Choisissez un serveur et un partage, ou saisissez un chemin, puis cliquez sur Analyser.'); }
    if (a === 'last' && p) send('openProfileSnapshot', { id: p.id });
    if (a === 'open') send('openSnapshot');
    if (a === 'new') openQuickConnect({ addMode: true });
    if (a === 'qc') openQuickConnect({});
  };
}
