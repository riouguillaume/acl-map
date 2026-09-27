'use strict';
/* Écriture contrôlée : formulaires, plan (avant/après), Dry Run, confirmation, résultats et sauvegardes. */

const LEVEL_CHOICES = [['Read', 'Lecture'], ['ReadExecute', 'Lecture et exécution (afficher le contenu)'], ['Write', 'Lecture et écriture (sans suppression)'], ['Modify', 'Modification'], ['Full', 'Contrôle total']];
const SCOPES = [['ThisFolderSubfoldersFiles', 'Ce dossier, les sous-dossiers et les fichiers'], ['ThisFolderSubfolders', 'Ce dossier et les sous-dossiers'], ['ThisFolderFiles', 'Ce dossier et les fichiers'],
  ['SubfoldersFiles', 'Les sous-dossiers et les fichiers uniquement'], ['SubfoldersOnly', 'Les sous-dossiers uniquement'], ['FilesOnly', 'Les fichiers uniquement'], ['ThisFolderOnly', 'Ce dossier seulement']];

function requireWrite() {
  if (S.settings?.writeEnabled) return true;
  toast('ACL Map est en lecture seule : activez les modifications dans Paramètres › Modifications.', true);
  return false;
}

function openAddAce(folderId) {
  if (!requireWrite()) return;
  let who = null;
  const m = modal({ title: 'Ajouter un groupe sur le dossier', body: `<p class="small"><b>${esc(fullPath(folderId))}</b></p>
    <div class="form">
      <label for="aaWho">Groupe ou compte</label><div class="picker"><input type="search" id="aaWho" placeholder="Rechercher dans l'instantané et dans l'annuaire…" autocomplete="off"><div class="suggest" id="aaSug" hidden></div></div>
      <label for="aaLevel">Autorisation</label><select id="aaLevel">${LEVEL_CHOICES.map(([k, l]) => `<option value="${k}" ${k === 'Modify' ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>
      <label for="aaScope">S'applique à</label><select id="aaScope">${SCOPES.map(([k, l]) => `<option value="${k}">${esc(l)}</option>`).join('')}</select>
      <label>Type</label><div class="row-flex"><label class="check"><input type="radio" name="aaType" value="allow" checked> Autoriser</label><label class="check"><input type="radio" name="aaType" value="deny"> Refuser</label></div>
    </div><p class="hint">Bonne pratique (AGDLP) : accordez les droits à un groupe domaine local (DL_…), jamais directement à un utilisateur. L'assistant AGDLP crée les groupes pour vous.</p>`,
    footer: '<button class="btn" data-close>Annuler</button><button class="btn primary" id="aaPlan">Préparer la modification</button>' });
  principalPicker($('#aaWho', m.root), $('#aaSug', m.root), p => { who = p; }, { live: true });
  $('#aaPlan', m.root).onclick = () => {
    if (!who) { toast('Choisissez un groupe ou un compte dans la liste.', true); return; }
    m.close();
    send('planAddAce', { folderId, principal: { sid: who.sid, name: who.name, dn: who.dn || null }, level: $('#aaLevel', m.root).value, scope: $('#aaScope', m.root).value, deny: m.root.querySelector('input[name=aaType]:checked').value === 'deny' });
  };
}

function openAddMember(group) {
  if (!requireWrite()) return;
  let who = null;
  const m = modal({ title: `Ajouter un membre à ${group.name}`, body: `<div class="form"><label for="amWho">Utilisateur ou groupe</label><div class="picker"><input type="search" id="amWho" placeholder="Nom, prénom, identifiant…" autocomplete="off"><div class="suggest" id="amSug" hidden></div></div></div>
    <p class="hint">La nouvelle appartenance s'applique à la prochaine ouverture de session de l'utilisateur.</p>`,
    footer: '<button class="btn" data-close>Annuler</button><button class="btn primary" id="amPlan">Préparer la modification</button>' });
  principalPicker($('#amWho', m.root), $('#amSug', m.root), p => { who = p; }, { live: true, kinds: ['User', 'Group', 'Computer'] });
  $('#amPlan', m.root).onclick = () => {
    if (!who) { toast('Choisissez une identité dans la liste.', true); return; }
    m.close();
    send('planMembership', { group: { sid: group.sid, name: group.name, dn: group.dn }, member: { sid: who.sid, name: who.name, dn: who.dn || null }, add: true });
  };
}

function openAgdlp(folderId) {
  if (!requireWrite()) return;
  const p = activeProfile();
  const share = (() => { for (let c = folderId; c >= 0; c = S.parent[c]) if (S.shareRoots.has(c)) return S.shareRoots.get(c)[0]; return S.snap.manifest.shareName || ''; })();
  const folderName = folderId === 0 ? (S.snap.manifest.rootPath.split('\\').filter(Boolean).pop() || '') : S.names[folderId];
  const members = [];
  const m = modal({ title: 'Assistant AGDLP', wide: true, body: `<p class="small">Dossier : <b>${esc(fullPath(folderId))}</b></p>
    <p class="small muted">A-G-DL-P : les comptes (A) vont dans un groupe global métier (G), imbriqué dans un groupe domaine local (DL) qui porte la permission (P) sur le dossier.</p>
    <div class="form">
      <label for="agMetier">Métier / équipe</label><input type="text" id="agMetier" placeholder="Compta">
      <label for="agShare">Libellé du partage</label><input type="text" id="agShare" value="${esc(share)}">
      <label for="agFolder">Libellé du dossier</label><input type="text" id="agFolder" value="${esc(folderName)}">
      <label>Accès à créer</label><div><label class="check"><input type="checkbox" id="agRw" checked> Lecture/écriture (Modification) → DL_…_RW</label><br><label class="check"><input type="checkbox" id="agRo"> Lecture seule (Lecture et exécution) → DL_…_RO</label></div>
      <label for="agOu">OU des nouveaux groupes</label><div class="row-flex"><input type="text" id="agOu" list="agOuList" value="${esc(p?.groupsOu || '')}" placeholder="OU=Groupes,DC=contoso,DC=local"><datalist id="agOuList"></datalist><button class="btn small" id="agListOu">Lister les OU</button></div>
      <label for="agMember">Membres du groupe global</label><div><div class="picker"><input type="search" id="agMember" placeholder="Ajouter un utilisateur…" autocomplete="off"><div class="suggest" id="agSug" hidden></div></div><div class="chips" id="agMembers" style="margin-top:6px"></div></div>
      <label>Noms qui seront utilisés</label><div id="agPreview" class="mono small"></div>
    </div><p class="hint">Les groupes existants de même nom sont réutilisés. Rien n'est écrit avant l'aperçu, le Dry Run et votre confirmation.</p>`,
    footer: '<button class="btn" data-close>Annuler</button><button class="btn primary" id="agPlan">Préparer le plan</button>' });
  const slug = s => s.normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[\s\\/]+/g, '-').replace(/[^A-Za-z0-9_.-]/g, '').replace(/-+/g, '-').replace(/^[-.]+|[-.]+$/g, '');
  const tpl = (t, right) => t.replace(/\{Metier\}/gi, slug($('#agMetier', m.root).value)).replace(/\{Partage\}/gi, slug($('#agShare', m.root).value)).replace(/\{Dossier\}/gi, slug($('#agFolder', m.root).value)).replace(/\{Droit\}/gi, right);
  const preview = () => {
    const s = S.settings;
    $('#agPreview', m.root).innerHTML = [tpl(s.ggTemplate, ''), $('#agRw', m.root).checked ? tpl(s.dlTemplate, 'RW') : null, $('#agRo', m.root).checked ? tpl(s.dlTemplate, 'RO') : null].filter(Boolean).map(esc).join('<br>');
    $('#agMembers', m.root).innerHTML = members.map((x, i) => `<span class="chip on">${esc(x.name)} <a data-rm="${i}" aria-label="Retirer">✕</a></span>`).join('');
  };
  ['#agMetier', '#agShare', '#agFolder', '#agRw', '#agRo'].forEach(s => $(s, m.root).addEventListener('input', preview));
  principalPicker($('#agMember', m.root), $('#agSug', m.root), x => { if (!members.some(y => y.sid === x.sid)) members.push(x); $('#agMember', m.root).value = ''; preview(); }, { live: true, kinds: ['User'] });
  m.root.addEventListener('click', async e => {
    const rm = e.target.closest('[data-rm]'); if (rm) { members.splice(+rm.dataset.rm, 1); preview(); }
    if (e.target.closest('#agListOu')) { const r = await request('listOus', 'ous', {}); if (r.ok) { $('#agOuList', m.root).innerHTML = r.data.ous.map(o => `<option value="${esc(o)}">`).join(''); toast(`${r.data.ous.length} OU : choisissez dans la liste du champ.`); } else toast(r.error, true); }
  });
  preview();
  $('#agPlan', m.root).onclick = () => {
    if (!$('#agMetier', m.root).value.trim()) { toast('Indiquez le métier (ex. Compta).', true); return; }
    m.close();
    send('planAgdlp', { folderId, metier: $('#agMetier', m.root).value.trim(), shareLabel: $('#agShare', m.root).value.trim(), folderLabel: $('#agFolder', m.root).value.trim(),
      readWrite: $('#agRw', m.root).checked, readOnly: $('#agRo', m.root).checked, ou: $('#agOu', m.root).value.trim(), members: members.map(x => ({ sid: x.sid, name: x.name, dn: x.dn || null })) });
  };
}

function openCreateGroup() {
  if (!requireWrite()) return;
  const p = activeProfile();
  const m = modal({ title: 'Créer un groupe de sécurité', body: `<div class="form">
    <label for="cgName">Nom (sAMAccountName)</label><input type="text" id="cgName" placeholder="DL_Donnees-Compta_RW">
    <label for="cgScope">Étendue</label><select id="cgScope"><option value="DomainLocal">Domaine local (porte les droits sur les dossiers)</option><option value="Global">Globale (regroupe les comptes d'un métier)</option><option value="Universal">Universelle</option></select>
    <label for="cgOu">OU</label><input type="text" id="cgOu" value="${esc(p?.groupsOu || '')}" placeholder="OU=Groupes,DC=contoso,DC=local">
    <label for="cgDesc">Description</label><input type="text" id="cgDesc"></div>`,
    footer: '<button class="btn" data-close>Annuler</button><button class="btn primary" id="cgPlan">Préparer la modification</button>' });
  $('#cgPlan', m.root).onclick = () => { m.close(); send('planCreateGroup', { name: $('#cgName', m.root).value.trim(), scope: $('#cgScope', m.root).value, ou: $('#cgOu', m.root).value.trim(), description: $('#cgDesc', m.root).value.trim() }); };
}

/* ---------- Revue du plan ---------- */
const KIND_LABEL = { AddAce: 'Ajout d\'autorisation', RemoveAce: 'Retrait d\'autorisation', CreateGroup: 'Création de groupe', AddGroupMember: 'Ajout de membre', RemoveGroupMember: 'Retrait de membre' };

function beforeAfter(op) {
  const b = new Set(op.before), a = new Set(op.after);
  return `<div class="ba"><div><div class="small muted">Avant</div><ul>${op.before.map(x => `<li class="${a.has(x) ? '' : 'del'}">${esc(x)}</li>`).join('') || '<li class="muted">—</li>'}</ul></div>
    <div><div class="small muted">Après</div><ul>${op.after.map(x => `<li class="${b.has(x) ? '' : 'add'}">${esc(x)}</li>`).join('') || '<li class="muted">—</li>'}</ul></div></div>`;
}

on('plan', ({ plan, writeEnabled, confirmWord }) => {
  const word = confirmWord || 'APPLIQUER';
  const m = modal({ title: 'Modification prévue', wide: true, dismissable: true, body: `
    <div class="banner info">Rien n'a encore été modifié. Vérifiez la cible, l'état avant/après et l'impact, lancez un Dry Run (vérification sur l'état réel), puis confirmez.</div>
    <h3 style="margin:6px 0 10px;font-size:15px">${esc(plan.title)}</h3>
    ${plan.warnings.length ? `<ul class="warnlist small">${plan.warnings.map(w => `<li>${esc(w)}</li>`).join('')}</ul>` : ''}
    ${plan.operations.map((op, i) => `<div class="op" data-op="${esc(op.id)}"><h5>${i + 1}. ${esc(KIND_LABEL[op.kind] || op.kind)}${op.noOp ? ' <span class="tag">déjà en place</span>' : ''}</h5>
      <div class="small">${esc(op.description)}</div>
      <dl class="kv"><dt>Cible</dt><dd class="mono small">${esc(op.path || op.group?.dn || op.target)}</dd>${op.kind === 'AddAce' || op.kind === 'RemoveAce' ? `<dt>Objets touchés</dt><dd>${fmt(op.affectedObjects)} (ce dossier et ses héritiers analysés)</dd>` : ''}</dl>
      ${op.warnings.length ? `<ul class="warnlist small">${op.warnings.map(w => `<li>${esc(w)}</li>`).join('')}</ul>` : ''}
      ${op.before.length || op.after.length ? beforeAfter(op) : ''}
      ${op.beforeSddl ? `<details class="fold"><summary>SDDL avant / après</summary><pre class="code">${esc(op.beforeSddl)}</pre><pre class="code">${esc(op.afterSddl)}</pre></details>` : ''}
      <div class="opres" data-res="${esc(op.id)}"></div></div>`).join('')}
    <div id="plRes"></div>
    <div class="form" style="margin-top:12px">
      <label>Vérifications</label><label class="check"><input type="checkbox" id="plChecked"> J'ai vérifié la cible, l'état après et l'impact. Une sauvegarde de l'état actuel sera faite avant chaque écriture.</label>
      <label for="plConfirm">Saisissez ${esc(word)}</label><input type="text" id="plConfirm" autocomplete="off" spellcheck="false">
    </div>
    ${writeEnabled ? '' : '<div class="banner" style="margin-top:10px">Lecture seule : le Dry Run est possible, l\'application exige d\'activer les modifications (Paramètres › Modifications).</div>'}`,
    footer: `<span class="small muted grow">Plan ${esc(plan.planId)} · journalisé</span><button class="btn" data-close>Fermer</button><button class="btn" id="plDry">Dry Run (vérifier sans modifier)</button><button class="btn danger" id="plApply" disabled>Appliquer</button>` });
  const upd = () => { $('#plApply', m.root).disabled = !(writeEnabled && $('#plChecked', m.root).checked && $('#plConfirm', m.root).value.trim() === word) || m.running; };
  $('#plChecked', m.root).onchange = upd; $('#plConfirm', m.root).oninput = upd;
  const run = dry => {
    m.running = true; upd(); $('#plDry', m.root).disabled = true;
    $$('.opres', m.root).forEach(x => { x.textContent = ''; x.className = 'opres'; });
    $('#plRes', m.root).innerHTML = `<div class="progress indet"><i></i></div><div class="small muted">${dry ? 'Dry Run en cours (lecture de l\'état réel)…' : 'Application en cours…'}</div>`;
    send('applyPlan', { planId: plan.planId, dryRun: dry, confirm: dry ? null : $('#plConfirm', m.root).value.trim() });
  };
  $('#plDry', m.root).onclick = () => run(true);
  $('#plApply', m.root).onclick = () => run(false);
  const onOp = r => {
    if (r.planId !== plan.planId || !document.body.contains(m.root)) return;
    const x = r.result, box = m.root.querySelector(`[data-res="${CSS.escape(x.operationId)}"]`);
    if (box) { box.className = 'opres ' + (x.success ? 'ok' : 'bad'); box.textContent = (x.success ? (x.skipped ? '• ' : '✔ ') : '✖ ') + x.message + (x.backupFile ? ' — sauvegarde : ' + x.backupFile : ''); }
  };
  const onDone = r => {
    if (r.planId !== plan.planId || !document.body.contains(m.root)) return;
    m.running = false; $('#plDry', m.root).disabled = false; upd();
    const res = $('#plRes', m.root);
    if (!r.data) { res.innerHTML = `<div class="banner bad">${esc(r.error || 'Échec')}</div>`; return; }
    if (r.dryRun) res.innerHTML = r.success ? '<div class="banner info">✔ Dry Run réussi : l\'état réel correspond à l\'analyse, aucune modification faite.</div>' : `<div class="banner bad">✖ Le Dry Run a échoué : corrigez avant d'appliquer. ${esc(r.error || '')}</div>`;
    else {
      res.innerHTML = r.success ? '<div class="banner info">✔ Modifications appliquées et vérifiées. Relancez une analyse pour mettre à jour la carte (l\'instantané ouvert reflète l\'état d\'avant).<div class="actions"><button class="btn small primary" id="plRescan">Relancer l\'analyse</button><button class="btn small" id="plBackups">Voir les sauvegardes</button></div></div>'
        : `<div class="banner bad">✖ Application interrompue : les opérations suivantes n'ont pas été exécutées. ${esc(r.error || '')}<div class="actions"><button class="btn small" id="plBackups">Voir les sauvegardes</button></div></div>`;
      $('#plRescan', m.root)?.addEventListener('click', () => { m.close(); $('#pbPath').value = S.snap.manifest.rootPath; startScan(); });
      $('#plBackups', m.root)?.addEventListener('click', () => send('listBackups'));
      $('#plConfirm', m.root).value = ''; $('#plChecked', m.root).checked = false; upd();
    }
  };
  on('opResult', onOp); on('applyDone', onDone);
});
