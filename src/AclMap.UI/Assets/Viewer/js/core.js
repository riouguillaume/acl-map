'use strict';
/* ACL Map — noyau de l'interface : canal hôte, état, utilitaires. Tout texte issu des données passe par esc(). */

const host = (() => {
  const handlers = [];
  const wv = window.chrome && window.chrome.webview;
  if (wv) {
    wv.addEventListener('message', e => handlers.forEach(h => h(e.data)));
    return { mode: 'webview', post: m => wv.postMessage(m), on: h => handlers.push(h) };
  }
  if (location.protocol === 'http:' && (location.hostname === 'localhost' || location.hostname === '127.0.0.1')) {
    // Hôte de développement (tests automatisés) : même protocole via WebSocket
    const queue = [];
    const ws = new WebSocket(`ws://${location.host}/ws`);
    ws.onopen = () => queue.splice(0).forEach(m => ws.send(JSON.stringify(m)));
    ws.onmessage = e => { const d = JSON.parse(e.data); handlers.forEach(h => h(d)); };
    return { mode: 'dev', post: m => ws.readyState === 1 ? ws.send(JSON.stringify(m)) : queue.push(m), on: h => handlers.push(h) };
  }
  return { mode: 'none', post: () => toast("Ouvrez ACL Map depuis l'application Windows.", true), on: h => handlers.push(h) };
})();

const S = {
  init: null, settings: null, sessionCreds: [], snap: null,
  parent: null, children: null, sdOf: null, flagsOf: null, names: null, depth: null,
  sd: new Map(), principals: new Map(), findingsByFolder: new Map(), shareRoots: new Map(),
  view: 'home', selFolder: null, selPrincipal: null, accessPath: 'ntfs', map: null, mapSid: null,
};

const listeners = {};
function on(type, fn) { (listeners[type] ||= []).push(fn); }
host.on(msg => {
  if (!msg || !msg.type) return;
  (listeners[msg.type] || []).forEach(fn => { try { fn(msg); } catch (e) { console.error(e); toast('Erreur d\'affichage : ' + e.message, true); } });
});
function send(type, data = {}) { host.post(Object.assign({ type }, data)); }

let reqSeq = 0;
/** Requête avec réponse de type donné (corrélée par requestId quand l'hôte le renvoie). */
function request(type, replyType, data = {}) {
  const requestId = 'r' + (++reqSeq);
  return new Promise(resolve => {
    const fn = msg => {
      if (msg.requestId && msg.requestId !== requestId) return;
      const arr = listeners[replyType]; arr.splice(arr.indexOf(fn), 1);
      resolve(msg);
    };
    on(replyType, fn);
    send(type, Object.assign({ requestId }, data));
  });
}

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = n => (n ?? 0).toLocaleString('fr-FR');
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
function el(html) { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; }
function fmtDate(d) { if (!d) return ''; const x = new Date(d); return isNaN(x) ? '' : x.toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' }); }

function toast(text, bad = false, ms = 4500) {
  const t = el(`<div class="toast${bad ? ' bad' : ''}">${esc(text)}</div>`);
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), ms);
}

/* Niveaux d'accès (AccessLevel) et précisions (AccessFlags) */
const LEVELS = ['Aucun accès', 'Autorisations spéciales', 'Liste du dossier', 'Lecture', 'Lecture et exécution', 'Lecture et écriture', 'Modification', 'Contrôle total'];
const TIER = [0, 1, 1, 2, 2, 3, 4, 5];
const F = { Denied: 1, CanChange: 2, Ambiguous: 4, AsOwner: 8, Unknown: 16, NullDacl: 32, Outside: 64 };
const NF = { File: 1, Reparse: 2, ListDenied: 4, SecUnreadable: 8, LongPath: 16, DepthLimit: 32, Backup: 64, Error: 128 };
const KIND = { User: 'Utilisateur', Group: 'Groupe AD', Computer: 'Ordinateur', WellKnown: 'Bien connu', LocalGroup: 'Groupe local', LocalUser: 'Compte local', Capability: 'Capacité', Foreign: 'Autre domaine', Unknown: 'Inconnu', implicit: 'Implicite', folder: 'Dossier' };
const SCOPE = { DomainLocal: 'domaine local', Global: 'globale', Universal: 'universelle', Local: 'locale', None: '' };
const SEV = { Critical: 'Critique', High: 'Élevée', Medium: 'Moyenne', Low: 'Faible', Info: 'Info' };
const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const SEV_COLOR = { Critical: 'var(--crit)', High: 'var(--high)', Medium: 'var(--med)', Low: 'var(--low)', Info: 'var(--info)' };

function levelChip(level, flags = 0) {
  if (flags & F.Outside) return `<span class="lv lv-out" title="Hors du partage choisi">hors partage</span>`;
  if (flags & F.Unknown) return `<span class="lv lv-unknown" title="Autorisations illisibles">inconnu</span>`;
  return `<span class="lv lv-${TIER[level] || 0}">${esc(LEVELS[level] || LEVELS[0])}</span>`;
}
function statusChips(flags) {
  let s = '';
  if (flags & F.Denied) s += '<span class="st deny" title="Un refus retire des droits">✖ refus</span>';
  if (flags & F.Ambiguous) s += '<span class="st amb" title="Calcul ambigu : ACE conditionnelle ou appartenance inconnue">? ambigu</span>';
  if (flags & F.CanChange) s += '<span class="st dac" title="Peut modifier les autorisations">⚿ autorisations</span>';
  return s;
}
function kindTag(k) { return `<span class="kind">${esc(KIND[k] || k || '')}</span>`; }

/* Index de l'instantané */
function indexSnapshot(snap) {
  const n = snap.folders.length;
  S.snap = snap;
  S.parent = new Int32Array(n); S.sdOf = new Int32Array(n); S.flagsOf = new Int32Array(n); S.depth = new Int32Array(n);
  S.names = new Array(n); S.children = new Array(n);
  for (let i = 0; i < n; i++) S.children[i] = [];
  for (const f of snap.folders) {
    const [id, parent, name, sd, flags] = f;
    S.parent[id] = parent; S.names[id] = name; S.sdOf[id] = sd; S.flagsOf[id] = flags;
    if (parent >= 0) { S.children[parent].push(id); S.depth[id] = S.depth[parent] + 1; }
  }
  const coll = new Intl.Collator('fr', { sensitivity: 'base', numeric: true });
  for (const c of S.children) if (c.length > 1) c.sort((a, b) => ((S.flagsOf[a] & NF.File) - (S.flagsOf[b] & NF.File)) || coll.compare(S.names[a], S.names[b]));
  S.sd = new Map(snap.descriptors.map(d => [d.id, d]));
  S.principals = new Map(snap.principals.map(p => [p.sid, p]));
  S.findingsByFolder = new Map();
  for (const f of snap.findings) for (const it of f.items) if (it.folderId != null) {
    const arr = S.findingsByFolder.get(it.folderId) || []; arr.push({ rule: f.ruleId, sev: f.severity, title: f.title }); S.findingsByFolder.set(it.folderId, arr);
  }
  S.shareRoots = new Map();
  for (const s of snap.shares) if (s.rootFolderId != null) { const a = S.shareRoots.get(s.rootFolderId) || []; a.push(s.name); S.shareRoots.set(s.rootFolderId, a); }
  S.accessPath = snap.defaultAccessPath || 'ntfs';
  S.map = null; S.mapSid = null; S.selFolder = null; S.selPrincipal = null;
}
function fullPath(id) {
  if (id == null || !S.snap) return '';
  if (id === 0) return S.snap.manifest.rootPath;
  const parts = [];
  for (let c = id; c > 0; c = S.parent[c]) parts.push(S.names[c]);
  return S.snap.manifest.rootPath.replace(/\\+$/, '') + '\\' + parts.reverse().join('\\');
}
function principalName(sid) { return S.principals.get(sid)?.name || sid; }

/* Fenêtres modales */
function modal({ title, body, footer = '', wide = false, onClose = null, dismissable = true }) {
  const back = el(`<div class="modal-back"><div class="modal${wide ? ' wide' : ''}" role="dialog" aria-modal="true" aria-label="${esc(title)}">
    <header><h2>${esc(title)}</h2>${dismissable ? '<button class="btn ghost icon" data-close aria-label="Fermer">✕</button>' : ''}</header>
    <div class="mbody"></div><footer></footer></div></div>`);
  const m = back.querySelector('.modal');
  const b = m.querySelector('.mbody');
  if (typeof body === 'string') b.innerHTML = body; else if (body) b.appendChild(body);
  const f = m.querySelector('footer');
  if (typeof footer === 'string') f.innerHTML = footer; else if (footer) f.appendChild(footer);
  if (!f.innerHTML) f.remove();
  const close = () => { back.remove(); document.removeEventListener('keydown', key); onClose && onClose(); };
  const key = e => { if (e.key === 'Escape' && dismissable && $('#modalRoot').lastElementChild === back) close(); };
  document.addEventListener('keydown', key);
  back.addEventListener('click', e => { if (e.target.closest('[data-close]')) close(); });
  $('#modalRoot').appendChild(back);
  setTimeout(() => (m.querySelector('input:not([type=checkbox]):not([disabled]),select,textarea') || m.querySelector('button:not([data-close])'))?.focus(), 30);
  return { root: m, body: b, close, footer: m.querySelector('footer') };
}

function confirmBox(title, text, okLabel = 'Confirmer') {
  return new Promise(res => {
    const m = modal({ title, body: `<p>${esc(text)}</p>`, footer: `<button class="btn" data-close>Annuler</button><button class="btn primary" data-ok>${esc(okLabel)}</button>`, onClose: () => res(false) });
    m.root.querySelector('[data-ok]').onclick = () => { res(true); m.close(); };
  });
}

/* Sélecteur d'identité : instantané + recherche dans l'annuaire (facultative) */
function principalPicker(input, box, onPick, { live = false, kinds = null } = {}) {
  let items = [], hl = -1, timer = null, liveItems = [];
  const render = () => {
    const all = items.concat(liveItems.filter(l => !items.some(i => i.sid === l.sid)));
    if (!all.length) { box.hidden = true; return; }
    box.innerHTML = all.slice(0, 60).map((p, i) => `<button type="button" data-i="${i}" class="${i === hl ? 'hl' : ''}">${kindTag(p.kind)}<span class="grow ellipsis">${esc(p.name)}${p.displayName ? ` <span class="muted small">${esc(p.displayName)}</span>` : ''}</span>${p.live ? '<span class="tag blue">annuaire</span>' : ''}${p.privileged ? '<span class="tag warn">privilégié</span>' : ''}</button>`).join('');
    box.hidden = false;
    box.onclick = e => { const b = e.target.closest('button[data-i]'); if (b) pick(all[+b.dataset.i]); };
  };
  const pick = p => { box.hidden = true; input.value = p.name; onPick(p); };
  input.addEventListener('input', () => {
    const q = input.value.trim().toLowerCase(); hl = -1; liveItems = [];
    items = !q ? [] : Array.from(S.principals.values()).filter(p => (!kinds || kinds.includes(p.kind)) && ((p.name || '').toLowerCase().includes(q) || (p.displayName || '').toLowerCase().includes(q) || p.sid.toLowerCase() === q))
      .sort((a, b) => (b.explicitFolders - a.explicitFolders) || a.name.localeCompare(b.name, 'fr')).slice(0, 40);
    render();
    clearTimeout(timer);
    if (live && q.length >= 2) timer = setTimeout(async () => {
      const r = await request('searchDirectory', 'directorySearch', { text: q, kind: kinds && kinds.length === 1 ? (kinds[0] === 'User' ? 'user' : 'group') : 'any' });
      if (input.value.trim().toLowerCase() !== q) return;
      if (r.ok) { liveItems = (r.data.items || []).filter(p => !kinds || kinds.includes(p.kind)).map(p => Object.assign({ live: true }, p)); render(); }
    }, 450);
  });
  input.addEventListener('keydown', e => {
    const n = box.querySelectorAll('button').length;
    if (e.key === 'ArrowDown') { hl = Math.min(n - 1, hl + 1); render(); e.preventDefault(); }
    else if (e.key === 'ArrowUp') { hl = Math.max(0, hl - 1); render(); e.preventDefault(); }
    else if (e.key === 'Enter' && hl >= 0) { box.querySelectorAll('button')[hl]?.click(); e.preventDefault(); }
    else if (e.key === 'Escape') box.hidden = true;
  });
  input.addEventListener('blur', () => setTimeout(() => { if (document.activeElement !== input) box.hidden = true; }, 200));
}

on('error', m => toast(m.message || 'Erreur', true, 7000));
on('info', m => toast(m.message));
