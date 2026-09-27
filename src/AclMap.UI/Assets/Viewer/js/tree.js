'use strict';
/* Arbre virtualisé : seules les lignes visibles sont dans le DOM (des centaines de milliers de dossiers). */

function createTree(container, opts) {
  const ROW = 26;
  const expanded = new Set([0]);
  let rows = [];          // identifiants visibles, dans l'ordre
  let keep = null;        // filtre actif : nœuds à conserver (correspondances + ancêtres)
  let matches = null;
  let query = '';
  let selected = null;
  const inner = el('<div class="spacer-rows"></div>');
  container.innerHTML = '';
  container.appendChild(inner);

  function rebuild() {
    rows = [];
    if (!S.snap) { draw(); return; }
    const stack = [0];
    while (stack.length) {
      const id = stack.pop();
      if (keep && !keep.has(id)) continue;
      rows.push(id);
      if (expanded.has(id) || (keep && keep.size < 3000)) {
        const kids = S.children[id];
        for (let i = kids.length - 1; i >= 0; i--) stack.push(kids[i]);
      }
    }
    inner.style.height = rows.length * ROW + 'px';
    draw();
    opts.onCount && opts.onCount(rows.length, matches ? matches.size : null);
  }

  function highlight(name) {
    if (!query) return esc(name);
    const i = name.toLowerCase().indexOf(query);
    if (i < 0) return esc(name);
    return esc(name.slice(0, i)) + '<mark>' + esc(name.slice(i, i + query.length)) + '</mark>' + esc(name.slice(i + query.length));
  }

  function draw() {
    const top = container.scrollTop, h = container.clientHeight || 600;
    const first = Math.max(0, Math.floor(top / ROW) - 10), last = Math.min(rows.length, Math.ceil((top + h) / ROW) + 10);
    let html = '';
    for (let r = first; r < last; r++) {
      const id = rows[r];
      const kids = S.children[id].length;
      const open = expanded.has(id) || (keep && keep.size < 3000);
      const tw = kids ? (open ? '▾' : '▸') : '';
      const fl = S.flagsOf[id];
      const icon = fl & NF.File ? '📄' : fl & NF.Reparse ? '↪' : (fl & (NF.ListDenied | NF.SecUnreadable)) ? '🔒' : '📁';
      const name = id === 0 ? S.snap.manifest.rootPath : S.names[id];
      html += `<div class="trow${id === selected ? ' sel' : ''}${opts.dim && opts.dim(id) ? ' dim' : ''}" role="treeitem" aria-level="${S.depth[id] + 1}" aria-selected="${id === selected}" data-id="${id}" style="top:${r * ROW}px;padding-left:${6 + S.depth[id] * 16}px">`
        + `<span class="tw" data-tw="${id}">${tw}</span><span class="ic" aria-hidden="true">${icon}</span>${opts.before ? opts.before(id) : ''}<span class="nm" title="${esc(name)}">${highlight(name)}</span>`
        + `<span class="flags">${opts.flags ? opts.flags(id) : ''}</span></div>`;
    }
    inner.innerHTML = html;
  }

  container.addEventListener('scroll', () => requestAnimationFrame(draw));
  new ResizeObserver(() => draw()).observe(container);
  container.addEventListener('click', e => {
    const row = e.target.closest('.trow'); if (!row) return;
    const id = +row.dataset.id;
    if (e.target.closest('[data-tw]')) { toggle(id); return; }
    select(id);
  });
  container.addEventListener('dblclick', e => { const row = e.target.closest('.trow'); if (row) toggle(+row.dataset.id); });
  container.addEventListener('keydown', e => {
    if (selected == null) { if (rows.length) select(rows[0]); return; }
    const i = rows.indexOf(selected);
    if (e.key === 'ArrowDown' && i < rows.length - 1) select(rows[i + 1], true);
    else if (e.key === 'ArrowUp' && i > 0) select(rows[i - 1], true);
    else if (e.key === 'ArrowRight') { if (!expanded.has(selected)) toggle(selected); else if (S.children[selected][0] != null) select(S.children[selected][0], true); }
    else if (e.key === 'ArrowLeft') { if (expanded.has(selected) && selected !== 0) toggle(selected); else if (S.parent[selected] >= 0) select(S.parent[selected], true); }
    else return;
    e.preventDefault();
  });

  function toggle(id) { if (expanded.has(id)) expanded.delete(id); else expanded.add(id); rebuild(); }

  function select(id, scroll = false) {
    selected = id;
    reveal(id, scroll);
    opts.onSelect && opts.onSelect(id);
  }

  function reveal(id, scroll = true) {
    let changed = false;
    for (let p = S.parent[id]; p >= 0; p = S.parent[p]) if (!expanded.has(p)) { expanded.add(p); changed = true; }
    if (keep && !keep.has(id)) { keep = null; matches = null; changed = true; }
    if (changed) rebuild(); else draw();
    if (scroll) {
      const r = rows.indexOf(id);
      if (r >= 0 && (r * ROW < container.scrollTop || r * ROW > container.scrollTop + container.clientHeight - ROW * 2))
        container.scrollTop = Math.max(0, r * ROW - container.clientHeight / 3);
      draw();
    }
  }

  /** Filtre : prédicat (id → bool) et/ou texte ; les ancêtres des correspondances restent visibles. */
  function setFilter(pred, text) {
    query = (text || '').trim().toLowerCase();
    if (!pred && !query) { keep = null; matches = null; rebuild(); return; }
    matches = new Set(); keep = new Set();
    const n = S.names ? S.names.length : 0;
    for (let i = 0; i < n; i++) {
      const name = (i === 0 ? S.snap.manifest.rootPath : S.names[i]).toLowerCase();
      if ((!query || name.includes(query)) && (!pred || pred(i))) {
        matches.add(i);
        for (let c = i; c >= 0 && !keep.has(c); c = S.parent[c]) keep.add(c);
      }
    }
    rebuild();
  }

  return {
    refresh: () => rebuild(), redraw: () => draw(), select, reveal, setFilter,
    get selected() { return selected; },
    expandAll(depth = 2) { for (let i = 0; i < S.names.length; i++) if (S.depth[i] < depth && S.children[i].length) expanded.add(i); rebuild(); },
    reset() { expanded.clear(); expanded.add(0); selected = null; keep = null; matches = null; query = ''; container.scrollTop = 0; rebuild(); },
  };
}
