// CTI Aggregator — operations console (vanilla JS, no build step)
(function () {
  if (!document.getElementById('iocs-body')) return;  // only on dashboard page

  const state = { page: 0, pageSize: 50, total: 0, loading: false };

  // --- Utilities --------------------------------------------------------
  function scoreClass(s) {
    if (s >= 80) return 'pill-high';
    if (s >= 40) return 'pill-med';
    return 'pill-low';
  }
  function fmtDate(s) {
    if (!s) return '—';
    const d = new Date(s);
    const now = Date.now();
    const diff = (now - d.getTime()) / 1000;
    if (diff < 60) return 'just now';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    if (diff < 86400 * 30) return Math.floor(diff / 86400) + 'd ago';
    return d.toLocaleDateString();
  }
  function fmtFull(s) { return s ? new Date(s).toLocaleString() : '—'; }
  function escapeHTML(s) {
    return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function num(n) { return (n == null) ? '—' : new Intl.NumberFormat().format(n); }

  // --- Filters / URL ----------------------------------------------------
  function getFilters() {
    return {
      q: document.getElementById('f-q').value.trim(),
      type: document.getElementById('f-type').value,
      source: document.getElementById('f-source').value,
      min_score: document.getElementById('f-min-score').value,
      days: document.getElementById('f-days').value,
      keyword: document.getElementById('f-keyword').value.trim(),
    };
  }
  function setKeywordFilter(kw) {
    document.getElementById('f-keyword').value = kw;
    state.page = 0;
    loadIOCs();
    updateExportLinks();
    document.getElementById('f-keyword').scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
  // Expose for inline onclick handlers in row HTML.
  window.__cti = { setKeywordFilter };
  function buildQS(extras = {}) {
    const f = { ...getFilters(), ...extras };
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(f)) if (v) qs.set(k, v);
    return qs.toString();
  }

  // --- Loaders ----------------------------------------------------------
  async function loadStats() {
    try {
      const r = await fetch('/api/stats');
      const d = await r.json();
      document.getElementById('stat-total').textContent = num(d.total);
      document.getElementById('stat-high').textContent = num(d.high_score);
      document.getElementById('stat-med').textContent = num(d.med_score);
      document.getElementById('stat-24h').textContent = num(d.last_24h);
      const top = (d.top_actors && d.top_actors[0]);
      document.getElementById('stat-top-actor').textContent = top ? top.actor : '—';
      document.getElementById('stat-top-actor-count').textContent = top ? `${top.count} IOCs attributed` : '—';
      document.getElementById('stat-24h-delta').textContent = `+${num(d.last_24h)} in last 24h`;
    } catch (e) { console.error(e); }
  }

  async function loadSources() {
    try {
      const r = await fetch('/api/feeds');
      const d = await r.json();
      const sel = document.getElementById('f-source');
      const existing = new Set([...sel.options].map(o => o.value));
      for (const f of d.feeds) {
        if (!existing.has(f.name)) {
          const o = document.createElement('option');
          o.value = f.name; o.textContent = f.display_name;
          sel.appendChild(o);
        }
      }
    } catch (e) { console.error(e); }
  }

  function rowSkeleton() {
    return `
      <tr>
        <td><span class="skel" style="width:80%; height:12px"></span></td>
        <td><span class="skel" style="width:36px; height:18px"></span></td>
        <td><span class="skel" style="width:38px; height:22px"></span></td>
        <td><span class="skel" style="width:60%; height:14px"></span></td>
        <td><span class="skel" style="width:80px; height:12px"></span></td>
        <td><span class="skel" style="width:60px; height:12px"></span></td>
        <td><span class="skel" style="width:50px; height:10px"></span></td>
      </tr>`;
  }

  async function loadIOCs() {
    if (state.loading) return;
    state.loading = true;
    const tbody = document.getElementById('iocs-body');
    tbody.innerHTML = rowSkeleton().repeat(8);

    try {
      const qs = buildQS({ limit: state.pageSize, offset: state.page * state.pageSize });
      const r = await fetch('/api/iocs?' + qs);
      const d = await r.json();
      state.total = d.total;

      document.getElementById('result-count').textContent =
        `${num(d.total)} result${d.total === 1 ? '' : 's'}` +
        (d.total > state.pageSize ? ` · showing ${state.page * state.pageSize + 1}–${Math.min((state.page + 1) * state.pageSize, d.total)}` : '');
      document.getElementById('page-info').textContent =
        `${state.page + 1} / ${Math.max(1, Math.ceil(d.total / state.pageSize))}`;

      document.getElementById('prev-page').disabled = state.page === 0;
      document.getElementById('next-page').disabled = (state.page + 1) * state.pageSize >= d.total;

      tbody.innerHTML = '';
      if (d.items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:40px; color:var(--text-faint)">
          No indicators match your filters.</td></tr>`;
        return;
      }

      for (const i of d.items) {
        const tr = document.createElement('tr');
        const sourceCell = (i.source_links && i.source_links.length)
          ? i.source_links.map(s => s.url
              ? `<a href="${escapeHTML(s.url)}" target="_blank" rel="noopener" class="source-link" title="Open source article">${escapeHTML(s.name)}<span class="arrow">↗</span></a>`
              : `<span class="faint">${escapeHTML(s.name)}</span>`).join(', &nbsp;')
          : '<span class="faint">—</span>';
        const whyCell = (i.score_chips && i.score_chips.length)
          ? i.score_chips.map(c => {
              // First keyword in the label is what we'll filter by on click.
              const first = (c.label.split(',')[0] || '').trim();
              const clickable = first && !c.label.endsWith(' host') && !c.label.startsWith('geo:') && !c.label.startsWith('ASN') && c.label !== 'sector+region';
              return clickable
                ? `<a href="#" class="why-chip why-chip-click" title="Click to filter IOCs by &quot;${escapeHTML(first)}&quot; (+${c.points} pts)" data-kw="${escapeHTML(first)}">${escapeHTML(c.label)}<span class="why-pts">+${c.points}</span></a>`
                : `<span class="why-chip" title="+${c.points} pts">${escapeHTML(c.label)}<span class="why-pts">+${c.points}</span></span>`;
            }).join('')
          : '<span class="why-empty">—</span>';
        const tagsCell = i.tags.slice(0, 4).map(t => `<span class="tag">${escapeHTML(t)}</span>`).join('') +
          (i.tags.length > 4 ? `<span class="tag">+${i.tags.length - 4}</span>` : '');

        tr.innerHTML = `
          <td><span class="ioc-value mono">${escapeHTML(i.value)}</span></td>
          <td><span class="type-chip" data-type="${i.type}">${i.type}</span></td>
          <td><span class="pill ${scoreClass(i.relevance_score)}">${i.relevance_score}</span></td>
          <td>${whyCell}</td>
          <td>${sourceCell}</td>
          <td>${tagsCell || '<span class="faint">—</span>'}</td>
          <td><span class="faint mono" style="font-size:0.74rem" title="${fmtFull(i.last_seen)}">${fmtDate(i.last_seen)}</span></td>`;
        tr.addEventListener('click', (e) => {
          if (e.target.closest('a.source-link')) return;
          const kwEl = e.target.closest('a.why-chip-click');
          if (kwEl) {
            e.preventDefault();
            setKeywordFilter(kwEl.dataset.kw);
            return;
          }
          openDrawer(i.id);
        });
        tbody.appendChild(tr);
      }
    } catch (e) {
      console.error(e);
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--score-high)">
        Failed to load IOCs. Check the server log.</td></tr>`;
    } finally {
      state.loading = false;
    }
  }

  // --- Drawer -----------------------------------------------------------
  async function openDrawer(id) {
    const drawer = document.getElementById('drawer');
    const body = document.getElementById('drawer-body');
    document.getElementById('drawer-title').textContent = '—';
    document.getElementById('drawer-sub').textContent = 'Loading…';
    body.innerHTML = '<div class="drawer-section"><div class="skel" style="width:100%; height:90px"></div></div>';
    drawer.classList.add('open');
    document.body.style.overflow = 'hidden';

    try {
      const r = await fetch('/api/iocs/' + id);
      const d = await r.json();
      document.getElementById('drawer-title').textContent = d.value;
      document.getElementById('drawer-sub').textContent = `${d.type.toUpperCase()} INDICATOR  ·  score ${d.relevance_score}`;

      const metaCells = [
        { label: 'Relevance score', value: `<span class="pill ${scoreClass(d.relevance_score)}" style="height:auto; padding:4px 10px; font-size:0.9rem">${d.relevance_score}</span>` },
        { label: 'Type', value: `<span class="type-chip" data-type="${d.type}">${d.type}</span>` },
        { label: 'First seen', value: fmtFull(d.first_seen) },
        { label: 'Last seen', value: fmtFull(d.last_seen) },
        d.threat_actor ? { label: 'Threat actor', value: escapeHTML(d.threat_actor) } : null,
        d.malware_family ? { label: 'Malware family', value: escapeHTML(d.malware_family) } : null,
        d.cve ? { label: 'CVE', value: escapeHTML(d.cve) } : null,
      ].filter(Boolean);

      const metaHTML = `<div class="metric-grid">${metaCells.map(c => `
        <div class="metric-cell">
          <div class="label">${c.label}</div>
          <div class="value">${c.value}</div>
        </div>`).join('')}</div>`;

      const reasonsHTML = (d.scoring_reasons && d.scoring_reasons.length) ? `
        <div class="reasons-list">
          ${d.scoring_reasons.map(r => `
            <div class="reason-row">
              <span class="reason-text">${escapeHTML(r.reason)}</span>
              <span class="reason-pts">+${r.points}</span>
            </div>`).join('')}
        </div>` : '<div class="faint">No scoring reasons recorded.</div>';

      const tagsHTML = (d.tags && d.tags.length)
        ? d.tags.map(t => `<span class="tag">${escapeHTML(t)}</span>`).join(' ')
        : '<span class="faint">No tags</span>';

      const sourcesHTML = (d.source_records && d.source_records.length) ? d.source_records.map(s => `
        <div class="source-card">
          <div class="source-card-head">
            <span class="source-card-name">${escapeHTML(s.source)}</span>
            ${s.url ? `<a class="source-card-link" href="${escapeHTML(s.url)}" target="_blank" rel="noopener">Read article ↗</a>` : ''}
          </div>
          ${s.url ? `<div class="source-card-url">${escapeHTML(s.url)}</div>` : ''}
          ${s.raw_context ? `<div class="source-card-ctx">${escapeHTML(s.raw_context)}</div>` : ''}
          <div class="source-card-meta">Ingested ${fmtFull(s.ingested_at)}</div>
        </div>`).join('') : '<div class="faint">No source records.</div>';

      body.innerHTML = `
        <div class="drawer-section">${metaHTML}</div>
        <div class="drawer-section">
          <h4>Why relevant? — scoring breakdown</h4>
          ${reasonsHTML}
        </div>
        <div class="drawer-section">
          <h4>Tags</h4>
          ${tagsHTML}
        </div>
        <div class="drawer-section">
          <h4>Source records · ${(d.source_records || []).length}</h4>
          ${sourcesHTML}
        </div>`;
    } catch (e) {
      body.innerHTML = `<div style="color:var(--score-high)">Failed to load detail.</div>`;
    }
  }

  function closeDrawer() {
    document.getElementById('drawer').classList.remove('open');
    document.body.style.overflow = '';
  }

  // --- Export links -----------------------------------------------------
  function updateExportLinks() {
    const qs = buildQS();
    document.getElementById('btn-export-csv').href = '/api/export?format=csv&' + qs;
    document.getElementById('btn-export-json').href = '/api/export?format=json&' + qs;
    document.getElementById('btn-export-stix').href = '/api/export?format=stix&' + qs;
  }

  // --- Wire up ----------------------------------------------------------
  document.getElementById('btn-apply').addEventListener('click', () => {
    state.page = 0;
    loadIOCs();
    updateExportLinks();
  });
  document.getElementById('btn-reset').addEventListener('click', () => {
    for (const id of ['f-q', 'f-type', 'f-source', 'f-min-score', 'f-days', 'f-keyword']) {
      document.getElementById(id).value = '';
    }
    state.page = 0;
    loadIOCs();
    updateExportLinks();
  });
  // Enter-to-apply in search + keyword box
  for (const id of ['f-q', 'f-keyword']) {
    document.getElementById(id).addEventListener('keydown', (e) => {
      if (e.key === 'Enter') document.getElementById('btn-apply').click();
    });
  }

  document.getElementById('prev-page').addEventListener('click', () => {
    if (state.page > 0) { state.page--; loadIOCs(); }
  });
  document.getElementById('next-page').addEventListener('click', () => {
    if ((state.page + 1) * state.pageSize < state.total) { state.page++; loadIOCs(); }
  });
  document.getElementById('drawer-close').addEventListener('click', closeDrawer);
  document.getElementById('drawer-bg').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });

  // --- Init -------------------------------------------------------------
  (async function init() {
    await loadSources();
    await loadStats();
    await loadIOCs();
    updateExportLinks();
    setInterval(loadStats, 20000);
  })();
})();
