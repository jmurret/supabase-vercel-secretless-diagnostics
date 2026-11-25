module.exports = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Supabase × Vercel secretless diagnostics</title>
  <style>
    :root {
      --pass: #16a34a; --pass-bg: #dcfce7;
      --warn: #ca8a04; --warn-bg: #fef9c3;
      --fail: #dc2626; --fail-bg: #fee2e2;
      --skip: #6b7280; --skip-bg: #f3f4f6;
      --pending: #94a3b8; --pending-bg: #f8fafc;
    }
    * { box-sizing: border-box; }
    body { font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 24px; background: #f8fafc; color: #0f172a; }
    header { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; margin-bottom: 20px; }
    h1 { font-size: 20px; margin: 0; }
    h2 { font-size: 15px; margin: 24px 0 8px; text-transform: uppercase; letter-spacing: .04em; color: #475569; }
    .meta { color: #64748b; font-size: 13px; }
    .summary { display: flex; gap: 8px; flex-wrap: wrap; }
    .pill { padding: 4px 10px; border-radius: 999px; font-size: 13px; font-weight: 600; border: 2px solid transparent; font-family: inherit; }
    button.pill { cursor: pointer; }
    button.pill:disabled { cursor: default; opacity: .4; }
    .summary.filtered button.pill:not(.active) { opacity: .5; }
    button.pill.active { border-color: currentColor; }
    .check { border-left: 6px solid; border-radius: 6px; padding: 10px 14px; margin-bottom: 8px; background: #fff; box-shadow: 0 1px 2px rgba(0,0,0,.05); }
    .check .title { display: flex; justify-content: space-between; gap: 12px; font-weight: 600; }
    .check .id { font-family: ui-monospace, monospace; font-size: 12px; color: #64748b; font-weight: 400; }
    .check .detail { margin-top: 4px; font-size: 14px; }
    .check dl { display: grid; grid-template-columns: max-content 1fr; gap: 2px 12px; margin: 6px 0 0; font-size: 13px; }
    .check dt { color: #64748b; }
    .check dd { margin: 0; font-family: ui-monospace, monospace; white-space: pre-wrap; word-break: break-all; }
    .check.pass { border-color: var(--pass); } .pill.pass { background: var(--pass-bg); color: var(--pass); }
    .check.warn { border-color: var(--warn); } .pill.warn { background: var(--warn-bg); color: var(--warn); }
    .check.fail { border-color: var(--fail); } .pill.fail { background: var(--fail-bg); color: var(--fail); }
    .check.skip { border-color: var(--skip); } .pill.skip { background: var(--skip-bg); color: var(--skip); }
    .check.pass { background: var(--pass-bg); } .check.warn { background: var(--warn-bg); }
    .check.fail { background: var(--fail-bg); }
    .check.skip { background: var(--skip-bg); }
    .check.pending { border-color: var(--pending); border-left-style: dashed; background: var(--pending-bg); color: #64748b; font-style: italic; }
    .pill.pending { background: var(--pending-bg); color: #64748b; border: 2px dashed var(--pending); }
    .error { color: var(--fail); }
    details { margin-top: 24px; }
    pre { background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 6px; overflow: auto; font-size: 12px; }
  </style>
</head>
<body>
  <header>
    <h1>Supabase × Vercel secretless diagnostics</h1>
    <div class="summary" id="summary"></div>
    <span class="meta" id="meta"></span>
  </header>
  <main id="checks"><p class="meta">Loading…</p></main>
  <details>
    <summary>Raw responses (<a href="/api/diagnostics">/api/diagnostics</a>, <a href="/api/cross-tenant">/api/cross-tenant</a>, <a href="/api/cross-tenant-s3">/api/cross-tenant-s3</a>)</summary>
    <pre id="raw"></pre>
  </details>
  <script>
    const LABELS = { pass: 'Pass', warn: 'Warning', fail: 'Fail', skip: 'Skipped', pending: 'Loading' };
    const STATUSES = ['pass', 'warn', 'fail', 'skip'];
    const CROSS_TENANT_PLACEHOLDER = {
      id: 'cross_tenant', group: 'cross_tenant', description: 'Cross-tenant checks', status: 'pending', detail: 'Loading…', placeholder: true,
    };
    const S3_PLACEHOLDER = {
      id: 'cross_tenant_storage_s3', group: 'cross_tenant', description: 'Storage S3 on other tenants', status: 'pending',
      detail: 'Loading… (waiting for target region)', placeholder: true,
    };
    let results = [];
    let diagnosticsResults = null;
    let crossTenantResults = [CROSS_TENANT_PLACEHOLDER];
    let s3Results = [S3_PLACEHOLDER];
    const raw = { diagnostics: null, cross_tenant: null, cross_tenant_s3: null };
    let filter = STATUSES.includes(location.hash.slice(1)) ? location.hash.slice(1) : null;

    function el(tag, attrs = {}, ...children) {
      const node = document.createElement(tag);
      Object.assign(node, attrs);
      for (const child of children) if (child != null) node.append(child);
      return node;
    }

    const fmt = (v) => (v === null || v === undefined ? '—' : typeof v === 'string' ? v : JSON.stringify(v, null, 2));

    function renderCheck(r) {
      const dl = el('dl', {},
        el('dt', { textContent: 'expected' }), el('dd', { textContent: fmt(r.expected) }),
        el('dt', { textContent: 'actual' }), el('dd', { textContent: fmt(r.actual) }));
      return el('div', { className: 'check ' + r.status },
        el('div', { className: 'title' },
          el('span', {}, r.description, ' ', el('span', { className: 'id', textContent: r.id })),
          el('span', { className: 'pill ' + r.status, textContent: LABELS[r.status] || r.status })),
        r.detail ? el('div', { className: 'detail', textContent: r.detail }) : null,
        r.status === 'skip' || r.status === 'pending' || r.placeholder ? null : dl);
    }

    function setFilter(status) {
      filter = status === filter ? null : status;
      history.replaceState(null, '', filter ? '#' + filter : location.pathname + location.search);
      render();
    }

    function render() {
      document.getElementById('summary').classList.toggle('filtered', Boolean(filter));
      for (const pill of document.querySelectorAll('#summary button.pill')) {
        const active = pill.dataset.filter === (filter || 'all');
        pill.classList.toggle('active', active);
        pill.setAttribute('aria-pressed', String(active));
      }
      const groups = new Map();
      for (const r of results) {
        if (filter && r.status !== filter && r.status !== 'pending') continue;
        if (!groups.has(r.group)) groups.set(r.group, []);
        groups.get(r.group).push(r);
      }
      const main = document.getElementById('checks');
      if (!groups.size) {
        main.replaceChildren(el('p', { className: 'meta', textContent: 'No checks match this filter.' }));
        return;
      }
      main.replaceChildren(...[...groups].flatMap(([group, items]) => [
        el('h2', { textContent: group.replace(/_/g, ' ') }),
        ...items.map(renderCheck),
      ]));
    }

    function pill(status, text, value, count) {
      const button = el('button', { type: 'button', className: 'pill ' + status, textContent: text, disabled: count === 0 });
      button.dataset.filter = value;
      button.title = value === 'all' ? 'Show all checks' : 'Show only ' + LABELS[status].toLowerCase() + ' checks';
      button.addEventListener('click', () => setFilter(value === 'all' ? null : value));
      return button;
    }

    const HINTS_KEY = 'pooler_hints';

    function readHints() {
      try {
        const hints = JSON.parse(localStorage.getItem(HINTS_KEY));
        return hints && typeof hints === 'object' ? hints : {};
      } catch {
        return {};
      }
    }

    const TARGETS_KEY = 'cross_tenant_targets';

    function readTargets() {
      try {
        const refs = JSON.parse(localStorage.getItem(TARGETS_KEY));
        return Array.isArray(refs) ? refs.filter((ref) => typeof ref === 'string') : [];
      } catch {
        return [];
      }
    }

    function saveHints(targets) {
      try {
        const hints = readHints();
        for (const t of targets || []) {
          if (t.jit_pooler && t.jit_pooler.pooler_host) hints[t.ref] = t.jit_pooler.pooler_host;
        }
        localStorage.setItem(HINTS_KEY, JSON.stringify(hints));
        if (targets) localStorage.setItem(TARGETS_KEY, JSON.stringify(targets.map((t) => t.ref)));
      } catch {}
    }

    function hintsQuery() {
      const pairs = Object.entries(readHints()).map(([ref, host]) => ref + ':' + host);
      return pairs.length ? '?pooler_hints=' + encodeURIComponent(pairs.join(',')) : '';
    }

    const regionOfHost = (host) => (/^aws-\\d+-([a-z]{2}-[a-z]+-\\d+)\\.pooler\\./.exec(host || '') || [])[1];

    // ref -> region, from the pooler hosts in the hints and in a /api/cross-tenant response.
    function knownRegions(targets) {
      const regions = {};
      for (const [ref, host] of Object.entries(readHints())) {
        const region = regionOfHost(host);
        if (region) regions[ref] = region;
      }
      for (const t of targets || []) {
        const region = t.jit_pooler && (t.jit_pooler.region || regionOfHost(t.jit_pooler.pooler_host));
        if (region) regions[t.ref] = region;
      }
      return regions;
    }

    // Returns null when a target has no known region.
    function regionsQuery(refs, regions) {
      if (!refs.length || refs.some((ref) => !regions[ref])) return null;
      return '?regions=' + encodeURIComponent(refs.map((ref) => ref + ':' + regions[ref]).join(','));
    }

    async function fetchJson(url, rawKey) {
      const res = await fetch(url, { cache: 'no-store', headers: { accept: 'application/json' } });
      const body = await res.json();
      raw[rawKey] = body;
      document.getElementById('raw').textContent = JSON.stringify(raw, null, 2);
      if (!res.ok) throw new Error(body.error || 'HTTP ' + res.status);
      return body;
    }

    function summarize(items) {
      const count = (status) => items.filter((r) => r.status === status).length;
      const s = { passed: count('pass'), warned: count('warn'), failed: count('fail'), skipped: count('skip'), pending: count('pending') };
      s.status = s.failed ? 'fail' : s.warned ? 'warn' : 'pass';
      return s;
    }

    function renderSummary() {
      const s = summarize(results);
      const pills = [
        pill(s.status, 'Overall: ' + LABELS[s.status], 'all'),
        pill('pass', s.passed + ' passed', 'pass', s.passed),
        pill('warn', s.warned + ' warnings', 'warn', s.warned),
        pill('fail', s.failed + ' failed', 'fail', s.failed),
        pill('skip', s.skipped + ' skipped', 'skip', s.skipped),
      ];
      if (s.pending) pills.push(el('span', { className: 'pill pending', textContent: s.pending + ' loading' }));
      document.getElementById('summary').replaceChildren(...pills);
    }

    // The S3 check goes after cross_tenant_storage, or at the end of the group.
    function crossTenantGroup() {
      const at = crossTenantResults.findIndex((r) => r.id === 'cross_tenant_storage');
      if (at < 0) return [...crossTenantResults, ...s3Results];
      return [...crossTenantResults.slice(0, at + 1), ...s3Results, ...crossTenantResults.slice(at + 1)];
    }

    function update() {
      if (!diagnosticsResults) return;
      results = [...diagnosticsResults, ...crossTenantGroup()];
      renderSummary();
      render();
    }

    async function loadDiagnostics() {
      try {
        const { checks, data } = await fetchJson('/api/diagnostics', 'diagnostics');
        const env = data.environment || {};
        document.getElementById('meta').textContent = [checks.spec, env.vercel_env, env.vercel_region, env.supabase_url_host, data.timestamp]
          .filter(Boolean).join(' · ');
        diagnosticsResults = checks.results;
        update();
      } catch (err) {
        document.getElementById('summary').replaceChildren();
        document.getElementById('checks').replaceChildren(el('p', { className: 'error', textContent: 'Failed to load diagnostics: ' + err.message }));
      }
    }

    // Returns the targets of the response, or null when the call failed.
    async function loadCrossTenant() {
      let targets = null;
      try {
        const { checks, data } = await fetchJson('/api/cross-tenant' + hintsQuery(), 'cross_tenant');
        targets = (data.cross_tenant && data.cross_tenant.targets) || [];
        saveHints(data.cross_tenant && data.cross_tenant.targets);
        crossTenantResults = checks.results;
      } catch (err) {
        crossTenantResults = [{ ...CROSS_TENANT_PLACEHOLDER, status: 'warn', detail: 'Failed to load cross-tenant checks: ' + err.message }];
      }
      update();
      return targets;
    }

    let s3Query = null;

    // A later call replaces the result of an earlier one.
    async function loadS3(query) {
      s3Query = query;
      try {
        const { checks } = await fetchJson('/api/cross-tenant-s3' + query, 'cross_tenant_s3');
        if (query === s3Query) s3Results = checks.results;
      } catch (err) {
        if (query === s3Query) s3Results = [{ ...S3_PLACEHOLDER, status: 'warn', detail: 'Failed to load the Storage S3 check: ' + err.message }];
      }
      update();
    }

    // The S3 check needs the region of each target. With a saved region for every saved target, it starts at
    // once. Otherwise it waits for the pooler hosts that /api/cross-tenant finds.
    async function loadCrossTenantGroup() {
      const early = regionsQuery(readTargets(), knownRegions());
      if (early) loadS3(early);
      const targets = await loadCrossTenant();
      const refs = targets ? targets.map((t) => t.ref) : readTargets();
      const regions = knownRegions(targets);
      const late = regionsQuery(refs, regions) ||
        '?regions=' + encodeURIComponent(refs.filter((ref) => regions[ref]).map((ref) => ref + ':' + regions[ref]).join(','));
      if (late !== early) loadS3(late);
    }

    function load() {
      loadDiagnostics();
      loadCrossTenantGroup();
    }

    window.addEventListener('hashchange', () => {
      const status = location.hash.slice(1);
      filter = STATUSES.includes(status) ? status : null;
      render();
    });
    load();
  </script>
</body>
</html>
`;
