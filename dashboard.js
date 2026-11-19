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
    .check.fail { background: var(--fail-bg); } .check.skip { background: var(--skip-bg); }
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
    <summary>Raw response (<a href="/api/diagnostics">/api/diagnostics</a>)</summary>
    <pre id="raw"></pre>
  </details>
  <script>
    const LABELS = { pass: 'Pass', warn: 'Warning', fail: 'Fail', skip: 'Skipped' };
    const STATUSES = Object.keys(LABELS);
    let results = [];
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
        r.status === 'skip' ? null : dl);
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
        if (filter && r.status !== filter) continue;
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

    async function load() {
      const main = document.getElementById('checks');
      const summary = document.getElementById('summary');
      const meta = document.getElementById('meta');
      try {
        const res = await fetch('/api/diagnostics', { cache: 'no-store', headers: { accept: 'application/json' } });
        const body = await res.json();
        document.getElementById('raw').textContent = JSON.stringify(body, null, 2);
        if (!res.ok) throw new Error(body.error || 'HTTP ' + res.status);
        const { checks, data } = body;
        const s = checks.summary;
        summary.replaceChildren(
          pill(s.status, 'Overall: ' + LABELS[s.status], 'all'),
          pill('pass', s.passed + ' passed', 'pass', s.passed),
          pill('warn', s.warned + ' warnings', 'warn', s.warned),
          pill('fail', s.failed + ' failed', 'fail', s.failed),
          pill('skip', s.skipped + ' skipped', 'skip', s.skipped));
        const env = data.environment || {};
        meta.textContent = [checks.spec, env.vercel_env, env.vercel_region, env.supabase_url_host, data.timestamp]
          .filter(Boolean).join(' · ');
        results = checks.results;
        render();
      } catch (err) {
        summary.replaceChildren();
        main.replaceChildren(el('p', { className: 'error', textContent: 'Failed to load diagnostics: ' + err.message }));
      }
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
