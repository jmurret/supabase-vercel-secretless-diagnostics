const test = require('node:test');
const assert = require('node:assert/strict');
const html = require('../dashboard');

const OTHER = 'zyxwvutsrqponmlkjihg';
const SCRIPT = /<script>([\s\S]*)<\/script>/.exec(html)[1];
const flush = () => new Promise((resolve) => setImmediate(resolve));

function fakeNode() {
  return {
    children: [],
    dataset: {},
    classList: { toggle() {} },
    append(...c) {
      this.children.push(...c);
    },
    replaceChildren(...c) {
      this.children = c;
    },
    setAttribute() {},
    addEventListener() {},
  };
}

const check = (id, status) => ({ id, group: 'cross_tenant', description: id, status });
const ok = (body) => ({ ok: true, status: 200, json: async () => body });

// Runs the dashboard script. Each fetch waits until the test answers it with respond(path, response).
function loadDashboard(storage = {}) {
  const nodes = {};
  const store = { ...storage };
  const pending = [];
  const fetchImpl = (url) =>
    new Promise((resolve) => {
      pending.push({ url, resolve });
    });
  const localStorage = {
    getItem: (k) => (k in store ? store[k] : null),
    setItem: (k, v) => {
      store[k] = v;
    },
  };
  const document = { createElement: fakeNode, getElementById: (id) => (nodes[id] ??= fakeNode()), querySelectorAll: () => [] };
  const run = new Function('document', 'localStorage', 'fetch', 'location', 'history', 'window', `${SCRIPT}\nreturn { get results() { return results; } };`);
  const page = run(document, localStorage, fetchImpl, { hash: '', pathname: '/', search: '' }, { replaceState() {} }, { addEventListener() {} });
  const urls = () => pending.map((p) => p.url);
  async function respond(prefix, response) {
    const call = pending.find((p) => p.url.startsWith(prefix) && !p.done);
    assert.ok(call, `no pending call for ${prefix}: ${urls().join(', ')}`);
    call.done = true;
    call.resolve(response);
    await flush();
    await flush();
  }
  return { page, store, urls, respond };
}

const DIAGNOSTICS = ok({ checks: { results: [{ id: 'auth_path', group: 'path', description: 'x', status: 'pass' }] }, data: {} });
const s3Row = (page) => page.results.find((r) => r.id === 'cross_tenant_storage_s3');

test('dashboard: without saved regions, S3 waits for /api/cross-tenant and uses its regions', async () => {
  const { page, store, urls, respond } = loadDashboard();
  assert.deepEqual(urls(), ['/api/diagnostics', '/api/cross-tenant']);
  await respond('/api/diagnostics', DIAGNOSTICS);
  assert.deepEqual([s3Row(page).status, s3Row(page).detail], ['pending', 'Loading… (waiting for target region)']);
  const host = 'aws-0-us-west-1.pooler.supabase.com';
  await respond('/api/cross-tenant', ok({
    checks: { results: [check('cross_tenant_storage', 'pass'), check('cross_tenant_gateway_coverage', 'pass')] },
    data: { cross_tenant: { targets: [{ ref: OTHER, jit_pooler: { pooler_host: host, region: 'us-west-1' } }] } },
  }));
  assert.equal(urls()[2], `/api/cross-tenant-s3?regions=${encodeURIComponent(`${OTHER}:us-west-1`)}`);
  assert.deepEqual(JSON.parse(store.cross_tenant_targets), [OTHER]);
  assert.deepEqual(JSON.parse(store.pooler_hints), { [OTHER]: host });
  assert.deepEqual(page.results.filter((r) => r.group === 'cross_tenant').map((r) => r.id), ['cross_tenant_storage', 'cross_tenant_storage_s3', 'cross_tenant_gateway_coverage']);
  await respond('/api/cross-tenant-s3', ok({ checks: { results: [check('cross_tenant_storage_s3', 'warn')] }, data: {} }));
  assert.equal(s3Row(page).status, 'warn');
  assert.equal(s3Row(page).placeholder, undefined);
});

test('dashboard: with a saved region for every saved target, S3 starts at once and runs once', async () => {
  const { page, urls, respond } = loadDashboard({
    cross_tenant_targets: JSON.stringify([OTHER]),
    pooler_hints: JSON.stringify({ [OTHER]: 'aws-1-eu-west-2.pooler.supabase.com' }),
  });
  const query = `/api/cross-tenant-s3?regions=${encodeURIComponent(`${OTHER}:eu-west-2`)}`;
  assert.deepEqual(urls().slice(1).sort(), [`/api/cross-tenant?pooler_hints=${encodeURIComponent(`${OTHER}:aws-1-eu-west-2.pooler.supabase.com`)}`, query].sort());
  await respond('/api/diagnostics', DIAGNOSTICS);
  await respond('/api/cross-tenant-s3', ok({ checks: { results: [check('cross_tenant_storage_s3', 'pass')] }, data: {} }));
  assert.equal(s3Row(page).status, 'pass');
  await respond('/api/cross-tenant', ok({ checks: { results: [check('cross_tenant_rest', 'pass')] }, data: { cross_tenant: { targets: [{ ref: OTHER, jit_pooler: {} }] } } }));
  assert.equal(urls().length, 3);
  assert.equal(s3Row(page).status, 'pass');
});

test('dashboard: an S3 error becomes a warning row', async () => {
  const { page, respond } = loadDashboard();
  await respond('/api/diagnostics', DIAGNOSTICS);
  await respond('/api/cross-tenant', ok({ checks: { results: [] }, data: { cross_tenant: { skipped: 'not set' } } }));
  await respond('/api/cross-tenant-s3?regions=', { ok: false, status: 500, json: async () => ({ error: 'boom' }) });
  assert.deepEqual([s3Row(page).status, s3Row(page).detail], ['warn', 'Failed to load the Storage S3 check: boom']);
});
