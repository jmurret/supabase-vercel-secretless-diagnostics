const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const crossTenant = require('../cross-tenant');
const { runChecks } = require('../checks');
const { oidcData, fakeRealtime } = require('./helpers');

const noFetch = () => {
  throw new Error('unexpected fetch');
};
const options = (extra) => ({ env: {}, now: () => 0, fetchImpl: noFetch, ...extra });
const isCrossTenant = (r) => r.group === 'cross_tenant';
const OTHER = 'zyxwvutsrqponmlkjihg';

test('runChecks include runs only the listed groups and the summary covers only them', async () => {
  const data = oidcData({ cross_tenant: { skipped: 'no targets' } });
  const { results, summary } = await runChecks(data, {}, options({ include: ['cross_tenant'] }));
  assert.ok(results.length > 0);
  assert.ok(results.every(isCrossTenant));
  assert.equal(summary.skipped, results.length);
  assert.equal(summary.passed + summary.warned + summary.failed + summary.skipped, results.length);
});

test('runChecks exclude drops the listed groups and the summary covers only the rest', async () => {
  const data = oidcData();
  const all = await runChecks(data, {}, options());
  const rest = await runChecks(data, {}, options({ exclude: ['cross_tenant'] }));
  const group = all.results.filter(isCrossTenant);
  assert.ok(group.length > 0);
  assert.equal(rest.results.length, all.results.length - group.length);
  assert.ok(rest.results.every((r) => !isCrossTenant(r)));
  const total = (s) => s.passed + s.warned + s.failed + s.skipped;
  assert.equal(total(rest.summary), rest.results.length);
});

test('control error detail does not repeat the status', async () => {
  const body = JSON.stringify({ code: 403, error_code: 'bad_jwt', msg: 'rejected' });
  const stub = async (url) => {
    const u = new URL(url);
    if (u.pathname === '/auth/v1/health') return new Response('{}', { status: 200 });
    return u.hostname.startsWith('abcdefghijklmnopqrst') ? new Response(body, { status: 403 }) : new Response('{}', { status: 401 });
  };
  const ct = await crossTenant.runCrossTenant({
    spec: `${OTHER}=sb_publishable_other`,
    ownUrl: 'https://abcdefghijklmnopqrst.supabase.co',
    ownKey: 'sb_publishable_own',
    token: 'header.payload.signature',
    fetchImpl: stub,
    createClientImpl: fakeRealtime().createClientImpl,
  });
  const row = crossTenant.evaluateService(ct, crossTenant.SERVICES[0]).rows[0].variants.v1;
  assert.equal(row.control_error, '403 bad_jwt: rejected');
  assert.match(row.reason, /control on this tenant returned 403;.*\(403 bad_jwt: rejected\)$/);
  assert.ok(!row.reason.includes('403 403'));
});

function loadHandler(name, spy, s3Spy = spyRunCrossTenant()) {
  const stubs = {
    '@supabase/supabase-js': { createClient: () => ({}) },
    '@vercel/functions/oidc': { getVercelOidcToken: async () => null },
    pg: { Client: class {} },
  };
  const realLoad = Module._load;
  const realRun = crossTenant.runCrossTenant;
  const realRunS3 = crossTenant.runCrossTenantS3;
  const paths = ['../diagnostics-core', `../api/${name}`].map((p) => require.resolve(p));
  Module._load = function (request, ...rest) {
    return request in stubs ? stubs[request] : realLoad.call(this, request, ...rest);
  };
  crossTenant.runCrossTenant = spy;
  crossTenant.runCrossTenantS3 = s3Spy;
  paths.forEach((p) => delete require.cache[p]);
  try {
    return require(paths[1]);
  } finally {
    Module._load = realLoad;
    crossTenant.runCrossTenant = realRun;
    crossTenant.runCrossTenantS3 = realRunS3;
    paths.forEach((p) => delete require.cache[p]);
  }
}

async function call(handler, path, { method = 'GET', headers = {} } = {}) {
  const res = {
    writeHead(status) {
      this.status = status;
    },
    end(body) {
      this.body = JSON.parse(body);
    },
  };
  await handler({ method, url: path, headers }, res);
  return res;
}

function spyRunCrossTenant() {
  const spy = async (args) => {
    spy.calls.push(args);
    return { skipped: 'spy' };
  };
  spy.calls = [];
  return spy;
}

test('/api/diagnostics does not run the cross-tenant probes or return their checks', async () => {
  const spy = spyRunCrossTenant();
  const res = await call(loadHandler('diagnostics', spy), '/api/diagnostics');
  assert.equal(res.status, 200);
  assert.equal(spy.calls.length, 0);
  assert.ok(!('cross_tenant' in res.body.data));
  assert.ok(res.body.checks.results.length > 0);
  assert.ok(res.body.checks.results.every((r) => !isCrossTenant(r)));
  assert.equal(res.body.checks.summary.skipped, res.body.checks.results.filter((r) => r.status === 'skip').length);
});

test('/api/diagnostics ignores the old cross_tenant query parameter', async () => {
  const spy = spyRunCrossTenant();
  const res = await call(loadHandler('diagnostics', spy), '/api/diagnostics?cross_tenant=later');
  assert.equal(res.status, 200);
  assert.equal(spy.calls.length, 0);
});

test('/api/cross-tenant returns only the cross_tenant group', async () => {
  const spy = spyRunCrossTenant();
  const res = await call(loadHandler('cross-tenant', spy), '/api/cross-tenant');
  assert.equal(res.status, 200);
  assert.equal(spy.calls.length, 1);
  assert.deepEqual(Object.keys(res.body.data).sort(), ['cross_tenant', 'jit']);
  assert.deepEqual(Object.keys(res.body.data.jit).sort(), ['management_api', 'postgres_login']);
  assert.deepEqual(res.body.data.cross_tenant, { skipped: 'spy' });
  const { results, summary } = res.body.checks;
  assert.ok(results.length > 0 && results.every(isCrossTenant));
  assert.ok(!results.some((r) => r.id === 'cross_tenant_storage_s3'));
  assert.equal(summary.passed + summary.warned + summary.failed + summary.skipped, results.length);
});

test('/api/cross-tenant-s3 runs only the S3 probes and returns only the storage_s3 check', async () => {
  const spy = spyRunCrossTenant();
  const s3Spy = spyRunCrossTenant();
  const res = await call(loadHandler('cross-tenant-s3', spy, s3Spy), '/api/cross-tenant-s3');
  assert.equal(res.status, 200);
  assert.equal(spy.calls.length, 0);
  assert.equal(s3Spy.calls.length, 1);
  assert.deepEqual(res.body.data, { cross_tenant_s3: { skipped: 'spy' } });
  assert.deepEqual(res.body.checks.results.map((r) => [r.id, r.group, r.status]), [['cross_tenant_storage_s3', 'cross_tenant', 'skip']]);
  assert.equal(res.body.checks.summary.skipped, 1);
});

test('/api/cross-tenant-s3 keeps only known regions and well-formed refs', async () => {
  const s3Spy = spyRunCrossTenant();
  const realHost = process.env.POSTGRES_POOLER_HOST;
  process.env.POSTGRES_POOLER_HOST = 'aws-0-ap-southeast-1.pooler.supabase.com';
  try {
    const query = `${OTHER}:eu-west-2,qwertyuiopasdfghjklz:mars-east-1,Bad_Ref:us-east-1,abc:us-east-1:extra,def:`;
    await call(loadHandler('cross-tenant-s3', spyRunCrossTenant(), s3Spy), `/api/cross-tenant-s3?regions=${encodeURIComponent(query)}`);
  } finally {
    if (realHost === undefined) delete process.env.POSTGRES_POOLER_HOST;
    else process.env.POSTGRES_POOLER_HOST = realHost;
  }
  assert.deepEqual(s3Spy.calls[0].regions, { [OTHER]: 'eu-west-2' });
  assert.equal(s3Spy.calls[0].ownPoolerHost, 'aws-0-ap-southeast-1.pooler.supabase.com');
  const none = spyRunCrossTenant();
  await call(loadHandler('cross-tenant-s3', spyRunCrossTenant(), none), '/api/cross-tenant-s3');
  assert.deepEqual(none.calls[0].regions, {});
});

test('/api/cross-tenant passes pooler_hints to the probes', async () => {
  const spy = spyRunCrossTenant();
  const realFetch = globalThis.fetch;
  const realResourceId = process.env.MARKETPLACE_RESOURCE_ID;
  process.env.MARKETPLACE_RESOURCE_ID = 'store_test';
  globalThis.fetch = async () => new Response(JSON.stringify({ token: 'header.payload.signature', expiresIn: 3600 }), { status: 200 });
  try {
    const handler = loadHandler('cross-tenant', spy);
    await call(handler, `/api/cross-tenant?pooler_hints=${OTHER}:pooler.example.com`, {
      headers: { 'x-vercel-oidc-token': 'oidc.token.value' },
    });
  } finally {
    globalThis.fetch = realFetch;
    if (realResourceId === undefined) delete process.env.MARKETPLACE_RESOURCE_ID;
    else process.env.MARKETPLACE_RESOURCE_ID = realResourceId;
  }
  assert.equal(spy.calls.length, 1);
  assert.deepEqual(spy.calls[0].jit.poolerHints, { [OTHER]: 'pooler.example.com' });
});

test('the endpoints accept only GET', async () => {
  for (const name of ['diagnostics', 'cross-tenant', 'cross-tenant-s3']) {
    const res = await call(loadHandler(name, spyRunCrossTenant()), `/api/${name}`, { method: 'POST' });
    assert.equal(res.status, 405, name);
  }
});
