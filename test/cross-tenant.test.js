const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeGatewayVersion, parseTargets, runCrossTenant } = require('../cross-tenant');
const { REF, oidcData, check } = require('./helpers');

const OWN_URL = `https://${REF}.supabase.co`;
const OTHER = 'zyxwvutsrqponmlkjihg';
const OTHER_V1 = 'qwertyuiopasdfghjklz';
const TOKEN = 'header.payload.signature';
const SERVICES = ['rest', 'auth_admin', 'storage', 'realtime'];
const PATHS = {
  rest: '/rest/v1/',
  auth_admin: '/auth/v1/admin/users',
  storage: '/storage/v1/bucket',
  realtime: '/realtime/v1/api/broadcast',
};

const serviceOf = (url) => SERVICES.find((s) => new URL(url).pathname === PATHS[s]);
const refOf = (url) => new URL(url).hostname.split('.')[0];

// respond(ref, service) -> { status, version } | Error
function stubFetch(respond, health = () => ({ status: 200 })) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    const isHealth = new URL(url).pathname === '/auth/v1/health';
    const r = isHealth ? health(refOf(url)) : respond(refOf(url), serviceOf(url));
    if (r instanceof Error) throw r;
    const headers = r.version === undefined ? {} : { 'sb-gateway-version': r.version };
    return new Response(r.body ?? '{}', { status: r.status, headers });
  };
  return { fetchImpl, calls };
}

const control200 = (rejectStatus, versions = {}) => (ref, service) =>
  ref === REF ? { status: 200, version: '2' } : { status: rejectStatus(service), version: versions[ref] ?? '2.0' };

async function run(opts) {
  const { respond, health, ownKey = 'sb_publishable_own', token = TOKEN } = opts;
  const spec = 'spec' in opts ? opts.spec : `${OTHER}=sb_publishable_other`;
  const { fetchImpl, calls } = stubFetch(respond, health);
  const ct = await runCrossTenant({ spec, ownUrl: OWN_URL, ownKey, token, fetchImpl });
  return { ct, calls, data: oidcData({ cross_tenant: ct }) };
}

const STORAGE_REJECT = { rest: 401, auth_admin: 403, storage: 400, realtime: 401 };

test('normalizes sb-gateway-version', () => {
  assert.equal(normalizeGatewayVersion('1'), 'v1');
  assert.equal(normalizeGatewayVersion('1.0'), 'v1');
  assert.equal(normalizeGatewayVersion('2'), 'v2');
  assert.equal(normalizeGatewayVersion('2.0'), 'v2');
  assert.equal(normalizeGatewayVersion('v2'), 'v2');
  assert.equal(normalizeGatewayVersion(null), 'unknown');
  assert.equal(normalizeGatewayVersion('beta'), 'unknown');
});

test('parses refs and URLs, and rejects same-tenant and malformed entries', () => {
  const { own, targets, errors } = parseTargets(
    ` ${OTHER}=k1, https://${OTHER_V1}.supabase.co/rest/v1=k2, ${REF}=k3, http://x.supabase.co=k4, nokey, bad_ref!=k5 ,`,
    OWN_URL
  );
  assert.deepEqual(own, { ref: REF, url: OWN_URL });
  assert.deepEqual(targets, [
    { ref: OTHER, url: `https://${OTHER}.supabase.co`, key: 'k1' },
    { ref: OTHER_V1, url: `https://${OTHER_V1}.supabase.co`, key: 'k2' },
  ]);
  assert.deepEqual(errors.map((e) => e.target), [REF, 'http://x.supabase.co', 'nokey', 'bad_ref!']);
  assert.match(errors[0].error, /Same tenant/);
});

test('derives the target domain from this deployment (staging)', () => {
  const { targets } = parseTargets(`${OTHER}=k`, `https://${REF}.supabase.green`);
  assert.equal(targets[0].url, `https://${OTHER}.supabase.green`);
});

test('empty CROSS_TENANT_TARGETS skips every cross-tenant check with a hint', async () => {
  for (const spec of [undefined, '', '  ']) {
    const { ct, calls, data } = await run({ spec, respond: () => assert.fail('no fetch') });
    assert.match(ct.skipped, /CROSS_TENANT_TARGETS is not set/);
    assert.equal(calls.length, 0);
    for (const id of ['cross_tenant_targets', ...SERVICES.map((s) => `cross_tenant_${s}`), 'cross_tenant_gateway_coverage']) {
      assert.equal((await check(id, { data })).status, 'skip', id);
    }
  }
});

test('no checks run without results (data has no cross_tenant)', async () => {
  assert.equal((await check('cross_tenant_rest')).status, 'skip');
});

test('same-ref target is a config error', async () => {
  const { data } = await run({ spec: `${REF}=k`, respond: control200(() => 401) });
  const r = await check('cross_tenant_targets', { data });
  assert.equal(r.status, 'fail');
  assert.match(r.detail, /Same tenant/);
  assert.equal((await check('cross_tenant_rest', { data })).status, 'skip');
});

test('sends the target key as apikey and the token as Bearer', async () => {
  const { calls } = await run({ respond: control200(() => 401) });
  const target = calls.filter((c) => refOf(c.url) === OTHER && serviceOf(c.url));
  assert.equal(target.length, 4);
  for (const c of target) {
    assert.equal(c.init.headers.apikey, 'sb_publishable_other');
    assert.equal(c.init.headers.Authorization, `Bearer ${TOKEN}`);
  }
  const health = calls.filter((c) => new URL(c.url).pathname === '/auth/v1/health');
  assert.deepEqual(health.map((c) => refOf(c.url)), [OTHER]);
  assert.equal(health[0].init.headers.apikey, 'sb_publishable_other');
  assert.equal(health[0].init.headers.Authorization, undefined);
  const rt = target.find((c) => serviceOf(c.url) === 'realtime');
  assert.equal(rt.init.method, 'POST');
  assert.deepEqual(JSON.parse(rt.init.body).messages[0].private, true);
  const own = calls.filter((c) => refOf(c.url) === REF);
  assert.ok(own.every((c) => c.init.headers.apikey === 'sb_publishable_own'));
});

test('rejection with a good control passes for every service', async () => {
  const { data } = await run({ respond: control200((s) => STORAGE_REJECT[s]) });
  for (const s of SERVICES) {
    const r = await check(`cross_tenant_${s}`, { data });
    assert.equal(r.status, 'pass', s);
    assert.deepEqual(
      { target: r.actual[0].target, gateway_version: r.actual[0].gateway_version, control_status: r.actual[0].control_status },
      { target: OTHER, gateway_version: 'v2', control_status: 200 }
    );
  }
});

for (const service of SERVICES) {
  test(`${service}: target accepting the token is a regression`, async () => {
    const status = service === 'realtime' ? 202 : 200;
    const { data } = await run({ respond: control200((s) => (s === service ? status : 401)) });
    const r = await check(`cross_tenant_${service}`, { data });
    assert.equal(r.status, 'fail');
    assert.match(r.detail, new RegExp(`^regression: .+ on ${OTHER} \\(gateway v2\\) accepted tenant ${REF}'s token`));
  });
}

test('target health failure makes a rejection inconclusive', async () => {
  for (const health of [() => ({ status: 401 }), () => ({ status: 404 }), () => new Error('ENOTFOUND')]) {
    const { data } = await run({ respond: control200((s) => STORAGE_REJECT[s]), health });
    for (const s of SERVICES) {
      const r = await check(`cross_tenant_${s}`, { data });
      assert.equal(r.status, 'warn', s);
      assert.match(r.detail, new RegExp(`${OTHER}: the target ref or key is not valid in this environment \\(GET /auth/v1/health returned `));
    }
  }
});

test('target health failure still reports an accepting target as a regression', async () => {
  const { data } = await run({ respond: control200(() => 200), health: () => ({ status: 401 }) });
  assert.equal((await check('cross_tenant_rest', { data })).status, 'fail');
});

test('control failure makes the result inconclusive', async () => {
  const respond = (ref) => (ref === REF ? { status: 401, version: '2' } : { status: 401, version: '2' });
  const { data } = await run({ respond });
  for (const s of SERVICES) {
    const r = await check(`cross_tenant_${s}`, { data });
    assert.equal(r.status, 'warn', s);
    assert.match(r.detail, /control on this tenant returned 401/);
  }
});

test('control failure still reports an accepting target as a regression', async () => {
  const respond = (ref) => (ref === REF ? { status: 401 } : { status: 200, version: '1' });
  const { data } = await run({ respond });
  assert.equal((await check('cross_tenant_rest', { data })).status, 'fail');
});

test('5xx and network errors are inconclusive, not pass', async () => {
  const fivexx = await run({ respond: control200(() => 503) });
  assert.equal((await check('cross_tenant_storage', { data: fivexx.data })).status, 'warn');
  const net = await run({ respond: (ref) => (ref === REF ? { status: 200 } : new Error('connect ECONNREFUSED')) });
  const r = await check('cross_tenant_realtime', { data: net.data });
  assert.equal(r.status, 'warn');
  assert.match(r.detail, /network error/);
});

test('unexpected 4xx is inconclusive for REST and Auth admin but a rejection for Storage', async () => {
  const { data } = await run({ respond: control200(() => 404) });
  assert.equal((await check('cross_tenant_rest', { data })).status, 'warn');
  assert.equal((await check('cross_tenant_auth_admin', { data })).status, 'warn');
  assert.equal((await check('cross_tenant_storage', { data })).status, 'pass');
});

test('gateway coverage passes with v1 and v2 targets and warns otherwise', async () => {
  const both = await run({
    spec: `${OTHER}=a,${OTHER_V1}=b`,
    respond: control200(() => 401, { [OTHER_V1]: '1.0' }),
  });
  const r = await check('cross_tenant_gateway_coverage', { data: both.data });
  assert.equal(r.status, 'pass');
  assert.deepEqual(r.actual.seen, ['v1', 'v2']);

  const onlyV2 = await run({ respond: control200(() => 401) });
  const w = await check('cross_tenant_gateway_coverage', { data: onlyV2.data });
  assert.equal(w.status, 'warn');
  assert.match(w.detail, /gateway v1/);

  const none = await run({ respond: (ref) => (ref === REF ? { status: 200 } : { status: 401 }) });
  assert.deepEqual((await check('cross_tenant_gateway_coverage', { data: none.data })).actual.seen, ['unknown']);
});

test('never returns the token or a 2xx body', async () => {
  const respond = (ref, service) =>
    ref === REF
      ? { status: 200, body: 'own-secret-data' }
      : service === 'rest'
        ? { status: 200, body: 'other-tenant-data' }
        : { status: 401, body: `invalid token ${TOKEN}` };
  const { ct, data } = await run({ respond });
  const json = JSON.stringify(ct);
  assert.ok(!json.includes(TOKEN));
  assert.ok(!json.includes('tenant-data') && !json.includes('own-secret-data'));
  const { results } = await require('../checks').runChecks(data, {}, { env: {}, now: () => 0, fetchImpl: () => assert.fail() });
  assert.ok(!JSON.stringify(results).includes(TOKEN));
});
