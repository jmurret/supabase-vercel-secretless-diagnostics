const test = require('node:test');
const assert = require('node:assert/strict');
const { runCrossTenant } = require('../cross-tenant');
const { REF, oidcData, check, fakeRealtime } = require('./helpers');

const OWN_URL = `https://${REF}.supabase.co`;
const OTHER = 'zyxwvutsrqponmlkjihg';
const TOKEN = 'header.payload.signature';
const JIT_TOKEN = 'jit-header.jit-payload.jit-signature';
const OWN_HOST = 'aws-0-us-east-1.pooler.supabase.com';
const IDS = ['cross_tenant_mgmt_jit', 'cross_tenant_pooler_login'];

const AUTH_FAILED = { error: 'password authentication failed for user "postgres"', code: '28P01' };
const CONTROL_OK = { management_api: { status: 200, role: 'postgres' }, postgres_login: { current_user: 'postgres' } };

const stubFetch = (healthStatus) => async (url) => {
  const u = new URL(url);
  if (u.pathname === '/auth/v1/health') return new Response('{}', { status: healthStatus });
  return new Response('{}', { status: u.hostname.startsWith(REF) ? 200 : 401 });
};

// mgmt(ref) -> result of requestJitAccess, pooler(ref, host) -> result of a pooler login
function run({ mgmt = () => ({ status: 403, error: 'forbidden' }), pooler = () => AUTH_FAILED, jit, control = CONTROL_OK, hints, healthStatus = 200 } = {}) {
  const fetchImpl = stubFetch(healthStatus);
  const calls = { mgmt: [], pooler: [] };
  const jitArg = jit ?? {
    token: JIT_TOKEN,
    poolerHost: OWN_HOST,
    poolerHints: hints,
    poolerCache: new Map(),
    requestJit: async (ref) => {
      calls.mgmt.push(ref);
      return mgmt(ref);
    },
    loginPooler: async (ref, host, timeoutMs) => {
      calls.pooler.push({ ref, host, timeoutMs });
      return pooler(ref, host);
    },
  };
  return runCrossTenant({
    spec: `${OTHER}=sb_publishable_other`,
    ownUrl: OWN_URL,
    ownKey: 'sb_publishable_own',
    token: TOKEN,
    jit: jitArg,
    fetchImpl,
    createClientImpl: fakeRealtime().createClientImpl,
  }).then((ct) => ({ ct, calls, data: oidcData({ cross_tenant: ct, jit: control }) }));
}

test('rejection with good controls passes both checks', async () => {
  const { data, calls } = await run();
  assert.deepEqual(calls.mgmt, [OTHER]);
  assert.ok(calls.pooler.every((c) => c.ref === OTHER));
  const m = await check('cross_tenant_mgmt_jit', { data });
  assert.equal(m.status, 'pass');
  assert.deepEqual([m.actual[0].target, m.actual[0].status, m.actual[0].control_status], [OTHER, 403, 200]);
  const p = await check('cross_tenant_pooler_login', { data });
  assert.equal(p.status, 'pass');
  assert.equal(p.actual[0].pooler_host, OWN_HOST);
  assert.match(p.detail, new RegExp(`${OTHER}: answered by ${OWN_HOST} \\(4 hosts tried, from search\\)`));
});

test('a target that fails the health check makes rejections inconclusive', async () => {
  const { data } = await run({ mgmt: () => ({ status: 404 }), healthStatus: 401 });
  for (const id of IDS) {
    const r = await check(id, { data });
    assert.equal(r.status, 'warn');
    assert.match(r.detail, /not valid in this environment/);
  }
});

test('401, 403 and 404 from the Management API are rejections', async () => {
  for (const status of [401, 403, 404]) {
    const { data } = await run({ mgmt: () => ({ status }) });
    assert.equal((await check('cross_tenant_mgmt_jit', { data })).status, 'pass', String(status));
  }
});

test('a JIT grant on another tenant is a regression', async () => {
  const { data } = await run({ mgmt: () => ({ status: 200, role: 'postgres' }) });
  const r = await check('cross_tenant_mgmt_jit', { data });
  assert.equal(r.status, 'fail');
  assert.match(r.detail, new RegExp(`^regression: Management API JIT grant on ${OTHER} accepted tenant ${REF}'s JIT token`));
});

test('a pooler login on another tenant is a regression', async () => {
  const { data } = await run({ pooler: () => ({ current_user: 'postgres' }) });
  const r = await check('cross_tenant_pooler_login', { data });
  assert.equal(r.status, 'fail');
  assert.match(r.detail, new RegExp(`^regression: pooler login on ${OTHER} accepted tenant ${REF}'s JIT token \\(answered by ${OWN_HOST}`));
  assert.equal(r.actual[0].current_user, 'postgres');
});

test('the pooler login uses the JIT startup option through the injected login, per target ref', async () => {
  const { calls } = await run();
  assert.equal(calls.pooler[0].ref, OTHER);
  assert.equal(calls.pooler[0].host, OWN_HOST);
  assert.ok(calls.pooler[0].timeoutMs <= 4000);
});

test('control failure makes the Management API result inconclusive', async () => {
  const { data } = await run({ control: { ...CONTROL_OK, management_api: { status: 403, error: 'Token role does not match requested role' } } });
  const r = await check('cross_tenant_mgmt_jit', { data });
  assert.equal(r.status, 'warn');
  assert.match(r.detail, /jit_management_api\) did not succeed.*\(403 Token role does not match requested role\)/);
});

test('control failure makes the pooler result inconclusive', async () => {
  const { data } = await run({ control: { ...CONTROL_OK, postgres_login: { error: 'no pg_hba.conf entry' } } });
  const r = await check('cross_tenant_pooler_login', { data });
  assert.equal(r.status, 'warn');
  assert.match(r.detail, /did not run as postgres, so a rejection by the target proves nothing \(no pg_hba.conf entry\)/);
});

test('a control failure still reports an accepting target as a regression', async () => {
  const { data } = await run({ mgmt: () => ({ status: 200 }), control: {} });
  assert.equal((await check('cross_tenant_mgmt_jit', { data })).status, 'fail');
});

test('network errors, 5xx and other pooler errors are inconclusive', async () => {
  const net = await run({ mgmt: () => ({ status: null, error: 'fetch failed' }), pooler: () => ({ error: 'connect ECONNREFUSED' }) });
  const m = await check('cross_tenant_mgmt_jit', { data: net.data });
  assert.equal(m.status, 'warn');
  assert.match(m.detail, /network error: fetch failed/);
  assert.equal((await check('cross_tenant_pooler_login', { data: net.data })).status, 'warn');
  const five = await run({ mgmt: () => ({ status: 502 }) });
  assert.equal((await check('cross_tenant_mgmt_jit', { data: five.data })).status, 'warn');
});

test('tenant not found on every pooler is inconclusive', async () => {
  const { data } = await run({ pooler: () => ({ error: 'Tenant or user not found', code: 'XX000' }) });
  const r = await check('cross_tenant_pooler_login', { data });
  assert.equal(r.status, 'warn');
  assert.match(r.detail, new RegExp(`${OTHER}: target not found on any regional pooler tried \\(34 hosts\\)`));
});

test('the pooler host that answered is searched for and reported', async () => {
  const host = 'aws-0-eu-west-1.pooler.supabase.com';
  const { data, ct } = await run({ pooler: (ref, h) => (h === host ? AUTH_FAILED : { error: 'Tenant or user not found' }) });
  assert.equal(ct.targets[0].jit_pooler.pooler_host, host);
  assert.equal(ct.targets[0].jit_pooler.hosts_tried, 8);
  assert.match((await check('cross_tenant_pooler_login', { data })).detail, /answered by aws-0-eu-west-1\.pooler\.supabase\.com \(8 hosts tried, from search\)/);
});

test('a pooler hint is tried first and shown as the source', async () => {
  const host = 'aws-1-eu-west-2.pooler.supabase.com';
  const { data, calls } = await run({ hints: { [OTHER]: host }, pooler: (ref, h) => (h === host ? AUTH_FAILED : { error: 'Tenant or user not found' }) });
  assert.equal(calls.pooler.length, 1);
  assert.match((await check('cross_tenant_pooler_login', { data })).detail, /\(1 host tried, from hint\)/);
});

test('both checks skip without a JIT token', async () => {
  const { data, calls } = await run({ jit: { skipped: 'JIT token mint failed: mint failed: 403' } });
  assert.equal(calls.mgmt.length + calls.pooler.length, 0);
  for (const id of IDS) {
    const r = await check(id, { data });
    assert.equal(r.status, 'skip', id);
    assert.equal(r.detail, 'JIT token mint failed: mint failed: 403');
  }
  const ct = await runCrossTenant({ spec: `${OTHER}=k`, ownUrl: OWN_URL, token: TOKEN, fetchImpl: stubFetch(200), createClientImpl: fakeRealtime().createClientImpl });
  for (const id of IDS) {
    assert.equal((await check(id, { data: oidcData({ cross_tenant: ct, jit: CONTROL_OK }) })).detail, 'No JIT resource token was minted.', id);
  }
});

test('the pooler check skips without POSTGRES_POOLER_HOST and the Management API check still runs', async () => {
  const jit = {
    token: JIT_TOKEN,
    poolerHost: undefined,
    poolerCache: new Map(),
    requestJit: async () => ({ status: 403 }),
    loginPooler: async () => assert.fail('no login'),
  };
  const { data } = await run({ jit });
  const p = await check('cross_tenant_pooler_login', { data });
  assert.equal(p.status, 'skip');
  assert.match(p.detail, /POSTGRES_POOLER_HOST is not set/);
  assert.equal((await check('cross_tenant_mgmt_jit', { data })).status, 'pass');
});

test('without targets or a default token, the JIT checks skip too', async () => {
  const ct = await runCrossTenant({ spec: '', ownUrl: OWN_URL, token: TOKEN, jit: { token: JIT_TOKEN } });
  const data = oidcData({ cross_tenant: ct, jit: CONTROL_OK });
  for (const id of IDS) assert.equal((await check(id, { data })).status, 'skip', id);
});

test('the JIT token is redacted from errors and never returned', async () => {
  const { ct, data } = await run({
    mgmt: () => ({ status: 401, error: `bad token ${JIT_TOKEN}`, endpoint: `x/${JIT_TOKEN}`, role: 'postgres' }),
    pooler: () => ({ error: `password authentication failed for ${JIT_TOKEN}`, code: '28P01', endpoint: `h:6543/${JIT_TOKEN}` }),
  });
  const json = JSON.stringify(ct);
  assert.ok(!json.includes(JIT_TOKEN));
  assert.ok(json.includes('bad token <redacted>'));
  assert.equal(ct.targets[0].jit_pooler.error, 'password authentication failed for <redacted>');
  const { runChecks } = require('../checks');
  const { results } = await runChecks(data, {}, { env: {}, now: () => 0, fetchImpl: () => assert.fail() });
  assert.ok(!JSON.stringify(results).includes(JIT_TOKEN));
});

test('the JIT checks are not part of gateway coverage', async () => {
  const { data } = await run();
  const r = await check('cross_tenant_gateway_coverage', { data });
  assert.deepEqual(Object.keys(r.actual[0]), ['target', 'v1', 'v2', 'missing']);
});
