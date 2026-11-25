const test = require('node:test');
const assert = require('node:assert/strict');
const { SERVICES: PROBES, normalizeGatewayVersion, parseTargets, runCrossTenant, evaluateService } = require('../cross-tenant');
const { REF, oidcData, check, fakeRealtime } = require('./helpers');

const OWN_URL = `https://${REF}.supabase.co`;
const OTHER = 'zyxwvutsrqponmlkjihg';
const OTHER_V1 = 'qwertyuiopasdfghjklz';
const TOKEN = 'header.payload.signature';
const SERVICES = ['rest', 'auth_admin', 'storage', 'realtime'];
const PATHS = {
  rest: '/rest/v1/countries',
  auth_admin: '/auth/v1/admin/users',
  storage: '/storage/v1/bucket',
  realtime: '/realtime/v1/api/broadcast',
};

const serviceOf = (url) => SERVICES.find((s) => new URL(url).pathname === PATHS[s]);
const refOf = (url) => new URL(url).hostname.split('.')[0];

const variantOf = (init) => (init?.headers?.['sb-forward-traffic'] ? 'v2' : 'v1');

// respond(ref, service, variant) -> { status, version?, body? } | Error. Without a version key, the request is
// answered by the gateway of its variant (v1 for v1, v2 for v2). version: undefined sends no header.
function stubFetch(respond, health = () => ({ status: 200 })) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    const isHealth = new URL(url).pathname === '/auth/v1/health';
    const variant = variantOf(init);
    const r = isHealth ? health(refOf(url)) : respond(refOf(url), serviceOf(url), variant);
    if (r instanceof Error) throw r;
    const version = 'version' in r ? r.version : variant === 'v2' ? '2.0' : '1';
    const headers = version === undefined ? {} : { 'sb-gateway-version': version };
    return new Response(r.body ?? '{}', { status: r.status, headers });
  };
  return { fetchImpl, calls };
}

const control200 = (rejectStatus) => (ref, service, variant) =>
  ref === REF ? { status: 200 } : { status: rejectStatus(service, variant) };

async function run(opts) {
  const { respond, health, ownKey = 'sb_publishable_own', token = TOKEN } = opts;
  const spec = 'spec' in opts ? opts.spec : `${OTHER}=sb_publishable_other`;
  const { fetchImpl, calls } = stubFetch(respond, health);
  const ct = await runCrossTenant({ spec, ownUrl: OWN_URL, ownKey, token, fetchImpl, createClientImpl: fakeRealtime().createClientImpl });
  return { ct, calls, data: oidcData({ cross_tenant: ct }) };
}

const evaluateRow = (ct, id) => evaluateService(ct, PROBES.find((s) => s.id === id)).rows[0];

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
  assert.equal(target.length, 8);
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
  const own = calls.filter((c) => refOf(c.url) === REF && serviceOf(c.url));
  assert.ok(own.every((c) => c.init.headers.apikey === 'sb_publishable_own'));
});

test('rejection with a good control passes for every service', async () => {
  const { data } = await run({ respond: control200((s) => STORAGE_REJECT[s]) });
  for (const s of SERVICES) {
    const r = await check(`cross_tenant_${s}`, { data });
    assert.equal(r.status, 'pass', s);
    const [row] = r.actual;
    assert.equal(row.target, OTHER);
    assert.equal(row.result, 'rejected');
    assert.deepEqual(
      Object.fromEntries(Object.entries(row.variants).map(([v, x]) => [v, [x.gateway_version, x.control_gateway_version, x.control_status, x.result]])),
      { v1: ['v1', 'v1', 200, 'rejected'], v2: ['v2', 'v2', 200, 'rejected'] }
    );
    assert.equal(r.detail, `${OTHER}: v1 rejected (${STORAGE_REJECT[s]}), v2 rejected (${STORAGE_REJECT[s]})`);
  }
});

for (const service of SERVICES) {
  test(`${service}: target accepting the token is a regression`, async () => {
    const status = service === 'realtime' ? 202 : 200;
    const { data } = await run({ respond: control200((s) => (s === service ? status : 401)) });
    const r = await check(`cross_tenant_${service}`, { data });
    assert.equal(r.status, 'fail');
    assert.match(r.detail, new RegExp(`^regression: .+ on ${OTHER} accepted tenant ${REF}'s token \\(v1 accepted \\(${status}\\), v2 accepted \\(${status}\\)\\)$`));
  });
}

test('target health failure makes a rejection inconclusive', async () => {
  for (const health of [() => ({ status: 401 }), () => ({ status: 404 }), () => new Error('ENOTFOUND')]) {
    const { data } = await run({ respond: control200((s) => STORAGE_REJECT[s]), health });
    for (const s of SERVICES) {
      const r = await check(`cross_tenant_${s}`, { data });
      assert.equal(r.status, 'warn', s);
      assert.match(r.detail, new RegExp(`${OTHER}: v1 inconclusive \\(the target ref or key is not valid in this environment \\(GET /auth/v1/health returned .*, v2 inconclusive \\(the target ref`));
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
    assert.match(r.detail, /control on this tenant returned 401; this tenant does not accept the token for this service either, so a rejection by the target proves nothing/);
  }
});

test('control and target errors keep a safe summary and no secrets', async () => {
  const KEY = 'sb_publishable_own';
  const body = JSON.stringify({
    code: 'PGRST301',
    message: `JWT rejected ${TOKEN} with ${KEY}`,
    details: 'not kept',
    hint: 'not kept',
    extra: { nested: TOKEN },
  });
  const respond = (ref) => (ref === REF ? { status: 401, body, version: '2' } : { status: 401, body: '{"error_code":"no_authorization","msg":"nope"}', version: '2' });
  const { ct, data } = await run({ respond });
  const row = evaluateRow(ct, 'rest').variants.v2;
  assert.equal(row.control_error, 'PGRST301: JWT rejected <redacted> with <redacted>');
  assert.equal(row.error, 'no_authorization: nope');
  const json = JSON.stringify(ct);
  assert.ok(!json.includes(TOKEN) && !json.includes(KEY) && !json.includes('not kept') && !json.includes('nested'));
  const r = await check('cross_tenant_rest', { data });
  assert.equal(r.status, 'warn');
  assert.match(r.detail, /returned 401;.*\(PGRST301: JWT rejected <redacted> with <redacted>\)/);
  assert.ok(!JSON.stringify(r).includes(TOKEN));
});

test('error summaries are cut to 200 characters per field', async () => {
  const respond = (ref) => (ref === REF ? { status: 403, body: JSON.stringify({ msg: 'x'.repeat(500) }) } : { status: 401 });
  const { ct } = await run({ respond });
  assert.equal(evaluateRow(ct, 'auth_admin').variants.v1.control_error.length, 200);
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

test('REST 404 PGRST205 from a target means the token was accepted', async () => {
  const { data } = await run({
    respond: (ref, service) => {
      if (ref === REF) return { status: 200, version: '2' };
      if (service === 'rest') return { status: 404, version: '1', body: JSON.stringify({ code: 'PGRST205', message: 'missing table' }) };
      return { status: 401, version: '1' };
    },
  });
  assert.equal((await check('cross_tenant_rest', { data })).status, 'fail');
});

test('gateway coverage passes when every target answered v1 requests with v1 and v2 requests with v2', async () => {
  const both = await run({ spec: `${OTHER}=a,${OTHER_V1}=b`, respond: control200(() => 401) });
  const r = await check('cross_tenant_gateway_coverage', { data: both.data });
  assert.equal(r.status, 'pass');
  assert.deepEqual(r.actual, [
    { target: OTHER, v1: ['v1'], v2: ['v2'], missing: [] },
    { target: OTHER_V1, v1: ['v1'], v2: ['v2'], missing: [] },
  ]);
});

test('gateway coverage warns and names each target whose requests reached the wrong gateway', async () => {
  const notForwarded = await run({
    spec: `${OTHER}=a,${OTHER_V1}=b`,
    respond: (ref) => (ref === REF ? { status: 200 } : { status: 401, ...(ref === OTHER_V1 && { version: '1' }) }),
  });
  const w = await check('cross_tenant_gateway_coverage', { data: notForwarded.data });
  assert.equal(w.status, 'warn');
  assert.equal(w.detail, `${OTHER_V1}: v2 requests were answered by v1`);

  const none = await run({ respond: (ref) => (ref === REF ? { status: 200 } : { status: 401, version: undefined }) });
  const n = await check('cross_tenant_gateway_coverage', { data: none.data });
  assert.equal(n.status, 'warn');
  assert.equal(n.detail, `${OTHER}: v1 requests were answered by unknown, v2 requests were answered by unknown`);
  assert.doesNotMatch(n.detail, /does not serve any projects/);
});

test('the forwarding header is sent only on v2 requests, to the target and to the control', async () => {
  const { calls } = await run({ respond: control200(() => 401) });
  const probes = calls.filter((c) => serviceOf(c.url));
  for (const ref of [REF, OTHER]) {
    const mine = probes.filter((c) => refOf(c.url) === ref);
    assert.equal(mine.length, 8, ref);
    assert.deepEqual(mine.filter((c) => 'sb-forward-traffic' in c.init.headers).map((c) => c.init.headers['sb-forward-traffic']), ['true', 'true', 'true', 'true']);
  }
  const health = calls.filter((c) => new URL(c.url).pathname === '/auth/v1/health');
  assert.equal(health.length, 1);
  assert.ok(!('sb-forward-traffic' in health[0].init.headers));
});

// v1 answer, v2 answer -> check status. The check status is the worst variant: fail > warn > pass.
const ROLLUP = [
  ['pass + pass = pass', { status: 401 }, { status: 401 }, 'pass'],
  ['pass + warn = warn', { status: 401 }, { status: 503 }, 'warn'],
  ['pass + fail = fail', { status: 401 }, { status: 200 }, 'fail'],
  ['warn + fail = fail', { status: 503 }, { status: 200 }, 'fail'],
];

for (const [name, v1, v2, status] of ROLLUP) {
  test(`variant rollup: ${name}`, async () => {
    const { ct, data } = await run({ respond: (ref, service, variant) => (ref === REF ? { status: 200 } : variant === 'v2' ? v2 : v1) });
    const results = { pass: 'rejected', warn: 'inconclusive', fail: 'accepted' };
    assert.equal(evaluateRow(ct, 'rest').result, results[status]);
    assert.equal((await check('cross_tenant_rest', { data })).status, status);
  });
}

test('a v2 request that api-gateway v1 answered is inconclusive, also with no gateway header', async () => {
  for (const version of ['1', undefined]) {
    const { ct, data } = await run({ respond: (ref) => (ref === REF ? { status: 200, version: '2' } : { status: 401, version }) });
    const row = evaluateRow(ct, 'rest');
    assert.equal(row.variants.v1.result, 'rejected');
    assert.deepEqual([row.variants.v2.result, row.variants.v2.reason], ['inconclusive', 'request was not forwarded to api-gateway v2']);
    const r = await check('cross_tenant_rest', { data });
    assert.equal(r.status, 'warn');
    assert.equal(r.detail, `Inconclusive: ${OTHER}: v1 rejected (401), v2 inconclusive (request was not forwarded to api-gateway v2)`);
  }
});

test('a v2 request that the target accepted is a regression even when api-gateway v1 answered it', async () => {
  const { data } = await run({ respond: (ref, service, variant) => (ref === REF ? { status: 200 } : { status: variant === 'v2' ? 200 : 401, version: '1' }) });
  const r = await check('cross_tenant_rest', { data });
  assert.equal(r.status, 'fail');
  assert.match(r.detail, /v1 rejected \(401\), v2 accepted \(200\)/);
});

test('each variant uses the control of the same variant', async () => {
  const failingV2 = await run({ respond: (ref, service, variant) => (ref === REF ? { status: variant === 'v2' ? 401 : 200 } : { status: 401 }) });
  const row = evaluateRow(failingV2.ct, 'rest');
  assert.deepEqual([row.variants.v1.control_status, row.variants.v1.result], [200, 'rejected']);
  assert.deepEqual([row.variants.v2.control_status, row.variants.v2.result], [401, 'inconclusive']);
  assert.match(row.variants.v2.reason, /^control on this tenant returned 401/);

  const controlNotForwarded = await run({ respond: (ref, service, variant) => (ref === REF ? { status: 200, version: '1' } : { status: 401 }) });
  const v2 = evaluateRow(controlNotForwarded.ct, 'rest').variants.v2;
  assert.deepEqual([v2.control_gateway_version, v2.result, v2.reason], ['v1', 'inconclusive', 'control on this tenant: request was not forwarded to api-gateway v2']);
  assert.equal(evaluateRow(controlNotForwarded.ct, 'rest').variants.v1.result, 'rejected');
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

const GATEWAY_BODY = JSON.stringify({ code: 'unauthorized', message: 'Vercel OIDC token not issued for this project' });
const GATEWAY_REASON = 'api-gateway rejected the token: Vercel OIDC token not issued for this project';

test('gateway rejection passes when the control fails', async () => {
  const respond = (ref, service) =>
    ref === REF
      ? { status: 403, body: JSON.stringify({ code: 403, error_code: 'bad_jwt', msg: 'rejected' }) }
      : { status: 401, body: service === 'auth_admin' ? GATEWAY_BODY : '{}' };
  const { ct, data } = await run({ respond });
  const row = evaluateRow(ct, 'auth_admin');
  assert.equal(row.result, 'rejected');
  assert.equal(row.variants.v1.reason, GATEWAY_REASON);
  const r = await check('cross_tenant_auth_admin', { data });
  assert.equal(r.status, 'pass');
  assert.equal(r.actual[0].variants.v2.reason, GATEWAY_REASON);
  assert.equal((await check('cross_tenant_rest', { data })).status, 'warn');
});

test('gateway rejection applies to every service and to a failing target health check', async () => {
  const respond = (ref) => (ref === REF ? { status: 403 } : { status: 401, body: GATEWAY_BODY });
  const { ct, data } = await run({ respond, health: () => ({ status: 404 }) });
  for (const service of SERVICES) {
    for (const v of ['v1', 'v2']) assert.equal(evaluateRow(ct, service).variants[v].reason, GATEWAY_REASON, `${service} ${v}`);
    assert.equal((await check(`cross_tenant_${service}`, { data })).status, 'pass', service);
  }
});

test('a plain 401 without the gateway message is still inconclusive when the control fails', async () => {
  const respond = (ref) => (ref === REF ? { status: 403 } : { status: 401, body: '{"msg":"other"}' });
  const { ct, data } = await run({ respond });
  const row = evaluateRow(ct, 'auth_admin');
  assert.equal(row.result, 'inconclusive');
  assert.match(row.variants.v1.reason, /control on this tenant returned 403/);
  assert.equal((await check('cross_tenant_auth_admin', { data })).status, 'warn');
});

test('the gateway message on a status other than 401 does not count as a gateway rejection', async () => {
  const respond = (ref) => (ref === REF ? { status: 403 } : { status: 403, body: GATEWAY_BODY });
  const { ct } = await run({ respond });
  assert.equal(evaluateRow(ct, 'rest').result, 'inconclusive');
});
