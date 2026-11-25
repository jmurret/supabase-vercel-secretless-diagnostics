const test = require('node:test');
const assert = require('node:assert/strict');
const { runCrossTenant, runCrossTenantS3, evaluateService, SERVICES } = require('../cross-tenant');
const { signRequest } = require('../sigv4');
const { REF, oidcData, check, fakeRealtime } = require('./helpers');

const OWN_URL = `https://${REF}.supabase.co`;
const OTHER = 'zyxwvutsrqponmlkjihg';
const TOKEN = 'header.payload.signature';
const OWN_KEY = 'sb_publishable_own';
const OTHER_KEY = 'sb_publishable_other';
const NOW = new Date('2026-11-25T10:00:00Z');
const S3_ID = 'cross_tenant_storage_s3';
const WS_ID = 'cross_tenant_realtime_ws';

const refOf = (url) => new URL(url).hostname.split('.')[0];
const xmlError = (code, message) => `<?xml version="1.0" encoding="UTF-8"?><Error><Code>${code}</Code><Message>${message}</Message></Error>`;
const DENIED = { status: 403, body: xmlError('AccessDenied', 'Access denied') };

// s3(ref, variant) -> { status, body? } | Error. Every other HTTP probe answers 401, health answers 200 unless told
// otherwise. Each request is answered by the gateway of its variant.
function stubFetch({ s3 = (ref) => (ref === REF ? { status: 200 } : DENIED), health = () => ({ status: 200 }) } = {}) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    const { pathname } = new URL(url);
    const variant = init?.headers?.['sb-forward-traffic'] ? 'v2' : 'v1';
    const r = pathname === '/auth/v1/health' ? health(refOf(url)) : pathname === '/storage/v1/s3/' ? s3(refOf(url), variant) : { status: 401 };
    if (r instanceof Error) throw r;
    return new Response(r.body ?? '{}', { status: r.status, headers: { 'sb-gateway-version': variant === 'v2' ? '2' : '1' } });
  };
  return { fetchImpl, calls };
}

const poolerHost = (region) => `aws-0-${region}.pooler.supabase.com`;

// ct is { cross_tenant, cross_tenant_s3 }: the websocket probe runs in runCrossTenant, S3 in runCrossTenantS3.
async function run({
  s3,
  health,
  ws,
  spec = `${OTHER}=${OTHER_KEY}`,
  ownKey = OWN_KEY,
  token = TOKEN,
  regions = { [OTHER]: 'us-east-1' },
  ownPoolerHost = poolerHost('us-east-1'),
  ...rest
} = {}) {
  const { fetchImpl, calls } = stubFetch({ s3, health });
  const realtime = fakeRealtime(ws);
  const common = { spec, ownUrl: OWN_URL, ownKey, token, fetchImpl, ...rest };
  const ct = {
    cross_tenant: await runCrossTenant({ ...common, createClientImpl: realtime.createClientImpl, realtimeTimeoutMs: 30, ...rest }),
    cross_tenant_s3: await runCrossTenantS3({ ...common, regions, ownPoolerHost, now: () => NOW }),
  };
  return { ct, calls, clients: realtime.clients, data: oidcData(ct) };
}

const rowOf = (ct, id) => evaluateService(id === 'storage_s3' ? ct.cross_tenant_s3 : ct.cross_tenant, SERVICES.find((s) => s.id === id)).rows[0];
const s3Calls = (calls, ref) => calls.filter((c) => new URL(c.url).pathname === '/storage/v1/s3/' && refOf(c.url) === ref);

test('S3 sends a signed ListBuckets with the target ref, the target key and the token as session token', async () => {
  const { calls } = await run();
  const [call] = s3Calls(calls, OTHER);
  assert.equal(call.url, `https://${OTHER}.supabase.co/storage/v1/s3/`);
  assert.equal(call.init.method, 'GET');
  const expected = signRequest({
    url: call.url,
    region: 'us-east-1',
    service: 's3',
    accessKeyId: OTHER,
    secretAccessKey: OTHER_KEY,
    sessionToken: TOKEN,
    headers: { 'x-amz-content-sha256': call.init.headers['x-amz-content-sha256'] },
    now: NOW,
  });
  assert.equal(call.init.headers.authorization, expected.headers.authorization);
  assert.equal(call.init.headers['x-amz-security-token'], TOKEN);
  assert.match(call.init.headers.authorization, new RegExp(`^AWS4-HMAC-SHA256 Credential=${OTHER}/20261125/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, `));
  assert.equal(call.init.headers.apikey, undefined);
  assert.ok(!JSON.stringify(call.init.headers.authorization).includes(TOKEN));
  const [own] = s3Calls(calls, REF);
  assert.match(own.init.headers.authorization, new RegExp(`Credential=${REF}/`));
});

test('S3 v2 request signs the forwarding header with the other headers', async () => {
  const { calls } = await run();
  const target = s3Calls(calls, OTHER);
  assert.equal(target.length, 2);
  const [v1, v2] = target;
  assert.equal(v1.init.headers['sb-forward-traffic'], undefined);
  assert.equal(v2.init.headers['sb-forward-traffic'], 'true');
  const expected = signRequest({
    url: v2.url,
    region: 'us-east-1',
    service: 's3',
    accessKeyId: OTHER,
    secretAccessKey: OTHER_KEY,
    sessionToken: TOKEN,
    headers: { 'x-amz-content-sha256': v2.init.headers['x-amz-content-sha256'], 'sb-forward-traffic': 'true' },
    now: NOW,
  });
  assert.equal(v2.init.headers.authorization, expected.headers.authorization);
  assert.match(v2.init.headers.authorization, /SignedHeaders=host;sb-forward-traffic;x-amz-content-sha256;x-amz-date;x-amz-security-token, /);
  assert.equal(s3Calls(calls, REF).filter((c) => c.init.headers['sb-forward-traffic'] === 'true').length, 1);
});

test('S3 region: the target region from regions, the control region from POSTGRES_POOLER_HOST', async () => {
  const { ct, calls } = await run({ regions: { [OTHER]: 'eu-west-2' }, ownPoolerHost: poolerHost('ap-southeast-1') });
  const row = rowOf(ct, 'storage_s3');
  assert.deepEqual([row.region, row.region_source, row.control_region, row.control_region_source], ['eu-west-2', 'regions', 'ap-southeast-1', 'own_pooler_host']);
  assert.equal(ct.cross_tenant_s3.targets[0].region, 'eu-west-2');
  assert.equal(ct.cross_tenant_s3.own.region, 'ap-southeast-1');
  assert.ok(s3Calls(calls, OTHER).every((c) => /Credential=[^,]*\/eu-west-2\/s3\/aws4_request/.test(c.init.headers.authorization)));
  assert.ok(s3Calls(calls, REF).every((c) => /Credential=[^,]*\/ap-southeast-1\/s3\/aws4_request/.test(c.init.headers.authorization)));
});

test('S3: a target without a region is not probed and is inconclusive, never signed for us-east-1', async () => {
  const { ct, calls, data } = await run({ regions: {} });
  assert.equal(s3Calls(calls, OTHER).length, 0);
  // One health check from each of runCrossTenant and runCrossTenantS3.
  assert.equal(calls.filter((c) => refOf(c.url) === OTHER && new URL(c.url).pathname === '/auth/v1/health').length, 2);
  const row = rowOf(ct, 'storage_s3');
  assert.equal(row.result, 'inconclusive');
  assert.deepEqual([row.variants.v1.reason, row.variants.v2.reason], ['target region unknown', 'target region unknown']);
  assert.equal(ct.cross_tenant_s3.targets[0].region, null);
  const r = await check(S3_ID, { data });
  assert.equal(r.status, 'warn');
  assert.equal(r.detail, `Inconclusive: ${OTHER}: v1 inconclusive (target region unknown), v2 inconclusive (target region unknown)`);
});

test('S3: a region for a ref that is not a target is ignored', async () => {
  const { ct, calls } = await run({ regions: { [OTHER]: 'us-east-1', qwertyuiopasdfghjklz: 'eu-west-1' } });
  assert.deepEqual(ct.cross_tenant_s3.ignored_regions, ['qwertyuiopasdfghjklz']);
  assert.ok(calls.every((c) => refOf(c.url) !== 'qwertyuiopasdfghjklz'));
});

test('S3: without a region for this tenant the control is not sent and the result is inconclusive', async () => {
  const { ct, calls, data } = await run({ ownPoolerHost: 'pooler.example.com' });
  assert.equal(s3Calls(calls, REF).length, 0);
  assert.equal(rowOf(ct, 'storage_s3').variants.v1.control_error, 'the region of this tenant is unknown: POSTGRES_POOLER_HOST does not name one');
  const r = await check(S3_ID, { data });
  assert.equal(r.status, 'warn');
  assert.match(r.detail, /control on this tenant returned the region of this tenant is unknown/);
});

test('/api/cross-tenant does not run S3 and returns the target pooler region', async () => {
  const { ct } = await run({ regions: {} });
  assert.equal('storage_s3' in ct.cross_tenant.targets[0].probes, false);
  assert.equal('storage_s3' in ct.cross_tenant.own.control, false);
  const jit = await runCrossTenant({
    spec: `${OTHER}=${OTHER_KEY}`,
    ownUrl: OWN_URL,
    ownKey: OWN_KEY,
    token: TOKEN,
    fetchImpl: stubFetch().fetchImpl,
    createClientImpl: fakeRealtime().createClientImpl,
    jit: {
      token: 'jit.token.value',
      poolerHost: poolerHost('us-east-1'),
      poolerCache: new Map(),
      requestJit: async () => ({ status: 403 }),
      loginPooler: async (ref, host) => (host === poolerHost('eu-west-2') ? { error: 'password authentication failed', code: '28P01' } : { error: 'Tenant or user not found' }),
    },
  });
  assert.deepEqual([jit.targets[0].jit_pooler.pooler_host, jit.targets[0].jit_pooler.region], [poolerHost('eu-west-2'), 'eu-west-2']);
});

test('S3: AccessDenied from the target with a good control passes and shows the S3 code', async () => {
  const { ct, data } = await run();
  const r = await check(S3_ID, { data });
  assert.equal(r.status, 'pass');
  for (const v of ['v1', 'v2']) {
    const x = r.actual[0].variants[v];
    assert.deepEqual(
      { status: x.status, error: x.error, control_status: x.control_status, gateway_version: x.gateway_version },
      { status: 403, error: 'AccessDenied: Access denied', control_status: 200, gateway_version: v }
    );
  }
  assert.equal(r.actual[0].target, OTHER);
  assert.equal(r.detail, `${OTHER}: v1 rejected (403), v2 rejected (403)`);
  assert.equal(rowOf(ct, 'storage_s3').result, 'rejected');
});

test('S3: credential errors with 401 or 403 are inconclusive and keep their S3 code', async () => {
  for (const [status, code] of [[401, 'InvalidAccessKeyId'], [403, 'SignatureDoesNotMatch']]) {
    const { data } = await run({ s3: (ref) => (ref === REF ? { status: 200 } : { status, body: xmlError(code, 'nope') }) });
    const r = await check(S3_ID, { data });
    assert.equal(r.status, 'warn', code);
    assert.match(r.detail, /before it checked the token/);
    assert.equal(r.actual[0].variants.v1.error, `${code}: nope`);
  }
});

test('S3: a 2xx from the target is a regression and no body is kept', async () => {
  const { ct, data } = await run({ s3: (ref) => ({ status: 200, body: '<ListAllMyBucketsResult>other-tenant-bucket</ListAllMyBucketsResult>' + ref }) });
  const r = await check(S3_ID, { data });
  assert.equal(r.status, 'fail');
  assert.match(r.detail, new RegExp(`^regression: Storage S3 on ${OTHER} accepted tenant ${REF}'s token \\(v1 accepted \\(200\\), v2 accepted \\(200\\)\\)`));
  assert.ok(!JSON.stringify(ct).includes('other-tenant-bucket'));
});

test('S3: control failure makes the result inconclusive and shows the control error', async () => {
  const { data } = await run({ s3: (ref) => (ref === REF ? { status: 403, body: xmlError('AccessDenied', 'own denied') } : DENIED) });
  const r = await check(S3_ID, { data });
  assert.equal(r.status, 'warn');
  assert.match(r.detail, /control on this tenant returned 403;.*\(AccessDenied: own denied\)/);
});

test('S3: a signature error on the control with a publishable key names the key type', async () => {
  const { ct, data } = await run({ s3: (ref) => (ref === REF ? { status: 403, body: xmlError('SignatureDoesNotMatch', 'bad signature') } : DENIED) });
  const row = rowOf(ct, 'storage_s3');
  assert.match(row.variants.v1.control_error, /^SignatureDoesNotMatch: bad signature The S3 secret is a publishable key \(sb_publishable_\.\.\.\)\. Storage S3 may accept only the legacy anon key/);
  assert.equal(row.result, 'inconclusive');
  assert.equal((await check(S3_ID, { data })).status, 'warn');
  const anon = await run({
    ownKey: 'eyJanon.key.value',
    s3: (ref) => (ref === REF ? { status: 403, body: xmlError('SignatureDoesNotMatch', 'bad signature') } : DENIED),
  });
  assert.equal(rowOf(anon.ct, 'storage_s3').variants.v2.control_error, 'SignatureDoesNotMatch: bad signature');
});

test('S3: target health failure makes a rejection inconclusive but not a regression', async () => {
  const { data } = await run({ health: () => ({ status: 401 }) });
  const r = await check(S3_ID, { data });
  assert.equal(r.status, 'warn');
  assert.match(r.detail, new RegExp(`${OTHER}: v1 inconclusive \\(the target ref or key is not valid in this environment \\(GET /auth/v1/health returned 401\\)\\)`));
  const bad = await run({ s3: () => ({ status: 200 }), health: () => ({ status: 404 }) });
  assert.equal((await check(S3_ID, { data: bad.data })).status, 'fail');
});

test('S3: the api-gateway 401 is a rejection even when the control and the health check fail', async () => {
  const gateway = JSON.stringify({ code: 'unauthorized', message: 'Vercel OIDC token not issued for this project' });
  const { ct, data } = await run({
    s3: (ref) => (ref === REF ? { status: 403, body: xmlError('AccessDenied', 'own denied') } : { status: 401, body: gateway }),
    health: () => ({ status: 404 }),
  });
  const row = rowOf(ct, 'storage_s3');
  assert.equal(row.result, 'rejected');
  assert.equal(row.variants.v2.reason, 'api-gateway rejected the token: Vercel OIDC token not issued for this project');
  assert.equal((await check(S3_ID, { data })).status, 'pass');
});

test('S3: 5xx and network errors are inconclusive', async () => {
  const fivexx = await run({ s3: (ref) => (ref === REF ? { status: 200 } : { status: 503 }) });
  assert.equal((await check(S3_ID, { data: fivexx.data })).status, 'warn');
  const net = await run({ s3: (ref) => (ref === REF ? { status: 200 } : new Error('connect ECONNREFUSED')) });
  const r = await check(S3_ID, { data: net.data });
  assert.equal(r.status, 'warn');
  assert.match(r.detail, /network error: connect ECONNREFUSED/);
});

test('S3: errors never keep the token or the key', async () => {
  const body = (ref) => xmlError('SignatureDoesNotMatch', `token ${TOKEN} key ${ref === REF ? OWN_KEY : OTHER_KEY}`);
  const { ct, data } = await run({ s3: (ref) => ({ status: 403, body: body(ref) }) });
  const json = JSON.stringify(ct);
  assert.ok(!json.includes(TOKEN) && !json.includes(OTHER_KEY) && !json.includes(OWN_KEY));
  assert.ok(json.includes('<redacted>'));
  assert.ok(!JSON.stringify(await check(S3_ID, { data })).includes(TOKEN));
  const thrown = await run({ s3: () => new Error(`failed with ${TOKEN}`) });
  assert.ok(!JSON.stringify(thrown.ct).includes(TOKEN));
});

test('S3 and the websocket probe are not part of gateway coverage', async () => {
  const { data } = await run({ s3: () => new Error('no answer') });
  const r = await check('cross_tenant_gateway_coverage', { data });
  assert.equal(r.status, 'pass');
  assert.deepEqual(r.actual[0], { target: OTHER, v1: ['v1'], v2: ['v2'], missing: [] });
});

test('the websocket probe sends one join per tenant, without a v2 variant', async () => {
  const { clients, ct } = await run();
  assert.equal(clients.length, 2);
  assert.equal(rowOf(ct, 'realtime_ws').variants, undefined);
});

test('websocket: join with the target key and the token; SUBSCRIBED is a regression', async () => {
  const { clients, data } = await run({ ws: () => ({ status: 'SUBSCRIBED' }) });
  const target = clients.find((c) => c.url.includes(OTHER));
  assert.equal(target.key, OTHER_KEY);
  assert.equal(target.token, TOKEN);
  assert.match(target.channels[0].name, /^vercel-oidc-xtenant-[0-9a-f]{12}$/);
  assert.deepEqual(target.channels[0].config, { config: { private: true } });
  const r = await check(WS_ID, { data });
  assert.equal(r.status, 'fail');
  assert.match(r.detail, new RegExp(`^regression: Realtime websocket on ${OTHER} .* accepted tenant ${REF}'s token`));
});

test('websocket: CHANNEL_ERROR on the target with a subscribed control passes and shows the error', async () => {
  const { clients, data } = await run();
  const r = await check(WS_ID, { data });
  assert.equal(r.status, 'pass');
  assert.deepEqual(
    { target: r.actual[0].target, status: r.actual[0].status, error: r.actual[0].error, control_status: r.actual[0].control_status },
    { target: OTHER, status: 'CHANNEL_ERROR', error: 'Unauthorized', control_status: 'SUBSCRIBED' }
  );
  assert.equal(clients.length, 2);
  assert.ok(clients.every((c) => c.removed === 1 && c.disconnected === 1));
});

test('websocket: a control that does not subscribe makes the result inconclusive with its error', async () => {
  const { data } = await run({ ws: () => ({ status: 'CHANNEL_ERROR', error: 'Unauthorized: no policy on realtime.messages' }) });
  const r = await check(WS_ID, { data });
  assert.equal(r.status, 'warn');
  assert.match(r.detail, /control on this tenant returned CHANNEL_ERROR;.*\(Unauthorized: no policy on realtime\.messages\)\. A private channel needs a policy on realtime\.messages/);
});

test('websocket: target health failure makes a rejection inconclusive but not a regression', async () => {
  const { data } = await run({ health: () => ({ status: 401 }) });
  const r = await check(WS_ID, { data });
  assert.equal(r.status, 'warn');
  assert.match(r.detail, /the target ref or key is not valid in this environment/);
  const bad = await run({ ws: () => ({ status: 'SUBSCRIBED' }), health: () => ({ status: 401 }) });
  assert.equal((await check(WS_ID, { data: bad.data })).status, 'fail');
});

test('websocket: no answer in time is inconclusive and the client is still closed', async () => {
  const { ct, clients, data } = await run({ ws: (url) => (url.includes(OTHER) ? 'hang' : { status: 'SUBSCRIBED' }) });
  const row = rowOf(ct, 'realtime_ws');
  assert.equal(row.status, 'TIMED_OUT');
  assert.equal(row.result, 'inconclusive');
  assert.match(row.reason, /no answer from the target \(no answer within 30 ms\)/);
  assert.equal((await check(WS_ID, { data })).status, 'warn');
  assert.ok(clients.every((c) => c.removed === 1 && c.disconnected === 1));
});

test('websocket: a TIMED_OUT answer from the client is inconclusive', async () => {
  const { data } = await run({ ws: (url) => (url.includes(OTHER) ? { status: 'TIMED_OUT' } : { status: 'SUBSCRIBED' }) });
  assert.equal((await check(WS_ID, { data })).status, 'warn');
});

test('websocket: a failure to create or use the client is inconclusive and cleaned up', async () => {
  const { ct, clients, data } = await run({ ws: (url) => (url.includes(OTHER) ? new Error('socket closed') : { status: 'SUBSCRIBED' }) });
  assert.match(rowOf(ct, 'realtime_ws').reason, /network error: socket closed/);
  assert.equal((await check(WS_ID, { data })).status, 'warn');
  assert.ok(clients.every((c) => c.removed === 1 && c.disconnected === 1));
  const noFactory = await run({
    createClientImpl: () => {
      throw new Error('Cannot find module @supabase/supabase-js');
    },
  });
  assert.match(rowOf(noFactory.ct, 'realtime_ws').reason, /network error: Cannot find module/);
});

test('websocket: errors never keep the token or the key', async () => {
  const { ct, data } = await run({ ws: (url, key, token) => ({ status: 'CHANNEL_ERROR', error: `bad ${token} with ${key}` }) });
  const json = JSON.stringify(ct);
  assert.ok(!json.includes(TOKEN) && !json.includes(OTHER_KEY) && !json.includes(OWN_KEY));
  assert.ok(json.includes('bad <redacted> with <redacted>'));
  assert.ok(!JSON.stringify(await check(WS_ID, { data })).includes(TOKEN));
});

test('both probes warn when this tenant has no key for the control', async () => {
  const { data } = await run({ ownKey: '' });
  for (const id of [S3_ID, WS_ID]) {
    const r = await check(id, { data });
    assert.equal(r.status, 'warn', id);
    assert.match(r.detail, /No publishable or anon key is set for this tenant/);
  }
});
