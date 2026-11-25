const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const { worstStatus, worstResult } = require('../gateway-variants');
const { oidcData, check } = require('./helpers');

const SERVICE_ROLE = { current_user: 'service_role' };
const ctx = { resourceToken: 'not-a-jwt' };

// v1 database_identity and gateway_v2 overrides -> data for the database checks.
function data({ db = SERVICE_ROLE, access = [{ table: 'countries', allowed: true, row_count: 3 }], controls, v2 } = {}) {
  return oidcData({
    server_credential: {
      auth_path: 'vercel_oidc_marketplace',
      resource_token: { claims: { role: 'service_role' } },
      database_identity: db,
      access,
      ...(controls && { controls }),
    },
    ...(v2 && { gateway_v2: v2 }),
  });
}

const v2 = (overrides = {}) => ({
  database_identity: SERVICE_ROLE,
  access: [{ table: 'countries', allowed: true, row_count: 3 }],
  gateway_versions: { access: 'v2', database_identity: 'v2' },
  ...overrides,
});

test('worstStatus: fail > warn > pass > skip; worstResult: accepted > inconclusive > rejected', () => {
  for (const [values, worst] of [
    [['pass', 'pass'], 'pass'],
    [['pass', 'warn'], 'warn'],
    [['pass', 'fail'], 'fail'],
    [['warn', 'fail'], 'fail'],
    [['pass', 'skip'], 'pass'],
    [['skip', 'warn'], 'warn'],
    [['skip', 'skip'], 'skip'],
  ]) {
    assert.equal(worstStatus(values), worst, values.join('+'));
    assert.equal(worstStatus([...values].reverse()), worst, values.join('+'));
  }
  assert.equal(worstResult(['rejected', 'inconclusive']), 'inconclusive');
  assert.equal(worstResult(['inconclusive', 'accepted']), 'accepted');
  assert.equal(worstResult(['rejected', 'rejected']), 'rejected');
});

test('a gateway check is the worst of its v1 and v2 results and shows both in the detail', async () => {
  const passBoth = await check('db_role', { data: data({ v2: v2() }), ctx });
  assert.deepEqual([passBoth.status, passBoth.detail], ['pass', 'v1 pass, v2 pass']);
  assert.deepEqual(passBoth.actual, { v1: 'service_role', v2: 'service_role' });
  assert.deepEqual([passBoth.variants.v1.status, passBoth.variants.v2.status], ['pass', 'pass']);

  const notForwarded = await check('db_role', { data: data({ v2: v2({ gateway_versions: { database_identity: 'v1' } }) }), ctx });
  assert.deepEqual([notForwarded.status, notForwarded.detail], ['warn', 'v1 pass, v2 warn (request was not forwarded to api-gateway v2)']);

  const failV2 = await check('db_role', { data: data({ v2: v2({ database_identity: { current_user: 'anon' } }) }), ctx });
  assert.equal(failV2.status, 'fail');
  assert.equal(failV2.detail, 'v1 pass, v2 fail (No role claim reached Supabase.)');

  const failV1 = await check('db_role', { data: data({ db: { current_user: 'anon' }, v2: v2({ gateway_versions: { database_identity: 'unknown' } }) }), ctx });
  assert.equal(failV1.status, 'fail');
  assert.match(failV1.detail, /^v1 fail .*, v2 warn \(request was not forwarded to api-gateway v2\)$/);
});

test('a gateway check uses the gateway versions of its own requests', async () => {
  const d = data({ v2: v2({ gateway_versions: { access: 'v1', database_identity: 'v2' } }) });
  assert.equal((await check('db_role', { data: d, ctx })).status, 'pass');
  assert.equal((await check('db_table_access', { data: d, ctx })).status, 'warn');
  const controls = { apikey_only: { current_user: 'anon' }, tampered_token: { status: 401, error_code: 'PGRST301', error: 'bad' } };
  const withControls = data({
    controls,
    v2: v2({ controls, gateway_versions: { access: 'v2', database_identity: 'v2', apikey_only: 'v2', tampered_token: 'v1' } }),
  });
  assert.equal((await check('db_anon_control', { data: withControls, ctx })).status, 'pass');
  assert.equal((await check('db_tampered_rejected', { data: withControls, ctx })).status, 'warn');
});

test('without v2 results the check keeps its v1 status, and it is skipped only when both are skipped', async () => {
  const noV2 = await check('db_role', { data: data(), ctx });
  assert.deepEqual([noV2.status, noV2.detail], ['pass', 'v1 pass, v2 skip (api-gateway v2 requests were not run.)']);
  const notOidc = await check('db_role', { data: oidcData({ server_credential: { auth_path: 'vercel_integration_keys' }, gateway_v2: v2() }) });
  assert.deepEqual([notOidc.status, notOidc.detail], ['skip', 'Not on the Vercel OIDC path.']);
});

test('gateway_v2_forwarding passes when every v2 request reached api-gateway v2', async () => {
  const ok = await check('gateway_v2_forwarding', { data: data({ v2: v2() }) });
  assert.equal(ok.status, 'pass');
  assert.equal(ok.group, 'path');
  const missed = await check('gateway_v2_forwarding', { data: data({ v2: v2({ gateway_versions: { access: 'v1', database_identity: 'unknown' } }) }) });
  assert.equal(missed.status, 'warn');
  assert.match(missed.detail, /^Not forwarded to api-gateway v2: access \(answered by v1\), database_identity \(answered by unknown\)\./);
  assert.equal((await check('gateway_v2_forwarding', { data: data() })).status, 'skip');
  assert.equal((await check('gateway_v2_forwarding', { data: data({ v2: v2({ gateway_versions: {} }) }) })).status, 'skip');
});

// Loads api/diagnostics with a fake supabase-js whose clients send one request through options.global.fetch.
function loadDiagnostics(fetchImpl) {
  const created = [];
  const createClient = (url, key, options = {}) => {
    created.push({ key, options });
    const send = async () => {
      const res = await (options.global?.fetch ?? fetchImpl)(`${url}/rest/v1/x`, { headers: options.global?.headers ?? {} });
      return res.headers.get('sb-gateway-version');
    };
    return {
      rpc: async () => {
        await send();
        return { data: { current_user: 'service_role' }, error: null };
      },
      from: () => ({
        select: async () => {
          await send();
          return { count: 1, error: null };
        },
      }),
    };
  };
  const stubs = {
    '@supabase/supabase-js': { createClient },
    '@vercel/functions/oidc': { getVercelOidcToken: async () => null },
    pg: { Client: class {} },
  };
  const realLoad = Module._load;
  const paths = ['../diagnostics-core', '../api/diagnostics'].map((p) => require.resolve(p));
  Module._load = function (request, ...rest) {
    return request in stubs ? stubs[request] : realLoad.call(this, request, ...rest);
  };
  paths.forEach((p) => delete require.cache[p]);
  try {
    return { handler: require(paths[1]), core: require(paths[0]), created };
  } finally {
    Module._load = realLoad;
    paths.forEach((p) => delete require.cache[p]);
  }
}

async function withEnv(env, fn) {
  const saved = Object.fromEntries(Object.keys(env).map((k) => [k, process.env[k]]));
  Object.assign(process.env, env);
  try {
    return await fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

const gatewayByHeader = (seen) => async (url, init) => {
  const forwarded = Boolean(init?.headers?.['sb-forward-traffic']);
  seen.push(forwarded);
  return new Response('{}', { status: 200, headers: { 'sb-gateway-version': forwarded ? '2' : '1' } });
};

test('/api/diagnostics sends each api-gateway request to v1 and v2 and keeps v1 at the old keys', async () => {
  const seen = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = gatewayByHeader(seen);
  try {
    await withEnv({ SUPABASE_URL: 'https://abcdefghijklmnopqrst.supabase.co', SUPABASE_ANON_KEY: 'anon-key' }, async () => {
      const { handler, created } = loadDiagnostics(globalThis.fetch);
      const res = {
        writeHead(status) {
          this.status = status;
        },
        end(body) {
          this.body = JSON.parse(body);
        },
      };
      await handler({ method: 'GET', url: '/api/diagnostics', headers: {} }, res);
      assert.equal(res.status, 200);
      const { data, checks } = res.body;
      assert.deepEqual(data.server_credential.database_identity, { current_user: 'service_role' });
      assert.deepEqual(data.server_credential.access, [{ table: 'countries', allowed: true, row_count: 1 }]);
      assert.deepEqual(data.gateway_v2.gateway_versions, { access: 'v2', database_identity: 'v2' });
      assert.deepEqual(data.gateway_v2.database_identity, { current_user: 'service_role' });
      assert.ok(!('controls' in data.gateway_v2));
      assert.deepEqual(seen.sort(), [false, false, true, true]);
      assert.ok(created.filter((c) => c.options.global?.headers?.['sb-forward-traffic'] === 'true').length >= 2);
      assert.equal(checks.results.find((r) => r.id === 'gateway_v2_forwarding').status, 'pass');
    });
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('gatewayClientFactory records "unknown" when no answer has the gateway header', async () => {
  await withEnv({ SUPABASE_URL: 'https://abcdefghijklmnopqrst.supabase.co' }, async () => {
    const { core } = loadDiagnostics(async () => new Response('{}'));
    const make = core.gatewayClientFactory('v2', async () => new Response('{}', { status: 200 }));
    const client = make('key');
    assert.equal(client.gatewayVersion(), 'unknown');
    await client.rpc('whoami_vercel');
    assert.equal(client.gatewayVersion(), 'unknown');
    const v2 = core.gatewayClientFactory('v2', async () => new Response('{}', { headers: { 'sb-gateway-version': '2.0' } }))('key');
    await v2.rpc('whoami_vercel');
    assert.equal(v2.gatewayVersion(), 'v2');
    assert.equal(core.gatewayClientFactory('v2')(''), null);
  });
});
