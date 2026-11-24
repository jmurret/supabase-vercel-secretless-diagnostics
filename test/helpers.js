const { runChecks } = require('../checks');

const REF = 'abcdefghijklmnopqrst';

function oidcData(overrides = {}) {
  return {
    environment: {
      supabase_url: { env_var: 'SUPABASE_URL', valid: true, host: `${REF}.supabase.co`, project_ref: REF },
    },
    server_credential: { auth_path: 'vercel_oidc_marketplace' },
    ...overrides,
  };
}

const noFetch = () => {
  throw new Error('unexpected fetch');
};

async function check(id, { data = oidcData(), ctx = {}, env = {} } = {}) {
  const { results } = await runChecks(data, ctx, { env, now: () => 0, fetchImpl: noFetch });
  const r = results.find((x) => x.id === id);
  if (!r) throw new Error(`no check ${id}`);
  return r;
}

module.exports = { REF, oidcData, check };
