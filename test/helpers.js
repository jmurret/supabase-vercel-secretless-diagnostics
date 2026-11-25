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

const REALTIME_DEFAULT = (url) =>
  new URL(url).hostname.startsWith(REF) ? { status: 'SUBSCRIBED' } : { status: 'CHANNEL_ERROR', error: 'Unauthorized' };

// answer(url, key, token) -> { status, error? } | Error | 'hang'. `clients` records each client it made.
function fakeRealtime(answer = REALTIME_DEFAULT) {
  const clients = [];
  const createClientImpl = (url, key, options) => {
    const client = { url, key, options, token: null, channels: [], removed: 0, disconnected: 0 };
    clients.push(client);
    return {
      realtime: {
        setAuth: async (token) => {
          client.token = token;
        },
        disconnect: () => {
          client.disconnected += 1;
        },
      },
      channel: (name, config) => {
        client.channels.push({ name, config });
        return {
          subscribe: (callback) => {
            const r = answer(url, key, client.token);
            if (r === 'hang') return;
            if (r instanceof Error) throw r;
            setImmediate(() => callback(r.status, r.error ? new Error(r.error) : undefined));
          },
        };
      },
      removeAllChannels: async () => {
        client.removed += 1;
      },
    };
  };
  return { createClientImpl, clients };
}

module.exports = { REF, oidcData, check, fakeRealtime };
