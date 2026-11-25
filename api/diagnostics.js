const dns = require('node:dns');
const { runChecks } = require('../checks');
const {
  JIT_ROLE,
  SUPABASE_URL_INFO,
  KEY_ENV_VARS,
  ANON_KEY_ENV_VARS,
  CLIENT_OPTIONS,
  makeClient,
  gatewayClientFactory,
  firstEnv,
  decodeJwt,
  jwtHeader,
  safeClaims,
  resolveServerCredential,
  resolveJitCredential,
  requestJitAccess,
  loginWithToken,
  loginPooler,
  noJitTokenResult,
  serve,
} = require('../diagnostics-core');

const PROBE_TABLES = ['countries'];

async function probeAccess(client) {
  return Promise.all(
    PROBE_TABLES.map(async (table) => {
      try {
        const { count, error } = await client.from(table).select('*', { count: 'exact', head: true });
        if (error) return { table, allowed: false, error_code: error.code || null, error: error.message || null };
        return { table, allowed: true, row_count: count };
      } catch (err) {
        return { table, allowed: false, error: err.message };
      }
    })
  );
}

async function dbWhoami(client) {
  try {
    const { data, error, status } = await client.rpc('whoami_vercel');
    if (error) return { status: status ?? null, error_code: error.code || null, error: error.message || null };
    return data;
  } catch (err) {
    return { error: err.message };
  }
}

async function describeEndUser(req) {
  const match = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
  if (!match) return { present: false };
  const jwt = match[1].trim();
  const result = { present: true, jwt_header: jwtHeader(jwt), claims: safeClaims(decodeJwt(jwt)) };

  const key = firstEnv(ANON_KEY_ENV_VARS) || firstEnv(KEY_ENV_VARS);
  const authClient = makeClient(key?.value);
  if (!authClient) return { ...result, authenticated: false, error: 'Supabase URL or key is not configured' };
  try {
    const { data, error } = await authClient.auth.getUser(jwt);
    if (error) throw error;
    const { user } = data;
    result.authenticated = true;
    result.user = {
      id: user.id,
      email: user.email ?? null,
      role: user.role ?? null,
      is_anonymous: user.is_anonymous ?? false,
      provider: user.app_metadata?.provider ?? null,
      providers: user.app_metadata?.providers ?? [],
      last_sign_in_at: user.last_sign_in_at ?? null,
    };
  } catch (err) {
    result.authenticated = false;
    result.error = err.message;
    return result;
  }

  const userClient = makeClient(key?.value, {
    ...CLIENT_OPTIONS,
    global: { headers: { Authorization: `Bearer ${jwt}` } },
  });
  [result.access, result.database_identity] = await Promise.all([
    probeAccess(userClient),
    dbWhoami(userClient),
  ]);
  return result;
}

// Changes the first signature character; the last one carries base64 padding bits, so changing it
// can decode to the same signature.
function tamper(token) {
  const i = token.lastIndexOf('.') + 1;
  return token.slice(0, i) + (token[i] === 'A' ? 'B' : 'A') + token.slice(i + 1);
}

// Runs probe with its own client and records the gateway version of the answer when the client has one.
async function traced(versions, name, client, probe) {
  const result = await probe(client);
  if (client.gatewayVersion) versions[name] = client.gatewayVersion();
  return result;
}

// The requests to the project api-gateway. make(key, options) creates each client: makeClient for api-gateway
// v1, or a gatewayClientFactory client for v2. The controls show that the role comes from the resource token:
// without it the request must run as anon, and with a tampered signature Supabase must reject it (401 PGRST301).
async function gatewayProbes(server, make, skipped) {
  const versions = {};
  const resourceToken = server.ctx?.resourceToken;
  const serverClient = () => make(...server.clientArgs);
  const hasClient = Boolean(SUPABASE_URL_INFO.valid && server.clientArgs?.[0]);
  const runControls = async () => {
    const [apikeyOnly, tampered] = await Promise.all([
      traced(versions, 'apikey_only', make(server.ctx.apikey), dbWhoami),
      traced(versions, 'tampered_token', make(server.ctx.apikey, { ...CLIENT_OPTIONS, accessToken: async () => tamper(resourceToken) }), dbWhoami),
    ]);
    return { apikey_only: apikeyOnly, tampered_token: tampered };
  };
  const [access, databaseIdentity, controls] = await Promise.all([
    hasClient ? traced(versions, 'access', serverClient(), probeAccess) : skipped,
    hasClient ? traced(versions, 'database_identity', serverClient(), dbWhoami) : skipped,
    hasClient && resourceToken ? runControls() : skipped,
  ]);
  return { access, database_identity: databaseIdentity, controls, gateway_versions: versions };
}

// The direct host has an A record only with the IPv4 add-on, and always has an AAAA record. Prefer IPv4, fall back to IPv6,
// and connect to the address literal with the host name as the TLS server name.
async function loginDirect(token, hostname) {
  const started = Date.now();
  const [[v4], [v6]] = await Promise.all([
    dns.promises.resolve4(hostname).catch(() => []),
    dns.promises.resolve6(hostname).catch(() => []),
  ]);
  const address = v4 ?? v6;
  if (!address) {
    return { resolve_failed: true, error: `no A or AAAA record for ${hostname}`, ms: Date.now() - started };
  }
  const family = v4 ? 4 : 6;
  const login = await loginWithToken(token, {
    host: address,
    port: 5432,
    user: JIT_ROLE,
    servername: hostname,
    endpoint: family === 6 ? `[${address}]` : address,
    timeoutMs: 5000,
  });
  return { ...login, address, family, ms: Date.now() - started };
}

async function runDiagnostics(req) {
  const server = await resolveServerCredential(req);
  const resourceToken = server.ctx?.resourceToken;
  const jit = await resolveJitCredential(server);
  const jitToken = jit.token;
  const noToken = { skipped: 'no resource token' };
  const skipped = {
    skipped: !SUPABASE_URL_INFO.valid
      ? 'no Supabase client: Supabase URL is missing or invalid'
      : 'no Supabase client: resource token could not be minted',
  };
  const noJitToken = noJitTokenResult(jit);
  const directHost = SUPABASE_URL_INFO.project_ref ? `db.${SUPABASE_URL_INFO.host}` : null;
  const isOidcPath = server.info.auth_path === 'vercel_oidc_marketplace';
  const [v1, v2, jitApi, jitApiDefaultRole, jitLogin, jitLoginNoJit, directLogin, endUser] = await Promise.all([
    gatewayProbes(server, makeClient, skipped),
    gatewayProbes(server, gatewayClientFactory('v2'), skipped),
    jitToken ? requestJitAccess(jitToken) : noJitToken,
    // Control: the default-role (service_role) token must not get JIT access to JIT_ROLE.
    resourceToken ? requestJitAccess(resourceToken) : noToken,
    jitToken ? loginPooler(jitToken, '--jit=true') : noJitToken,
    jitToken ? loginPooler(jitToken) : noJitToken,
    jitToken && directHost ? loginDirect(jitToken, directHost) : noJitToken,
    describeEndUser(req),
  ]);

  const data = {
    timestamp: new Date().toISOString(),
    environment: {
      vercel_env: process.env.VERCEL_ENV ?? null,
      vercel_region: process.env.VERCEL_REGION ?? null,
      supabase_url_host: SUPABASE_URL_INFO.host,
      supabase_url: SUPABASE_URL_INFO,
    },
    server_credential: {
      ...server.info,
      access: v1.access,
      database_identity: v1.database_identity,
      ...(isOidcPath && { controls: v1.controls }),
    },
    // The same requests with sb-forward-traffic: true, and the gateway version that answered each one.
    gateway_v2: {
      access: v2.access,
      database_identity: v2.database_identity,
      ...(isOidcPath && { controls: v2.controls }),
      gateway_versions: v2.gateway_versions,
    },
    jit: {
      resource_token: jit.info,
      management_api: jitApi,
      management_api_default_role: jitApiDefaultRole,
      postgres_login: jitLogin,
      postgres_login_no_jit: jitLoginNoJit,
      direct_login: directLogin,
    },
    end_user: endUser,
  };
  const checks = await runChecks(data, server.ctx, { exclude: ['cross_tenant'] });
  return { data, checks };
}

module.exports = serve('Diagnostics', runDiagnostics);
