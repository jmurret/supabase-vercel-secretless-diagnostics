const { createClient } = require('@supabase/supabase-js');
const { getVercelOidcToken } = require('@vercel/functions/oidc');
const dns = require('node:dns');
const { Client } = require('pg');
const { runChecks } = require('../checks');

const URL_ENV_VAR = ['SUPABASE_URL', 'NEXT_PUBLIC_SUPABASE_URL'].find((n) => process.env[n]);
const SUPABASE_URL = URL_ENV_VAR ? process.env[URL_ENV_VAR].replace(/\/+$/, '') : undefined;
// Public keys only: secret/service-role keys are removed for OIDC (secretless) resources.
const ANON_KEY_ENV_VARS = [
  'SUPABASE_PUBLISHABLE_KEY', 'NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY', 'SUPABASE_ANON_KEY', 'NEXT_PUBLIC_SUPABASE_ANON_KEY',
];
// Supabase host suffix -> Management API base URL (used for the JIT access probe).
const MANAGEMENT_APIS = [
  ['.supabase.red', 'https://api.supabase.green'],
  ['.supabase.co', 'https://api.supabase.com'],
];
const JIT_ROLE = 'postgres';
const PROBE_TIMEOUT_MS = 5000;
const PROBE_TABLES = ['countries'];
const SAFE_CLAIMS = [
  'iss', 'sub', 'aud', 'role', 'exp', 'iat', 'nbf', 'email', 'scope', 'aal', 'is_anonymous',
  'owner', 'owner_id', 'project', 'project_id', 'environment', 'user_id', 'act',
];
const CLIENT_OPTIONS = { auth: { persistSession: false, autoRefreshToken: false } };

function describeSupabaseUrl() {
  const info = { env_var: URL_ENV_VAR ?? null, valid: false, host: null, project_ref: null, management_api: null };
  if (!SUPABASE_URL) return info;
  try {
    const { host, hostname } = new URL(SUPABASE_URL);
    const mgmt = MANAGEMENT_APIS.find(([suffix]) => hostname.endsWith(suffix));
    // The project ref is only derivable from <ref>.supabase.<tld> hosts, not custom domains.
    Object.assign(info, {
      valid: true,
      host,
      project_ref: mgmt ? hostname.split('.')[0] : null,
      management_api: mgmt ? mgmt[1] : null,
    });
  } catch {}
  return info;
}

const SUPABASE_URL_INFO = describeSupabaseUrl();

function makeClient(key, options = CLIENT_OPTIONS) {
  return SUPABASE_URL_INFO.valid && key ? createClient(SUPABASE_URL, key, options) : null;
}

function firstEnv(names) {
  const name = names.find((n) => process.env[n]);
  return name ? { name, value: process.env[name] } : null;
}

function decodeJwtPart(token, index) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    return JSON.parse(Buffer.from(parts[index], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

const decodeJwt = (token) => decodeJwtPart(token, 1);

function jwtHeader(token) {
  const header = decodeJwtPart(token, 0);
  return header ? { alg: header.alg ?? null, kid: header.kid ?? null, typ: header.typ ?? null } : null;
}

function safeClaims(payload) {
  if (!payload) return null;
  const claims = {};
  for (const key of SAFE_CLAIMS) {
    if (payload[key] !== undefined) claims[key] = payload[key];
  }
  if (typeof payload.exp === 'number') {
    claims.expires_in_s = payload.exp - Math.floor(Date.now() / 1000);
    claims.expired = claims.expires_in_s <= 0;
  }
  return claims;
}

function describeKey(key) {
  if (key.startsWith('sb_secret_')) return { key_format: 'sb_secret', role: 'service_role' };
  if (key.startsWith('sb_publishable_')) return { key_format: 'sb_publishable', role: 'anon' };
  const payload = decodeJwt(key);
  return { key_format: payload ? 'jwt' : 'unknown', role: payload?.role ?? null };
}

async function getOidcToken(req) {
  const header = req?.headers['x-vercel-oidc-token'];
  if (header) return { token: header, source: 'header' };
  try {
    // Falls back to Vercel's request context / VERCEL_OIDC_TOKEN (refreshed via the CLI in dev).
    const token = await getVercelOidcToken();
    if (token) return { token, source: 'vercel_functions' };
  } catch {}
  return null;
}

class MintError extends Error {
  constructor(message, status = null, body = null) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

const resourceTokenCache = new Map();
const TOKEN_REFRESH_MARGIN_MS = 60_000;

// Exchanges the deployment's Vercel OIDC token for a Marketplace resource token that the
// Supabase resource trusts. Cached until shortly before it expires. Without a role, Vercel issues
// the resource's default role (service_role); with one, it issues a token for that role.
async function mintResourceToken(resourceId, oidcToken, role) {
  const cacheKey = `${resourceId}:${role ?? ''}`;
  const cached = resourceTokenCache.get(cacheKey);
  if (cached && cached.expiresAt - TOKEN_REFRESH_MARGIN_MS > Date.now()) {
    return { ...cached, cached: true };
  }
  const query = role ? `?role=${encodeURIComponent(role)}` : '';
  const res = await fetch(
    `https://api.vercel.com/v1/integrations/resources/${encodeURIComponent(resourceId)}/token${query}`,
    {
      method: 'POST',
      headers: { Authorization: `Bearer ${oidcToken}`, 'content-type': 'application/json' },
    }
  );
  if (!res.ok) {
    const body = (await res.text()).slice(0, 500);
    throw new MintError(`mint failed: ${res.status}`, res.status, body);
  }
  const minted = await res.json();
  if (!minted?.token) throw new MintError('mint response did not include a token');
  const expiresAt = minted.expiresAt ?? Date.now() + (minted.expiresIn ?? 0) * 1000;
  const entry = { token: minted.token, tokenType: minted.tokenType ?? 'bearer', expiresAt };
  resourceTokenCache.set(cacheKey, entry);
  return { ...entry, cached: false };
}

// Mints a resource token and describes it for the response. Never throws: on a failed mint it
// returns the error and its description instead of a token.
async function mintAndDescribe(resourceId, oidcToken, role) {
  try {
    const minted = await mintResourceToken(resourceId, oidcToken, role);
    return {
      token: minted.token,
      fields: {
        cached: minted.cached,
        token_type: minted.tokenType,
        expires_at: new Date(minted.expiresAt).toISOString(),
        expires_in_s: Math.round((minted.expiresAt - Date.now()) / 1000),
        jwt_header: jwtHeader(minted.token),
        claims: safeClaims(decodeJwt(minted.token)),
      },
    };
  } catch (err) {
    return { error: err, fields: { error: err.message, status: err.status ?? null, response_body: err.body ?? null } };
  }
}

// Uses a Marketplace resource token (minted from the Vercel OIDC token) when an OIDC token is
// available, otherwise the public Supabase key injected by the Vercel integration.
async function resolveServerCredential(req) {
  const oidc = await getOidcToken(req);
  if (oidc) {
    const anonKey = firstEnv(ANON_KEY_ENV_VARS);
    const resourceId = process.env.MARKETPLACE_RESOURCE_ID;
    const info = {
      auth_path: 'vercel_oidc_marketplace',
      apikey: anonKey ? { env_var: anonKey.name, ...describeKey(anonKey.value) } : null,
      oidc: {
        source: oidc.source,
        jwt_header: jwtHeader(oidc.token),
        claims: safeClaims(decodeJwt(oidc.token)),
      },
      resource_token: { resource_id: resourceId ?? null },
    };
    if (!resourceId) {
      info.resource_token.error = 'MARKETPLACE_RESOURCE_ID is not set';
      return { client: null, info, ctx: { oidcToken: oidc.token }, error: new MintError(info.resource_token.error) };
    }
    const { token, fields, error } = await mintAndDescribe(resourceId, oidc.token);
    Object.assign(info.resource_token, fields);
    if (!token) return { client: null, info, ctx: { oidcToken: oidc.token }, error };
    return {
      client: makeClient(anonKey?.value, { ...CLIENT_OPTIONS, accessToken: async () => token }),
      info,
      // Raw tokens/keys for probes and checks.js signature/size checks; never serialized.
      ctx: { oidcToken: oidc.token, resourceToken: token, apikey: anonKey?.value },
    };
  }
  const key = firstEnv(ANON_KEY_ENV_VARS);
  return {
    client: makeClient(key?.value),
    info: {
      auth_path: 'vercel_integration_keys',
      key_env_var: key?.name ?? null,
      ...(key ? describeKey(key.value) : { key_format: null, role: null }),
    },
  };
}

// The Management API and the Postgres logins need a token whose role claim equals the requested
// JIT role, so this mints a separate token with that role. The default-role token is not used here.
async function resolveJitCredential(server) {
  const oidcToken = server.ctx?.oidcToken;
  const resourceId = server.info?.resource_token?.resource_id;
  if (!oidcToken || !resourceId) return { info: { skipped: 'no OIDC token or resource id' } };
  const { token, fields } = await mintAndDescribe(resourceId, oidcToken, JIT_ROLE);
  return { token, info: { role: JIT_ROLE, ...fields } };
}

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

  const key = firstEnv(ANON_KEY_ENV_VARS);
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

// Control requests that show the role comes from the resource token: without it the request must
// run as anon, and with a tampered signature Supabase must reject it (401 PGRST301).
async function runControls(ctx) {
  const apikeyOnly = makeClient(ctx.apikey);
  const tampered = makeClient(ctx.apikey, { ...CLIENT_OPTIONS, accessToken: async () => tamper(ctx.resourceToken) });
  const [apikeyOnlyResult, tamperedResult] = await Promise.all([dbWhoami(apikeyOnly), dbWhoami(tampered)]);
  return { apikey_only: apikeyOnlyResult, tampered_token: tamperedResult };
}

async function requestJitAccess(token) {
  const { management_api: mgmt, project_ref: ref } = SUPABASE_URL_INFO;
  if (!mgmt || !ref) return { skipped: 'Supabase URL is not a <ref>.supabase.co host' };
  const started = Date.now();
  try {
    const res = await fetch(`${mgmt}/v1/projects/${encodeURIComponent(ref)}/database/jit`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ role: JIT_ROLE, rhost: '127.0.0.1' }),
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    const text = await res.text();
    let body = null;
    try {
      body = JSON.parse(text);
    } catch {}
    const result = { endpoint: `${mgmt}/v1/projects/${ref}/database/jit`, status: res.status, ms: Date.now() - started };
    if (res.status === 200) result.role = body?.user_role?.role ?? null;
    else result.error = (body?.message ?? text).slice(0, 500);
    return result;
  } catch (err) {
    return { status: null, error: err.message, ms: Date.now() - started };
  }
}

// Logs in to Postgres with the resource token as the password. Without an explicit host, host, port
// and user come from SUPABASE_POOLER_HOST/PORT/USER (set by `pnpm run bootstrap`); no static password is used.
async function loginWithToken(token, { host, port, user, options, servername, endpoint, timeoutMs = 10_000 } = {}) {
  if (!host) {
    const { SUPABASE_POOLER_HOST, SUPABASE_POOLER_PORT, SUPABASE_POOLER_USER } = process.env;
    if (!SUPABASE_POOLER_HOST || !SUPABASE_POOLER_USER) {
      return { skipped: 'SUPABASE_POOLER_HOST or SUPABASE_POOLER_USER is not set: run `pnpm run bootstrap`' };
    }
    host = SUPABASE_POOLER_HOST;
    port = Number(SUPABASE_POOLER_PORT) || 5432;
    user = SUPABASE_POOLER_USER;
  }
  endpoint ??= `${host}:${port}`;
  const client = new Client({
    host,
    port,
    user,
    password: token,
    ...(options && { options }),
    database: 'postgres',
    ssl: { rejectUnauthorized: false, ...(servername && { servername }) },
    connectionTimeoutMillis: timeoutMs,
  });
  client.on('error', () => {});
  const started = Date.now();
  try {
    await client.connect();
    const { rows } = await client.query('select current_user');
    return { endpoint, current_user: rows[0].current_user, ms: Date.now() - started };
  } catch (err) {
    return { endpoint, error: err.message, code: err.code, ms: Date.now() - started };
  } finally {
    await client.end().catch(() => {});
  }
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

async function runDiagnostics(req, res) {
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
  const noJitToken = { skipped: jit.info.error ? `JIT token mint failed: ${jit.info.error}` : 'no JIT resource token' };
  const directHost = SUPABASE_URL_INFO.project_ref ? `db.${SUPABASE_URL_INFO.host}` : null;
  const [serverAccess, serverDbIdentity, controls, jitApi, jitApiDefaultRole, jitLogin, jitLoginNoJit, directLogin, endUser] = await Promise.all([
    server.client ? probeAccess(server.client) : skipped,
    server.client ? dbWhoami(server.client) : skipped,
    server.client && resourceToken ? runControls(server.ctx) : skipped,
    jitToken ? requestJitAccess(jitToken) : noJitToken,
    // Control: the default-role (service_role) token must not get JIT access to JIT_ROLE.
    resourceToken ? requestJitAccess(resourceToken) : noToken,
    jitToken ? loginWithToken(jitToken, { options: '--jit=true' }) : noJitToken,
    jitToken ? loginWithToken(jitToken) : noJitToken,
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
      access: serverAccess,
      database_identity: serverDbIdentity,
      ...(server.info.auth_path === 'vercel_oidc_marketplace' && { controls }),
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
  const checks = await runChecks(data, server.ctx);
  res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify({ data, checks }, null, 2));
}

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.writeHead(405, { 'Content-Type': 'application/json', Allow: 'GET' });
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }
  try {
    await runDiagnostics(req, res);
  } catch (error) {
    console.error('Diagnostics error:', error);
    res.writeHead(500, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({ error: error.message }));
  }
};
