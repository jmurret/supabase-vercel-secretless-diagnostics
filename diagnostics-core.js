const { createClient } = require('@supabase/supabase-js');
const { getVercelOidcToken } = require('@vercel/functions/oidc');
const { Client } = require('pg');
const { runChecks } = require('./checks');
const { poolerLoginParams } = require('./pooler');
const { runCrossTenant, runCrossTenantS3, isLegacyAnonKey } = require('./cross-tenant');
const { parsePoolerHints, parseRegionHints } = require('./pooler-discovery');
const { GATEWAY_HEADER, variantHeaders, normalizeGatewayVersion } = require('./gateway-variants');

const URL_ENV_VAR = ['SUPABASE_URL', 'NEXT_PUBLIC_SUPABASE_URL'].find((n) => process.env[n]);
const SUPABASE_URL = URL_ENV_VAR ? process.env[URL_ENV_VAR].replace(/\/+$/, '') : undefined;
const KEY_ENV_VARS = ['SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_ANON_KEY', 'NEXT_PUBLIC_SUPABASE_ANON_KEY'];
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

// Returns a makeClient for api-gateway `variant`. Its clients send the forwarding header of the variant, and
// client.gatewayVersion() gives the sb-gateway-version of the answers ("unknown" without an answer). Use one
// client for each probe, so that the version belongs to that probe.
function gatewayClientFactory(variant, fetchImpl = (...args) => fetch(...args)) {
  return (key, options = CLIENT_OPTIONS) => {
    if (!SUPABASE_URL_INFO.valid || !key) return null;
    const versions = new Set();
    const recordingFetch = async (...args) => {
      const res = await fetchImpl(...args);
      versions.add(normalizeGatewayVersion(res.headers.get(GATEWAY_HEADER)));
      return res;
    };
    const client = createClient(SUPABASE_URL, key, {
      ...options,
      global: { ...options.global, headers: { ...options.global?.headers, ...variantHeaders(variant) }, fetch: recordingFetch },
    });
    return Object.assign(client, { gatewayVersion: () => [...versions].sort().join(',') || 'unknown' });
  };
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
// available, otherwise the Supabase keys injected by the Vercel integration.
async function resolveServerCredential(req) {
  const oidc = await getOidcToken(req);
  if (oidc) {
    const anonKey = firstEnv(ANON_KEY_ENV_VARS) || firstEnv(KEY_ENV_VARS);
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
      return { clientArgs: null, info, ctx: { oidcToken: oidc.token }, error: new MintError(info.resource_token.error) };
    }
    const { token, fields, error } = await mintAndDescribe(resourceId, oidc.token);
    Object.assign(info.resource_token, fields);
    if (!token) return { clientArgs: null, info, ctx: { oidcToken: oidc.token }, error };
    return {
      // Arguments of makeClient (or of a gatewayClientFactory client) for the server client.
      clientArgs: [anonKey?.value, { ...CLIENT_OPTIONS, accessToken: async () => token }],
      info,
      // Raw tokens/keys for probes and checks.js signature/size checks; never serialized.
      ctx: { oidcToken: oidc.token, resourceToken: token, apikey: anonKey?.value },
    };
  }
  const key = firstEnv(KEY_ENV_VARS);
  return {
    clientArgs: [key?.value],
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

async function requestJitAccess(token, ref = SUPABASE_URL_INFO.project_ref) {
  const { management_api: mgmt } = SUPABASE_URL_INFO;
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

// Logs in to Postgres with the resource token as the password.
async function loginWithToken(token, { host, port, user, database = 'postgres', options, servername, endpoint, timeoutMs = 10_000 }) {
  endpoint ??= `${host}:${port}`;
  const client = new Client({
    host,
    port,
    user,
    password: token,
    ...(options && { options }),
    database,
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

async function loginPooler(token, options, ref, host, timeoutMs) {
  const env = host ? { ...process.env, POSTGRES_POOLER_HOST: host } : process.env;
  const params = poolerLoginParams(env, JIT_ROLE, ref);
  return params.skipped ? params : loginWithToken(token, { ...params, options, ...(timeoutMs && { timeoutMs }) });
}

const noJitTokenResult = (jit) => ({ skipped: jit.info.error ? `JIT token mint failed: ${jit.info.error}` : 'no JIT resource token' });

function runCrossTenantProbes(req, server, jit) {
  const jitToken = jit.token;
  return runCrossTenant({
    spec: process.env.CROSS_TENANT_TARGETS,
    ownUrl: SUPABASE_URL,
    ownKey: server.ctx?.apikey,
    token: server.ctx?.resourceToken,
    jit: jitToken
      ? {
          token: jitToken,
          requestJit: (ref) => requestJitAccess(jitToken, ref),
          poolerHost: process.env.POSTGRES_POOLER_HOST,
          poolerHints: parsePoolerHints(new URL(req.url ?? '/', 'http://localhost').searchParams.get('pooler_hints')),
          loginPooler: (ref, host, timeoutMs) => loginPooler(jitToken, '--jit=true', ref, host, timeoutMs),
        }
      : noJitTokenResult(jit),
  });
}

// Runs the cross-tenant probes and the two JIT results that the cross_tenant checks use as controls.
async function runCrossTenantDiagnostics(req) {
  const server = await resolveServerCredential(req);
  const jit = await resolveJitCredential(server);
  const jitToken = jit.token;
  const noJitToken = noJitTokenResult(jit);
  const [jitApi, jitLogin, crossTenant] = await Promise.all([
    jitToken ? requestJitAccess(jitToken) : noJitToken,
    jitToken ? loginPooler(jitToken, '--jit=true') : noJitToken,
    runCrossTenantProbes(req, server, jit),
  ]);
  const data = { cross_tenant: crossTenant, jit: { management_api: jitApi, postgres_login: jitLogin } };
  const checks = await runChecks(data, server.ctx, { include: ['cross_tenant'], exclude: [S3_CHECK_ID] });
  return { data, checks };
}

const S3_CHECK_ID = 'cross_tenant_storage_s3';
const S3_KEY_ENV_VARS = ['SUPABASE_ANON_KEY', 'NEXT_PUBLIC_SUPABASE_ANON_KEY'];

function ownS3Key() {
  const ref = SUPABASE_URL_INFO.project_ref ?? undefined;
  return S3_KEY_ENV_VARS.map((name) => process.env[name]).find((value) => isLegacyAnonKey(value, ref));
}

// Runs the Storage S3 probes with the target regions from ?regions=<ref>:<region>,...
async function runCrossTenantS3Diagnostics(req) {
  const server = await resolveServerCredential(req);
  const crossTenantS3 = await runCrossTenantS3({
    spec: process.env.CROSS_TENANT_TARGETS,
    ownUrl: SUPABASE_URL,
    ownS3Key: ownS3Key(),
    token: server.ctx?.resourceToken,
    ownPoolerHost: process.env.POSTGRES_POOLER_HOST,
    regions: parseRegionHints(new URL(req.url ?? '/', 'http://localhost').searchParams.get('regions')),
  });
  const data = { cross_tenant_s3: crossTenantS3 };
  const checks = await runChecks(data, server.ctx, { include: [S3_CHECK_ID] });
  return { data, checks };
}

// Wraps a function that returns the response body in a GET-only (req, res) handler.
function serve(name, run) {
  return async function handler(req, res) {
    if (req.method !== 'GET') {
      res.writeHead(405, { 'Content-Type': 'application/json', Allow: 'GET' });
      res.end(JSON.stringify({ error: 'Method not allowed' }));
      return;
    }
    try {
      const body = await run(req);
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify(body, null, 2));
    } catch (error) {
      console.error(`${name} error:`, error);
      res.writeHead(500, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ error: error.message }));
    }
  };
}

module.exports = {
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
  runCrossTenantDiagnostics,
  runCrossTenantS3Diagnostics,
  serve,
};
