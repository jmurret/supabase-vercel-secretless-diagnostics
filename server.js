const http = require('http');
const { createClient } = require('@supabase/supabase-js');
const { getVercelOidcToken } = require('@vercel/functions/oidc');

const SUPABASE_URL = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
const KEY_ENV_VARS = ['SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_ANON_KEY', 'NEXT_PUBLIC_SUPABASE_ANON_KEY'];
const ANON_KEY_ENV_VARS = ['SUPABASE_ANON_KEY', 'NEXT_PUBLIC_SUPABASE_ANON_KEY'];
const PROBE_TABLES = ['countries'];
const SAFE_CLAIMS = [
  'iss', 'sub', 'aud', 'role', 'exp', 'iat', 'nbf', 'email', 'scope', 'aal', 'is_anonymous',
  'owner', 'owner_id', 'project', 'project_id', 'environment', 'user_id', 'act',
];
const CLIENT_OPTIONS = { auth: { persistSession: false, autoRefreshToken: false } };

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
// Supabase resource trusts. Cached until shortly before it expires.
async function mintResourceToken(resourceId, oidcToken) {
  const cached = resourceTokenCache.get(resourceId);
  if (cached && cached.expiresAt - TOKEN_REFRESH_MARGIN_MS > Date.now()) {
    return { ...cached, cached: true };
  }
  const res = await fetch(
    `https://api.vercel.com/v1/integrations/marketplace/resources/${encodeURIComponent(resourceId)}/token`,
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
  resourceTokenCache.set(resourceId, entry);
  return { ...entry, cached: false };
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
      apikey_env_var: anonKey?.name ?? null,
      oidc: {
        source: oidc.source,
        jwt_header: jwtHeader(oidc.token),
        claims: safeClaims(decodeJwt(oidc.token)),
      },
      resource_token: { resource_id: resourceId ?? null },
    };
    if (!resourceId) {
      info.resource_token.error = 'MARKETPLACE_RESOURCE_ID is not set';
      return { client: null, info, error: new MintError(info.resource_token.error) };
    }
    try {
      const minted = await mintResourceToken(resourceId, oidc.token);
      Object.assign(info.resource_token, {
        cached: minted.cached,
        token_type: minted.tokenType,
        expires_at: new Date(minted.expiresAt).toISOString(),
        expires_in_s: Math.round((minted.expiresAt - Date.now()) / 1000),
        jwt_header: jwtHeader(minted.token),
        claims: safeClaims(decodeJwt(minted.token)),
      });
      const token = minted.token;
      return {
        client: createClient(SUPABASE_URL, anonKey?.value, {
          ...CLIENT_OPTIONS,
          accessToken: async () => token,
        }),
        info,
      };
    } catch (err) {
      Object.assign(info.resource_token, {
        error: err.message,
        status: err.status ?? null,
        response_body: err.body ?? null,
      });
      return { client: null, info, error: err };
    }
  }
  const key = firstEnv(KEY_ENV_VARS);
  return {
    client: createClient(SUPABASE_URL, key?.value, CLIENT_OPTIONS),
    info: {
      auth_path: 'vercel_integration_keys',
      key_env_var: key?.name ?? null,
      ...(key ? describeKey(key.value) : { key_format: null, role: null }),
    },
  };
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
    const { data, error } = await client.rpc('whoami_vercel');
    if (error) return { error_code: error.code || null, error: error.message || null };
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
  const authClient = createClient(SUPABASE_URL, key?.value, CLIENT_OPTIONS);
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

  const userClient = createClient(SUPABASE_URL, key?.value, {
    ...CLIENT_OPTIONS,
    global: { headers: { Authorization: `Bearer ${jwt}` } },
  });
  [result.access, result.database_identity] = await Promise.all([
    probeAccess(userClient),
    dbWhoami(userClient),
  ]);
  return result;
}

async function handleDiagnostics(req, res) {
  const server = await resolveServerCredential(req);
  const skipped = { skipped: 'no Supabase client: resource token could not be minted' };
  const [serverAccess, serverDbIdentity, endUser] = await Promise.all([
    server.client ? probeAccess(server.client) : skipped,
    server.client ? dbWhoami(server.client) : skipped,
    describeEndUser(req),
  ]);
  let supabaseHost = null;
  try {
    supabaseHost = new URL(SUPABASE_URL).host;
  } catch {}

  const body = {
    timestamp: new Date().toISOString(),
    environment: {
      vercel_env: process.env.VERCEL_ENV ?? null,
      vercel_region: process.env.VERCEL_REGION ?? null,
      supabase_url_host: supabaseHost,
    },
    server_credential: { ...server.info, access: serverAccess, database_identity: serverDbIdentity },
    end_user: endUser,
  };
  res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body, null, 2));
}

const server = http.createServer(async (req, res) => {
  const path = req.url.split('?')[0];
  if (path === '/api/diagnostics' && req.method === 'GET') {
    try {
      await handleDiagnostics(req, res);
    } catch (error) {
      console.error('Diagnostics error:', error);
      res.writeHead(500, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ error: error.message }));
    }
  } else if (req.url === '/api/countries' && req.method === 'GET') {
    try {
      const { client: supabase, error: credentialError } = await resolveServerCredential(req);
      if (credentialError) throw credentialError;
      const { data: rows, error } = await supabase
        .from('countries')
        .select('name')
        .order('name');
      if (error) throw error;
      const html = `
        <!DOCTYPE html>
        <html>
          <head>
            <title>Countries</title>
            <style>
              body { font-family: Arial, sans-serif; padding: 20px; }
              table { border-collapse: collapse; width: 100%; max-width: 600px; }
              th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
              th { background-color: #f2f2f2; }
            </style>
          </head>
          <body>
            <h1>Countries</h1>
            <table>
              <thead>
                <tr><th>Name</th></tr>
              </thead>
              <tbody>
                ${rows.map(row => `<tr><td>${row.name}</td></tr>`).join('')}
              </tbody>
            </table>
          </body>
        </html>
      `;
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(html);
    } catch (error) {
      console.error('Database query error:', error);
      res.writeHead(500, { 'Content-Type': 'text/html' });
      res.end(`<h1>Error</h1><p>${error.message}</p>`);
    }
  } else {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<h1>hhello    world!!!!1 wooo!!1!!</h1>');
  }
});

server.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
