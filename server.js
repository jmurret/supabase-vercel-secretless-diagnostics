const http = require('http');
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
const KEY_ENV_VARS = ['SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_ANON_KEY', 'NEXT_PUBLIC_SUPABASE_ANON_KEY'];
const ANON_KEY_ENV_VARS = ['SUPABASE_ANON_KEY', 'NEXT_PUBLIC_SUPABASE_ANON_KEY'];
const PROBE_TABLES = ['countries'];
const SAFE_CLAIMS = [
  'iss', 'sub', 'aud', 'role', 'exp', 'iat', 'nbf', 'email', 'scope', 'aal', 'is_anonymous',
  'owner', 'owner_id', 'project', 'project_id', 'environment', 'user_id',
];
const CLIENT_OPTIONS = { auth: { persistSession: false, autoRefreshToken: false } };

function firstEnv(names) {
  const name = names.find((n) => process.env[n]);
  return name ? { name, value: process.env[name] } : null;
}

function decodeJwt(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
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

function getOidcToken(req) {
  const header = req?.headers['x-vercel-oidc-token'];
  if (header) return { token: header, source: 'header' };
  if (process.env.VERCEL_OIDC_TOKEN) return { token: process.env.VERCEL_OIDC_TOKEN, source: 'env' };
  return null;
}

// Uses the Vercel OIDC token (via Supabase third-party auth) when present, otherwise the
// Supabase keys injected by the Vercel integration.
function resolveServerCredential(req) {
  const oidc = getOidcToken(req);
  if (oidc) {
    const anonKey = firstEnv(ANON_KEY_ENV_VARS) || firstEnv(KEY_ENV_VARS);
    const token = oidc.token;
    return {
      client: createClient(SUPABASE_URL, anonKey?.value, {
        ...CLIENT_OPTIONS,
        accessToken: async () => token,
      }),
      info: {
        auth_path: 'vercel_oidc',
        oidc_source: oidc.source,
        apikey_env_var: anonKey?.name ?? null,
        claims: safeClaims(decodeJwt(token)),
      },
    };
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
    const { data, error } = await client.rpc('whoami');
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
  const result = { present: true, claims: safeClaims(decodeJwt(jwt)) };

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
  const server = resolveServerCredential(req);
  const [serverAccess, serverDbIdentity, endUser] = await Promise.all([
    probeAccess(server.client),
    dbWhoami(server.client),
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
      const { client: supabase } = resolveServerCredential(req);
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
