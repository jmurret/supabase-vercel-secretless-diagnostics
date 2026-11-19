const crypto = require('crypto');

// Expectations from "Vercel Marketplace OIDC" (Vercel OIDC secretless spec, Nov 18).
const SPEC = 'Vercel Marketplace OIDC (spec updated Nov 18)';
const EXPECTED_ROLE = 'authenticated';
const MAX_TTL_S = 15 * 60;
const CLOCK_TOLERANCE_S = 60;
const MAX_PAYLOAD_BYTES = 4096;
const REQUIRED_RESOURCE_CLAIMS = ['aud', 'sub', 'act', 'iat', 'nbf', 'exp'];
const OIDC_ISS_RE = /^https:\/\/oidc\.vercel\.com(\/[^/]+)?$/;
const RESOURCE_ISS_RE = /^https:\/\/integrations\.vercel\.com\/(oac_[A-Za-z0-9]+)$/;
const JWKS_MAX_AGE_MS = 60 * 60 * 1000;
const STATIC_SECRET_ENV_VARS = [
  'SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_SECRET_KEY', 'SUPABASE_ANON_KEY', 'NEXT_PUBLIC_SUPABASE_ANON_KEY',
];

const MINT_ERROR_HINTS = {
  not_found: "No matching resource is connected to this project for the deployment's environment.",
  invalid_resource: 'The resource id is empty or malformed; check MARKETPLACE_RESOURCE_ID.',
  invalid_role: "The resource doesn't define the requested role (or defines no roles).",
  forbidden: "The caller isn't a Vercel deployment OIDC token, or can't read the project's integration resources.",
  ambiguous_resource: 'The project has two resources of this product with the same prefix; change one prefix.',
  resource_oidc_not_enabled: "The resource's credentialTypes doesn't include \"oidc\".",
  resource_claims_too_large: 'The resolved token payload exceeds 4 KB; trim customClaims.',
};

function decodeJwtPart(token, index) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    return JSON.parse(Buffer.from(parts[index], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

const result = (status, expected = null, actual = null, detail = null) => ({ status, expected, actual, detail });
const pass = (expected, actual, detail) => result('pass', expected, actual, detail);
const warn = (expected, actual, detail) => result('warn', expected, actual, detail);
const fail = (expected, actual, detail) => result('fail', expected, actual, detail);
const skip = (detail) => result('skip', null, null, detail);

const jwksCache = new Map();

async function fetchJwks(url, fetchImpl, now) {
  const cached = jwksCache.get(url);
  if (cached && cached.expiresAt > now) return cached.keys;
  const res = await fetchImpl(url);
  if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
  const { keys } = await res.json();
  const maxAge = /max-age=(\d+)/.exec(res.headers?.get?.('cache-control') || '');
  const ttl = Math.min(maxAge ? Number(maxAge[1]) * 1000 : JWKS_MAX_AGE_MS, JWKS_MAX_AGE_MS);
  jwksCache.set(url, { keys: keys || [], expiresAt: now + ttl });
  return keys || [];
}

async function verifySignature(token, iss, fetchImpl, now) {
  const header = decodeJwtPart(token, 0);
  const url = `${iss}/jwks.json`;
  let keys = await fetchJwks(url, fetchImpl, now);
  let jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) {
    // Spec: refresh on unknown kid.
    jwksCache.delete(url);
    keys = await fetchJwks(url, fetchImpl, now);
    jwk = keys.find((k) => k.kid === header.kid);
  }
  if (!jwk) return fail(`kid in ${url}`, header.kid, 'No published key matches the token kid.');
  const [h, p, s] = token.split('.');
  const ok = crypto.verify(
    'RSA-SHA256',
    Buffer.from(`${h}.${p}`),
    crypto.createPublicKey({ key: jwk, format: 'jwk' }),
    Buffer.from(s, 'base64url')
  );
  return ok
    ? pass('valid RS256 signature', 'valid', `Verified with kid ${header.kid} from ${url}.`)
    : fail('valid RS256 signature', 'invalid', `Signature does not verify against kid ${header.kid}.`);
}

function parseMintErrorCode(body) {
  try {
    const parsed = JSON.parse(body);
    return parsed?.error?.code ?? parsed?.code ?? (typeof parsed?.error === 'string' ? parsed.error : null);
  } catch {
    return null;
  }
}

function buildContext(data, ctx, env, nowMs) {
  const sc = data.server_credential || {};
  const isOidcPath = sc.auth_path === 'vercel_oidc_marketplace';
  const oidcRaw = ctx?.oidcToken ? decodeJwtPart(ctx.oidcToken, 1) : null;
  const resRaw = ctx?.resourceToken ? decodeJwtPart(ctx.resourceToken, 1) : null;
  return {
    env,
    now: Math.floor(nowMs / 1000),
    nowMs,
    sc,
    isOidcPath,
    oidcHeader: sc.oidc?.jwt_header ?? null,
    oidc: oidcRaw ?? sc.oidc?.claims ?? null,
    minted: Boolean(ctx?.resourceToken),
    resHeader: sc.resource_token?.jwt_header ?? null,
    res: resRaw ?? sc.resource_token?.claims ?? null,
    resourceToken: ctx?.resourceToken ?? null,
    db: sc.database_identity ?? null,
  };
}

const notOidc = (c) => (c.isOidcPath ? null : skip('Not on the Vercel OIDC path.'));
const needOidc = (c) => notOidc(c) || (c.oidc ? null : skip('No Vercel OIDC token.'));
const needResource = (c) => notOidc(c) || (c.minted && c.res ? null : skip('No resource token was minted.'));
const needDb = (c) =>
  needResource(c) || (c.db && !c.db.skipped ? null : skip('database_identity was not queried.'));

const CHECKS = [
  {
    id: 'auth_path',
    group: 'path',
    description: 'Server talks to Supabase with a Vercel Marketplace OIDC resource token, not static keys',
    run: (c) =>
      c.isOidcPath
        ? pass('vercel_oidc_marketplace', c.sc.auth_path)
        : fail('vercel_oidc_marketplace', c.sc.auth_path ?? null, 'No Vercel OIDC token was found, so static integration keys were used.'),
  },
  {
    id: 'no_static_secret',
    group: 'path',
    description: 'No long-lived Supabase secret keys are present (oidc-only resources have no static secrets)',
    run: (c) => {
      const present = STATIC_SECRET_ENV_VARS.filter((n) => c.env[n]);
      const secret = present.filter((n) => n === 'SUPABASE_SERVICE_ROLE_KEY' || n === 'SUPABASE_SECRET_KEY' || c.env[n].startsWith('sb_secret_'));
      if (secret.length) return warn('no secret key env vars', secret, 'A service-role/secret key is still configured.');
      return pass('no secret key env vars', present.length ? `only public keys: ${present.join(', ')}` : 'none');
    },
  },
  {
    id: 'oidc_present',
    group: 'vercel_oidc',
    description: "Deployment's Vercel OIDC token is available (x-vercel-oidc-token or getVercelOidcToken)",
    run: (c) =>
      notOidc(c) ||
      (c.oidc ? pass('token present', c.sc.oidc?.source) : fail('token present', null, 'OIDC token could not be decoded.')),
  },
  {
    id: 'oidc_iss',
    group: 'vercel_oidc',
    description: 'OIDC token is issued by Vercel',
    run: (c) =>
      needOidc(c) ||
      (OIDC_ISS_RE.test(c.oidc.iss || '')
        ? pass('https://oidc.vercel.com[/<team>]', c.oidc.iss)
        : fail('https://oidc.vercel.com[/<team>]', c.oidc.iss ?? null)),
  },
  {
    id: 'oidc_alg_kid',
    group: 'vercel_oidc',
    description: 'OIDC token is RS256-signed with a kid',
    run: (c) =>
      needOidc(c) ||
      (c.oidcHeader?.alg === 'RS256' && c.oidcHeader?.kid
        ? pass({ alg: 'RS256', kid: 'present' }, c.oidcHeader)
        : fail({ alg: 'RS256', kid: 'present' }, c.oidcHeader)),
  },
  {
    id: 'oidc_not_expired',
    group: 'vercel_oidc',
    description: 'OIDC token is within its validity window (60 s tolerance)',
    run: (c) => {
      const s = needOidc(c);
      if (s) return s;
      const { exp, nbf } = c.oidc;
      const actual = { exp, nbf: nbf ?? null, now: c.now };
      if (typeof exp !== 'number' || exp <= c.now - CLOCK_TOLERANCE_S) return fail('exp in the future', actual, 'Token is expired.');
      if (typeof nbf === 'number' && nbf > c.now + CLOCK_TOLERANCE_S) return fail('nbf not in the future', actual, `Token not valid for ${nbf - c.now}s (clock skew?).`);
      return pass('valid now', actual);
    },
  },
  {
    id: 'oidc_owner_project',
    group: 'vercel_oidc',
    description: 'OIDC token identifies owner, project and environment, matching VERCEL_ENV',
    run: (c) => {
      const s = needOidc(c);
      if (s) return s;
      const { owner, project, environment } = c.oidc;
      const actual = { owner: owner ?? null, project: project ?? null, environment: environment ?? null };
      const missing = Object.keys(actual).filter((k) => !actual[k]);
      if (missing.length) return fail('owner, project, environment present', actual, `Missing: ${missing.join(', ')}.`);
      if (c.env.VERCEL_ENV && environment !== c.env.VERCEL_ENV) {
        return warn({ environment: c.env.VERCEL_ENV }, actual, 'Token environment differs from VERCEL_ENV.');
      }
      return pass('owner, project, environment present', actual);
    },
  },
  {
    id: 'mint_ok',
    group: 'mint',
    description: 'Vercel minted a Marketplace resource token for MARKETPLACE_RESOURCE_ID',
    run: (c) => {
      const s = needOidc(c);
      if (s) return s;
      const rt = c.sc.resource_token || {};
      if (c.minted) return pass('token minted', { resource_id: rt.resource_id, cached: rt.cached ?? false });
      const code = parseMintErrorCode(rt.response_body);
      const hint = MINT_ERROR_HINTS[code] ?? rt.error ?? 'Mint failed.';
      return fail('token minted', { resource_id: rt.resource_id ?? null, status: rt.status ?? null, code }, hint);
    },
  },
  {
    id: 'resource_alg_kid',
    group: 'resource_token',
    description: 'Resource token is RS256-signed with a kid (only RS256 is used by Vercel)',
    run: (c) =>
      needResource(c) ||
      (c.resHeader?.alg === 'RS256' && c.resHeader?.kid
        ? pass({ alg: 'RS256', kid: 'present' }, c.resHeader)
        : fail({ alg: 'RS256', kid: 'present' }, c.resHeader)),
  },
  {
    id: 'resource_required_claims',
    group: 'resource_token',
    description: 'Resource token has the required claims aud, sub, act, iat, nbf, exp',
    run: (c) => {
      const s = needResource(c);
      if (s) return s;
      const missing = REQUIRED_RESOURCE_CLAIMS.filter((k) => c.res[k] === undefined);
      return missing.length
        ? fail(REQUIRED_RESOURCE_CLAIMS, Object.keys(c.res), `Missing: ${missing.join(', ')}.`)
        : pass(REQUIRED_RESOURCE_CLAIMS, 'all present');
    },
  },
  {
    id: 'resource_iss',
    group: 'resource_token',
    description: 'Resource token is issued by our Vercel integration',
    run: (c) => {
      const s = needResource(c);
      if (s) return s;
      const id = c.env.VERCEL_INTEGRATION_ID;
      if (id) {
        const expected = `https://integrations.vercel.com/${id}`;
        return c.res.iss === expected ? pass(expected, c.res.iss) : fail(expected, c.res.iss ?? null);
      }
      return RESOURCE_ISS_RE.test(c.res.iss || '')
        ? warn('https://integrations.vercel.com/<VERCEL_INTEGRATION_ID>', c.res.iss, 'Format OK; set VERCEL_INTEGRATION_ID to check the exact issuer.')
        : fail('https://integrations.vercel.com/oac_…', c.res.iss ?? null);
    },
  },
  {
    id: 'resource_aud',
    group: 'resource_token',
    description: 'Resource token audience is our integration installation',
    run: (c) => {
      const s = needResource(c);
      if (s) return s;
      const expected = c.env.VERCEL_INTEGRATION_INSTALLATION_ID;
      if (expected) return c.res.aud === expected ? pass(expected, c.res.aud) : fail(expected, c.res.aud ?? null);
      return typeof c.res.aud === 'string' && c.res.aud.startsWith('icfg_')
        ? warn('<VERCEL_INTEGRATION_INSTALLATION_ID>', c.res.aud, 'Format OK; set VERCEL_INTEGRATION_INSTALLATION_ID to check the exact installation.')
        : fail('icfg_…', c.res.aud ?? null);
    },
  },
  {
    id: 'resource_sub',
    group: 'resource_token',
    description: 'Resource token subject is the Supabase resource being accessed',
    run: (c) => {
      const s = needResource(c);
      if (s) return s;
      const expected = c.env.SUPABASE_RESOURCE_ID;
      if (!c.res.sub) return fail(expected ?? 'present', null);
      if (expected) return c.res.sub === expected ? pass(expected, c.res.sub) : fail(expected, c.res.sub);
      return warn('<SUPABASE_RESOURCE_ID>', c.res.sub, 'Set SUPABASE_RESOURCE_ID to check the exact resource.');
    },
  },
  {
    id: 'resource_role',
    group: 'resource_token',
    description: `Resource token role is "${EXPECTED_ROLE}"`,
    run: (c) => {
      const s = needResource(c);
      if (s) return s;
      if (c.res.role === undefined) {
        return fail(EXPECTED_ROLE, null, "No role claim: define roles/defaultRole in the resource's customClaims. Without it Supabase runs as anon.");
      }
      return c.res.role === EXPECTED_ROLE ? pass(EXPECTED_ROLE, c.res.role) : fail(EXPECTED_ROLE, c.res.role);
    },
  },
  {
    id: 'resource_act',
    group: 'resource_token',
    description: 'Resource token act.sub identifies this deployment (matches the OIDC token sub)',
    run: (c) => {
      const s = needResource(c);
      if (s) return s;
      const actSub = c.res.act?.sub ?? null;
      const expected = c.oidc?.sub ?? 'owner:<team>:project:<project>:environment:<env>';
      if (!actSub) return fail(expected, null, 'act.sub is missing.');
      if (c.oidc?.sub && actSub !== c.oidc.sub) return fail(expected, actSub, 'act.sub differs from the deployment OIDC sub.');
      const env = /:environment:([^:]+)$/.exec(actSub)?.[1];
      if (c.res.environment && env && env !== c.res.environment) {
        return fail(expected, actSub, `act environment "${env}" differs from environment claim "${c.res.environment}".`);
      }
      return pass(expected, actSub);
    },
  },
  {
    id: 'resource_environment',
    group: 'resource_token',
    description: 'Resource token environment matches the deployment environment',
    run: (c) => {
      const s = needResource(c);
      if (s) return s;
      const expected = c.oidc?.environment ?? c.env.VERCEL_ENV ?? null;
      if (!c.res.environment) return warn(expected, null, 'environment claim is absent (it can be removed via customClaims).');
      if (expected && c.res.environment !== expected) return warn(expected, c.res.environment);
      return pass(expected, c.res.environment);
    },
  },
  {
    id: 'resource_time',
    group: 'resource_token',
    description: 'Resource token is within nbf/exp (60 s tolerance)',
    run: (c) => {
      const s = needResource(c);
      if (s) return s;
      const { nbf, exp } = c.res;
      const actual = { nbf: nbf ?? null, exp: exp ?? null, now: c.now };
      if (typeof exp !== 'number' || exp <= c.now - CLOCK_TOLERANCE_S) return fail('exp in the future', actual, 'Token is expired.');
      if (typeof nbf === 'number' && nbf > c.now + CLOCK_TOLERANCE_S) {
        return fail('nbf <= now + 60s', actual, `Token not valid for ${nbf - c.now}s (clock skew?).`);
      }
      return pass('valid now', actual);
    },
  },
  {
    id: 'resource_lifetime',
    group: 'resource_token',
    description: 'Resource token lifetime is at most 15 minutes',
    run: (c) => {
      const s = needResource(c);
      if (s) return s;
      const { iat, exp } = c.res;
      if (typeof iat !== 'number' || typeof exp !== 'number') return warn(`<= ${MAX_TTL_S}s`, null, 'iat or exp missing.');
      const ttl = exp - iat;
      return ttl <= MAX_TTL_S ? pass(`<= ${MAX_TTL_S}s`, `${ttl}s`) : warn(`<= ${MAX_TTL_S}s`, `${ttl}s`);
    },
  },
  {
    id: 'resource_size',
    group: 'resource_token',
    description: 'Resource token payload fits within 4 KB',
    run: (c) => {
      const s = needResource(c);
      if (s) return s;
      if (!c.resourceToken) return skip('Raw token unavailable.');
      const bytes = c.resourceToken.split('.')[1].length;
      return bytes <= MAX_PAYLOAD_BYTES ? pass(`<= ${MAX_PAYLOAD_BYTES} bytes`, bytes) : warn(`<= ${MAX_PAYLOAD_BYTES} bytes`, bytes);
    },
  },
  {
    id: 'resource_signature',
    group: 'resource_token',
    description: "Resource token signature verifies against the integration's published JWKS",
    run: async (c, { fetchImpl }) => {
      const s = needResource(c);
      if (s) return s;
      if (!c.resourceToken) return skip('Raw token unavailable.');
      if (!RESOURCE_ISS_RE.test(c.res.iss || '')) return skip('iss is not a Vercel integration issuer; not fetching its JWKS.');
      if (c.resHeader?.alg !== 'RS256' || !c.resHeader?.kid) return fail('RS256 with kid', c.resHeader);
      try {
        return await verifySignature(c.resourceToken, c.res.iss, fetchImpl, c.nowMs);
      } catch (err) {
        return fail('valid RS256 signature', null, err.message);
      }
    },
  },
  {
    id: 'db_accepted',
    group: 'database',
    description: 'Supabase accepted the resource token',
    run: (c) => {
      const s = needDb(c);
      if (s) return s;
      if (!c.db.error) return pass('accepted', 'accepted');
      const detail =
        c.db.error_code === 'PGRST301'
          ? `Supabase has no key for this token. Add Third-Party Auth → Custom OIDC with issuer ${c.res.iss}.`
          : c.db.error;
      return fail('accepted', c.db.error_code ?? c.db.error, detail);
    },
  },
  {
    id: 'db_role',
    group: 'database',
    description: `Database request runs as "${EXPECTED_ROLE}"`,
    run: (c) => {
      const s = needDb(c);
      if (s) return s;
      if (c.db.error) return skip('Supabase rejected the token.');
      return c.db.current_user === EXPECTED_ROLE
        ? pass(EXPECTED_ROLE, c.db.current_user)
        : fail(EXPECTED_ROLE, c.db.current_user ?? null, c.db.current_user === 'anon' ? 'No role claim reached Supabase.' : null);
    },
  },
  {
    id: 'db_claims_match',
    group: 'database',
    description: 'Claims seen by the database match the minted token (iss, sub, aud, role)',
    run: (c) => {
      const s = needDb(c);
      if (s) return s;
      if (c.db.error) return skip('Supabase rejected the token.');
      const dbClaims = c.db.jwt_claims || {};
      const keys = ['iss', 'sub', 'aud', 'role'];
      const expected = Object.fromEntries(keys.map((k) => [k, c.res[k] ?? null]));
      const actual = Object.fromEntries(keys.map((k) => [k, dbClaims[k] ?? null]));
      const diff = keys.filter((k) => JSON.stringify(expected[k]) !== JSON.stringify(actual[k]));
      return diff.length ? fail(expected, actual, `Mismatch: ${diff.join(', ')}.`) : pass(expected, actual);
    },
  },
  {
    id: 'db_no_rls_bypass',
    group: 'database',
    description: 'Database role does not bypass RLS',
    run: (c) => {
      const s = needDb(c);
      if (s) return s;
      if (c.db.error) return skip('Supabase rejected the token.');
      return c.db.bypasses_rls === false ? pass(false, false) : fail(false, c.db.bypasses_rls ?? null);
    },
  },
];

async function runChecks(data, ctx, { env = process.env, now = Date.now, fetchImpl = fetch } = {}) {
  const c = buildContext(data, ctx, env, now());
  const results = [];
  for (const check of CHECKS) {
    let outcome;
    try {
      outcome = await check.run(c, { fetchImpl });
    } catch (err) {
      outcome = fail(null, null, `Check errored: ${err.message}`);
    }
    results.push({ id: check.id, group: check.group, description: check.description, ...outcome });
  }
  const count = (st) => results.filter((r) => r.status === st).length;
  const summary = { passed: count('pass'), warned: count('warn'), failed: count('fail'), skipped: count('skip') };
  summary.status = summary.failed ? 'fail' : summary.warned ? 'warn' : 'pass';
  return { spec: SPEC, summary: { status: summary.status, ...summary }, results };
}

module.exports = { runChecks };
