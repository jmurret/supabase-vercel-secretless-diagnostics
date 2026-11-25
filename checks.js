const crypto = require('crypto');
const { RESYNC_HINT } = require('./pooler');
const {
  SERVICES: CROSS_TENANT_SERVICES, JIT_PROBES, evaluateService, describeVariants, evaluateJitProbe, gatewayCoverage,
} = require('./cross-tenant');
const { FORWARD_HEADER, VARIANTS, notForwardedReason, isForwarded, worstStatus } = require('./gateway-variants');

// Expectations from "Vercel Marketplace OIDC" (Vercel OIDC secretless spec, Nov 18).
const SPEC = 'Vercel Marketplace OIDC (spec updated Nov 18)';
const EXPECTED_ROLE = 'service_role';
// service_role has BYPASSRLS in Supabase; any other role must not bypass RLS.
const EXPECTED_BYPASS_RLS = EXPECTED_ROLE === 'service_role';
const MAX_TTL_S = 15 * 60;
const CLOCK_TOLERANCE_S = 60;
const MAX_PAYLOAD_BYTES = 4096;
const REQUIRED_RESOURCE_CLAIMS = ['aud', 'sub', 'act', 'iat', 'nbf', 'exp'];
const OIDC_ISS_RE = /^https:\/\/oidc\.vercel\.com(\/[^/]+)?$/;
const RESOURCE_ISS_RE = /^https:\/\/integrations\.vercel\.com\/(oac_[A-Za-z0-9]+)$/;
const JWKS_MAX_AGE_MS = 60 * 60 * 1000;
const SECRET_ENV_VARS = ['SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_SECRET_KEY', 'SUPABASE_JWT_SECRET'];
const STATIC_SECRET_ENV_VARS = [
  ...SECRET_ENV_VARS, 'SUPABASE_ANON_KEY', 'NEXT_PUBLIC_SUPABASE_ANON_KEY',
  'SUPABASE_PUBLISHABLE_KEY', 'NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY',
];
// These carry the static database password; OIDC-only resources must not get them.
const POSTGRES_SECRET_ENV_VARS = ['POSTGRES_URL', 'POSTGRES_PRISMA_URL', 'POSTGRES_URL_NON_POOLING', 'POSTGRES_PASSWORD'];
const RESOURCE_ID_RE = /^(store|ir)_/;
const HOSTNAME_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i;
const PROJECT_REF_RE = /^[a-z]{20}$/;
const JIT_ROLE = 'postgres';
const MISSING_RELATION_CODES = ['PGRST205', '42P01'];
const MISSING_FUNCTION_CODES = ['PGRST202', '42883'];

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

function isSecretValue(value) {
  if (typeof value !== 'string') return false;
  if (value.startsWith('sb_secret_')) return true;
  return decodeJwtPart(value, 1)?.role === 'service_role';
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
    url: data.environment?.supabase_url ?? null,
    controls: sc.controls ?? null,
    jit: data.jit ?? null,
    crossTenant: data.cross_tenant ?? null,
    crossTenantS3: data.cross_tenant_s3 ?? null,
    gatewayV2: data.gateway_v2 ?? null,
  };
}

const notOidc = (c) => (c.isOidcPath ? null : skip('Not on the Vercel OIDC path.'));
const needOidc = (c) => notOidc(c) || (c.oidc ? null : skip('No Vercel OIDC token.'));
const needResource = (c) => notOidc(c) || (c.minted && c.res ? null : skip('No resource token was minted.'));
const needDb = (c) =>
  needResource(c) || (c.db && !c.db.skipped ? null : skip('database_identity was not queried.'));

const isSkipped = (r) => !r || r.skipped;

// The JIT checks use a separate token minted with role JIT_ROLE. They fail when that mint failed.
const needJitToken = (c) => {
  const s = needResource(c);
  if (s) return s;
  const t = c.jit?.resource_token;
  if (t?.error) {
    return fail(`JIT token with role ${JIT_ROLE}`, { status: t.status ?? null, error: t.error, response_body: t.response_body ?? null },
      `The token with role ${JIT_ROLE} could not be minted.`);
  }
  return null;
};

const JIT_HINT = 'Check that JIT access is enabled: run `pnpm run enable-jit`.';
const CTRL_2151_HINT = 'Known issue CTRL-2151: the pooler needs `--jit=true`. Existing clients send this option, so this is a warning, not a failure.';
const JIT_ROLE_MISMATCH = 'Token role does not match requested role';
const JIT_ROLE_HINT = `The token role must equal the requested JIT role. Mint the token with ?role=${JIT_ROLE}.`;
const jitApiHint = (r) => (r.status === 403 && r.error?.includes(JIT_ROLE_MISMATCH) ? JIT_ROLE_HINT : JIT_HINT);
const needCrossTenant = (c, ct = c.crossTenant) => {
  if (!ct) return skip('Cross-tenant probes were not run.');
  if (ct.skipped) return skip(ct.skipped);
  return null;
};
const needCrossTenantTargets = (c, ct = c.crossTenant) =>
  needCrossTenant(c, ct) || (ct.targets.length ? null : skip('No valid cross-tenant targets; see cross_tenant_targets.'));

function crossTenantServiceCheck(service) {
  const onGateways = service.noGateway ? '' : ' on api-gateway v1 and v2';
  return {
    id: `cross_tenant_${service.id}`,
    group: 'cross_tenant',
    description: `${service.label} on other tenants rejects this tenant's default-role resource token${onGateways} (${service.request ?? `${service.method} ${service.path}`})`,
    run: (c) => {
      const ct = service.regional ? c.crossTenantS3 : c.crossTenant;
      const s = needCrossTenantTargets(c, ct);
      if (s) return s;
      const { rows, accepted, inconclusive } = evaluateService(ct, service);
      const expected = `${service.expected} from every target${onGateways}`;
      const ownRef = ct.own.ref;
      if (service.noGateway) {
        if (accepted.length) {
          return fail(expected, rows, accepted
            .map((r) => `regression: ${service.label} on ${r.target} (gateway ${r.gateway_version}) accepted tenant ${ownRef}'s token`)
            .join('; '));
        }
        if (inconclusive.length) {
          return warn(expected, rows, `Inconclusive: ${inconclusive.map((r) => `${r.target}: ${r.reason}`).join('; ')}`);
        }
        return pass(expected, rows);
      }
      if (accepted.length) {
        return fail(expected, rows, accepted
          .map((r) => `regression: ${service.label} on ${r.target} accepted tenant ${ownRef}'s token (${describeVariants(r)})`)
          .join('; '));
      }
      const outcomes = (list) => list.map((r) => `${r.target}: ${describeVariants(r)}`).join('; ');
      if (inconclusive.length) return warn(expected, rows, `Inconclusive: ${outcomes(inconclusive)}`);
      return pass(expected, rows, outcomes(rows));
    },
  };
}

function crossTenantJitCheck(probe) {
  return {
    id: `cross_tenant_${probe.id}`,
    group: 'cross_tenant',
    description: probe.description,
    run: (c) => {
      const s = needCrossTenantTargets(c);
      if (s) return s;
      const evaluated = evaluateJitProbe(c.crossTenant, c.jit, probe);
      if (evaluated.skipped) return skip(evaluated.skipped);
      const { rows, accepted, inconclusive } = evaluated;
      const ownRef = c.crossTenant.own.ref;
      const note = (r) => (r.note ? ` (${r.note})` : '');
      if (accepted.length) {
        return fail(probe.expected, rows, accepted
          .map((r) => `regression: ${probe.label} on ${r.target} accepted tenant ${ownRef}'s JIT token${note(r)}`)
          .join('; '));
      }
      if (inconclusive.length) {
        return warn(probe.expected, rows, `Inconclusive: ${inconclusive.map((r) => `${r.target}: ${r.reason}${note(r)}`).join('; ')}`);
      }
      const notes = rows.filter((r) => r.note).map((r) => `${r.target}: ${r.note}`).join('; ');
      return pass(probe.expected, rows, notes || undefined);
    },
  };
}

const NO_ROUTE_CODES =['ENETUNREACH', 'EHOSTUNREACH', 'EADDRNOTAVAIL', 'ETIMEDOUT'];
const isAuthFailure = (r) => r.code === '28P01' || /password authentication failed/.test(r.error);
const isNoRoute = (r) => NO_ROUTE_CODES.includes(r.code) || r.error === 'timeout expired';

const CHECKS = [
  {
    id: 'supabase_url',
    group: 'config',
    description: 'SUPABASE_URL (or NEXT_PUBLIC_SUPABASE_URL) is set to a valid URL',
    run: (c) => {
      if (!c.url?.env_var) return fail('set', null, 'Set SUPABASE_URL (or NEXT_PUBLIC_SUPABASE_URL).');
      if (!c.url.valid) return fail('valid URL', c.url.env_var, 'Set it to https://<project ref>.supabase.co.');
      return pass('valid URL', { env_var: c.url.env_var, host: c.url.host, project_ref: c.url.project_ref });
    },
  },
  {
    id: 'apikey_public',
    group: 'config',
    description: 'The apikey header carries only a publishable or anon key (the token sets the role)',
    run: (c) => {
      const s = notOidc(c);
      if (s) return s;
      const k = c.sc.apikey;
      const expected = 'publishable or anon key';
      if (!k) return fail(expected, null, 'Set SUPABASE_PUBLISHABLE_KEY to the project\'s publishable key (it is a public key).');
      if (k.key_format === 'sb_secret' || k.role === 'service_role') {
        return fail(expected, k, `${k.env_var} holds a secret key; put the publishable key there and remove the secret.`);
      }
      if (k.key_format === 'unknown') return warn(expected, k, 'Unrecognized key format.');
      return pass(expected, k);
    },
  },
  {
    id: 'resource_id',
    group: 'config',
    description: 'MARKETPLACE_RESOURCE_ID is set to a Vercel resource id (store_… or ir_…)',
    run: (c) => {
      const s = notOidc(c);
      if (s) return s;
      const id = c.env.MARKETPLACE_RESOURCE_ID;
      const hint = 'Find it in the Vercel dashboard under Storage → the Supabase resource; the id is in the page URL.';
      if (!id) return fail('store_… or ir_…', null, `MARKETPLACE_RESOURCE_ID is not set. ${hint}`);
      return RESOURCE_ID_RE.test(id) ? pass('store_… or ir_…', id) : warn('store_… or ir_…', id, hint);
    },
  },
  {
    id: 'pooler_host',
    group: 'config',
    description: 'POSTGRES_POOLER_HOST is set to a pooler host name (no scheme, port or path)',
    run: (c) => {
      const host = c.env.POSTGRES_POOLER_HOST;
      const expected = '<provider>-<cluster>-<region>.pooler.<domain>';
      if (!host) return fail(expected, null, `POSTGRES_POOLER_HOST is not set. ${RESYNC_HINT}`);
      if (!HOSTNAME_RE.test(host)) return fail(expected, host, 'Set it to the host name only, without a scheme, port or path.');
      if (!host.includes('.pooler.')) return fail(expected, host, 'The host name does not contain ".pooler.".');
      return pass(expected, host);
    },
  },
  {
    id: 'project_ref',
    group: 'config',
    description: 'SUPABASE_PROJECT_REF is set to a project ref that matches SUPABASE_URL',
    run: (c) => {
      const ref = c.env.SUPABASE_PROJECT_REF;
      const urlRef = c.url?.project_ref ?? null;
      const expected = urlRef ?? '20 lowercase letters';
      if (!ref) return fail(expected, null, `SUPABASE_PROJECT_REF is not set. ${RESYNC_HINT}`);
      if (!PROJECT_REF_RE.test(ref)) return fail(expected, ref, 'A project ref is 20 lowercase letters.');
      if (!urlRef) return warn(expected, ref, 'SUPABASE_URL is not a <ref>.supabase.co host, so the ref cannot be compared.');
      return ref === urlRef
        ? pass(expected, ref)
        : fail(expected, ref, 'SUPABASE_PROJECT_REF and SUPABASE_URL point to different Supabase projects.');
    },
  },
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
    description: 'No long-lived Supabase secret keys or Postgres passwords are present (oidc-only resources have no static secrets)',
    run: (c) => {
      const present = STATIC_SECRET_ENV_VARS.filter((n) => c.env[n]);
      // Names only; also catches secret keys stored under other env var names.
      const secret = [...new Set([
        ...SECRET_ENV_VARS.filter((n) => c.env[n]),
        ...Object.keys(c.env).filter((n) => isSecretValue(c.env[n])),
      ])].sort();
      const postgres = POSTGRES_SECRET_ENV_VARS.filter((n) => c.env[n]);
      if (postgres.length) {
        return fail('no secret key env vars', [...secret, ...postgres],
          `Static database password env vars are set: ${postgres.join(', ')}. OIDC-only resources do not get them; remove them from the Vercel project.`);
      }
      if (secret.length) return warn('no secret key env vars', secret, 'A service-role/secret key or JWT secret is still configured.');
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
    id: 'oidc_team',
    group: 'vercel_oidc',
    description: 'VERCEL_TEAM_ID, if set, matches the OIDC token owner_id',
    run: (c) => {
      const s = needOidc(c);
      if (s) return s;
      const team = c.env.VERCEL_TEAM_ID;
      if (!team) return skip('VERCEL_TEAM_ID is not set.');
      if (!c.oidc.owner_id) return warn(team, null, 'OIDC token has no owner_id claim.');
      return team === c.oidc.owner_id
        ? pass(team, c.oidc.owner_id)
        : warn(team, c.oidc.owner_id, 'Remove VERCEL_TEAM_ID, or set it to the team that owns the resource.');
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
    id: 'resource_sub_project',
    group: 'resource_token',
    description: 'Resource token subject is the project ref in SUPABASE_URL',
    run: (c) => {
      const s = needResource(c);
      if (s) return s;
      const ref = c.url?.project_ref;
      if (!ref) return skip('SUPABASE_URL is not a <ref>.supabase.co host (custom domain?).');
      return c.res.sub === ref
        ? pass(ref, c.res.sub)
        : fail(ref, c.res.sub ?? null, 'MARKETPLACE_RESOURCE_ID and SUPABASE_URL point to different Supabase projects.');
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
    id: 'gateway_v2_forwarding',
    group: 'path',
    description: `Requests with the ${FORWARD_HEADER} header reach api-gateway v2 (from the sb-gateway-version response header)`,
    run: (c) => {
      const versions = c.gatewayV2?.gateway_versions;
      if (!versions || !Object.keys(versions).length) return skip('No api-gateway v2 requests were sent.');
      const missed = Object.entries(versions).filter(([, version]) => !isForwarded('v2', version));
      if (!missed.length) return pass('v2', versions);
      return warn('v2', versions,
        `Not forwarded to api-gateway v2: ${missed.map(([name, version]) => `${name} (${version === 'loop' ? 'forwarding loop between v1 and v2' : `answered by ${version}`})`).join(', ')}. The v2 results of the database checks are inconclusive. Staging can have no forwarding configured.`);
    },
  },
  {
    id: 'db_accepted',
    group: 'database',
    gateway: ['database_identity'],
    description: 'Supabase accepted the resource token',
    run: (c) => {
      const s = needDb(c);
      if (s) return s;
      if (!c.db.error) return pass('accepted', 'accepted');
      const detail =
        c.db.error_code === 'PGRST301'
          ? `Supabase has no key for this token. Add Third-Party Auth → Custom OIDC with issuer ${c.res.iss}.`
          : MISSING_FUNCTION_CODES.includes(c.db.error_code)
            ? 'public.whoami_vercel() does not exist; apply the migration in supabase/migrations.'
            : c.db.error;
      return fail('accepted', c.db.error_code ?? c.db.error, detail);
    },
  },
  {
    id: 'db_role',
    group: 'database',
    gateway: ['database_identity'],
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
    gateway: ['database_identity'],
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
    id: 'db_rls_bypass',
    group: 'database',
    gateway: ['database_identity'],
    description: `Database role ${EXPECTED_BYPASS_RLS ? 'bypasses' : 'does not bypass'} RLS, as expected for "${EXPECTED_ROLE}"`,
    run: (c) => {
      const s = needDb(c);
      if (s) return s;
      if (c.db.error) return skip('Supabase rejected the token.');
      return c.db.bypasses_rls === EXPECTED_BYPASS_RLS
        ? pass(EXPECTED_BYPASS_RLS, c.db.bypasses_rls)
        : fail(EXPECTED_BYPASS_RLS, c.db.bypasses_rls ?? null);
    },
  },
  {
    id: 'db_table_access',
    group: 'database',
    gateway: ['access'],
    description: 'Probe tables (public.countries) can be read with the resource token',
    run: (c) => {
      const s = needResource(c);
      if (s) return s;
      const access = c.sc.access;
      if (!Array.isArray(access)) return skip(access?.skipped ?? 'Tables were not probed.');
      const denied = access.filter((t) => !t.allowed);
      const actual = Object.fromEntries(access.map((t) => [t.table, t.allowed ? `${t.row_count} rows` : t.error_code ?? t.error]));
      if (!denied.length) return pass('readable', actual);
      const missing = denied.filter((t) => MISSING_RELATION_CODES.includes(t.error_code)).map((t) => `public.${t.table}`);
      return fail('readable', actual, missing.length ? `Missing: ${missing.join(', ')}; create it.` : denied[0].error);
    },
  },
  {
    id: 'db_anon_control',
    group: 'database',
    gateway: ['apikey_only', 'database_identity'],
    description: 'Control: without the resource token (apikey only) the request runs as anon',
    run: (c) => {
      const s = needDb(c);
      if (s) return s;
      const r = c.controls?.apikey_only;
      if (isSkipped(r)) return skip(r?.skipped ?? 'Control was not run.');
      if (r.error) return fail('anon', r.error_code ?? r.error, r.error);
      if (r.current_user !== 'anon') {
        return fail('anon', r.current_user ?? null, 'The apikey alone grants a non-anon role; use a publishable or anon key.');
      }
      if (!c.db.error && c.db.current_user === r.current_user) {
        return fail('differs from token role', r.current_user, 'Same role with and without the token, so the role is not coming from the token.');
      }
      return pass('anon', r.current_user);
    },
  },
  {
    id: 'db_tampered_rejected',
    group: 'database',
    gateway: ['tampered_token'],
    description: 'Control: Supabase rejects the resource token with a tampered signature (401 PGRST301)',
    run: (c) => {
      const s = needResource(c);
      if (s) return s;
      const r = c.controls?.tampered_token;
      const expected = { status: 401, error_code: 'PGRST301' };
      if (isSkipped(r)) return skip(r?.skipped ?? 'Control was not run.');
      if (!r.error) return fail(expected, { accepted: true, current_user: r.current_user ?? null }, 'Supabase accepted a token with a broken signature.');
      const actual = { status: r.status ?? null, error_code: r.error_code ?? null };
      return actual.status === 401 && actual.error_code === 'PGRST301' ? pass(expected, actual) : fail(expected, actual, r.error);
    },
  },
  {
    id: 'jit_token_role',
    group: 'jit',
    description: `The JIT token is minted with ?role=${JIT_ROLE} and carries role ${JIT_ROLE}`,
    run: (c) => {
      const s = needJitToken(c);
      if (s) return s;
      const t = c.jit?.resource_token;
      if (!t || t.skipped) return skip(t?.skipped ?? 'No JIT token was minted.');
      const role = t.claims?.role ?? null;
      return role === JIT_ROLE
        ? pass(`role = ${JIT_ROLE}`, { role, expires_in_s: t.claims?.expires_in_s ?? null })
        : fail(`role = ${JIT_ROLE}`, { role }, 'Vercel did not issue the requested role. Check the allowed roles in the resource customClaims.');
    },
  },
  {
    id: 'jit_management_api',
    group: 'jit',
    description: `Management API grants JIT database access (${JIT_ROLE}) for the JIT token`,
    run: (c) => {
      const s = needJitToken(c);
      if (s) return s;
      const r = c.jit?.management_api;
      if (!r) return skip('JIT access was not requested.');
      if (r.skipped) return warn('HTTP 200', null, r.skipped);
      if (r.status === 200) return pass(`HTTP 200, role ${JIT_ROLE}`, { status: r.status, role: r.role ?? null, ms: r.ms });
      return fail(`HTTP 200, role ${JIT_ROLE}`, { status: r.status ?? null, error: r.error ?? null },
        jitApiHint(r));
    },
  },
  {
    id: 'jit_default_role_rejected',
    group: 'jit',
    description: `Management API rejects JIT access (${JIT_ROLE}) for the default-role (service_role) resource token`,
    run: (c) => {
      const s = needResource(c);
      if (s) return s;
      const r = c.jit?.management_api_default_role;
      const expected = `HTTP 403 "${JIT_ROLE_MISMATCH}"`;
      if (!r) return skip('JIT access was not requested with the default-role token.');
      if (r.skipped) return warn(expected, null, r.skipped);
      const actual = { status: r.status ?? null, error: r.error ?? null, ...(r.role && { role: r.role }) };
      if (r.status === 403 && r.error?.includes(JIT_ROLE_MISMATCH)) return pass(expected, actual);
      return fail(expected, actual, r.status === 200
        ? 'A token minted without ?role got JIT access. The Management API does not bind JIT to the token role claim.'
        : null);
    },
  },
  {
    id: 'jit_postgres_login',
    group: 'jit',
    description: `Postgres login through the pooler (POSTGRES_POOLER_HOST:6543, user ${JIT_ROLE}.<SUPABASE_PROJECT_REF>) with the JIT token as the password and the --jit=true option runs as ${JIT_ROLE}`,
    run: (c) => {
      const s = needJitToken(c);
      if (s) return s;
      const r = c.jit?.postgres_login;
      const expected = `current_user = ${JIT_ROLE}`;
      if (!r) return skip('Postgres login was not attempted.');
      if (r.skipped) return fail(expected, null, r.skipped);
      if (r.error) return fail(expected, { endpoint: r.endpoint, error: r.error }, JIT_HINT);
      return r.current_user === JIT_ROLE
        ? pass(expected, { endpoint: r.endpoint, current_user: r.current_user, ms: r.ms })
        : fail(expected, { endpoint: r.endpoint, current_user: r.current_user });
    },
  },
  {
    id: 'jit_postgres_login_no_jit',
    group: 'jit',
    description: `Postgres login through the pooler (POSTGRES_POOLER_HOST:6543) with the JIT token as the password and without the --jit=true option (CTRL-2151)`,
    run: (c) => {
      const s = needJitToken(c);
      if (s) return s;
      const r = c.jit?.postgres_login_no_jit;
      const expected = `current_user = ${JIT_ROLE}`;
      if (!r) return skip('Postgres login was not attempted.');
      if (r.skipped) return skip(r.skipped);
      if (r.error) {
        const actual = { endpoint: r.endpoint, error: r.error };
        return isAuthFailure(r) ? warn(expected, actual, CTRL_2151_HINT) : fail(expected, actual);
      }
      return r.current_user === JIT_ROLE
        ? pass(expected, { endpoint: r.endpoint, current_user: r.current_user, ms: r.ms }, 'CTRL-2151 may be fixed.')
        : fail(expected, { endpoint: r.endpoint, current_user: r.current_user });
    },
  },
  {
    id: 'jit_direct_login',
    group: 'jit',
    description: `Postgres login to the direct host (db.<project host>, IPv4 if it has an address, else IPv6) with the JIT token as the password runs as ${JIT_ROLE}`,
    run: (c) => {
      const s = needJitToken(c);
      if (s) return s;
      const r = c.jit?.direct_login;
      const expected = `current_user = ${JIT_ROLE}`;
      if (!r) return skip('Direct login was not attempted.');
      if (r.skipped) return skip(r.skipped);
      if (r.resolve_failed) return skip('The direct host has no IPv4 or IPv6 address.');
      if (r.family === 6 && isNoRoute(r)) {
        return skip(`The direct host has only an IPv6 address, and this runtime has no IPv6 route. Add the IPv4 add-on to the project to test it from here. ${r.error} via ${r.endpoint}.`);
      }
      if (r.error) return fail(expected, { endpoint: r.endpoint, error: r.error }, JIT_HINT);
      return r.current_user === JIT_ROLE
        ? pass(expected, { endpoint: r.endpoint, address: r.address, current_user: r.current_user, ms: r.ms })
        : fail(expected, { endpoint: r.endpoint, current_user: r.current_user });
    },
  },
  {
    id: 'cross_tenant_targets',
    group: 'cross_tenant',
    description: 'CROSS_TENANT_TARGETS lists other tenants as <project ref or https:// URL>=<publishable or anon key>[:<legacy anon key>]',
    run: (c) => {
      const s = needCrossTenant(c);
      if (s) return s;
      const { targets, errors } = c.crossTenant;
      const actual = { targets: targets.map((t) => t.url), ...(errors.length && { errors }) };
      if (errors.length) return fail('valid entries for other tenants', actual, errors.map((e) => `${e.target ?? '(empty)'}: ${e.error}`).join(' '));
      return pass('valid entries for other tenants', actual);
    },
  },
  ...CROSS_TENANT_SERVICES.map(crossTenantServiceCheck),
  ...JIT_PROBES.map(crossTenantJitCheck),
  {
    id: 'cross_tenant_gateway_coverage',
    group: 'cross_tenant',
    description: `Cross-tenant requests reach api-gateway v1 without the ${FORWARD_HEADER} header and api-gateway v2 with it (from the sb-gateway-version response header)`,
    run: (c) => {
      const s = needCrossTenantTargets(c);
      if (s) return s;
      const targets = gatewayCoverage(c.crossTenant);
      const expected = 'for every target: v1 requests answered by api-gateway v1, v2 requests answered by api-gateway v2';
      const missed = targets.filter((t) => t.missing.length);
      if (!missed.length) return pass(expected, targets);
      return warn(expected, targets, missed
        .map((t) => `${t.target}: ${t.missing.map((v) => `${v} requests were answered by ${t[v].join(', ') || 'no gateway'}`).join(', ')}`)
        .join('; '));
    },
  },
];

async function runOne(check, c, deps) {
  try {
    return await check.run(c, deps);
  } catch (err) {
    return fail(null, null, `Check errored: ${err.message}`);
  }
}

// The v2 context replaces the api-gateway results with the results of the requests sent to api-gateway v2.
const v2Context = (c) => ({
  ...c,
  sc: { ...c.sc, access: c.gatewayV2.access },
  db: c.gatewayV2.database_identity ?? null,
  controls: c.gatewayV2.controls ?? null,
});

const describeOutcome = (variant, r) => `${variant} ${r.status}${r.detail ? ` (${r.detail})` : ''}`;

// A check with `gateway` (the names of its requests in gateway_v2.gateway_versions) runs on the v1 results and on
// the v2 results. A v2 result is inconclusive when api-gateway v2 did not answer one of its requests. The status
// is the worst of the two: fail, then warn, then pass, then skip.
async function runOnGateways(check, c, deps) {
  const outcomes = { v1: await runOne(check, c, deps) };
  outcomes.v2 = c.gatewayV2 ? await runOne(check, v2Context(c), deps) : skip('api-gateway v2 requests were not run.');
  if (outcomes.v2.status !== 'skip') {
    const versions = check.gateway.map((name) => c.gatewayV2.gateway_versions?.[name] ?? 'unknown');
    const missed = versions.find((version) => !isForwarded('v2', version));
    if (missed) outcomes.v2 = warn(outcomes.v2.expected, outcomes.v2.actual, notForwardedReason(missed));
  }
  const statuses = VARIANTS.map((v) => outcomes[v].status);
  if (statuses.every((s) => s === 'skip')) return { ...outcomes.v1, variants: outcomes };
  return {
    status: worstStatus(statuses),
    expected: outcomes.v1.expected ?? outcomes.v2.expected,
    actual: Object.fromEntries(VARIANTS.map((v) => [v, outcomes[v].actual])),
    detail: VARIANTS.map((v) => describeOutcome(v, outcomes[v])).join(', '),
    variants: outcomes,
  };
}

// include and exclude are lists of group names and check ids. The summary covers only the checks that ran.
async function runChecks(data, ctx, { env = process.env, now = Date.now, fetchImpl = fetch, include, exclude } = {}) {
  const c = buildContext(data, ctx, env, now());
  const results = [];
  const matches = (list, check) => list.includes(check.group) || list.includes(check.id);
  const selected = CHECKS.filter((check) => (!include || matches(include, check)) && !(exclude && matches(exclude, check)));
  for (const check of selected) {
    const outcome = check.gateway ? await runOnGateways(check, c, { fetchImpl }) : await runOne(check, c, { fetchImpl });
    results.push({ id: check.id, group: check.group, description: check.description, ...outcome });
  }
  const count = (st) => results.filter((r) => r.status === st).length;
  const summary = {
    passed: count('pass'),
    warned: count('warn'),
    failed: count('fail'),
    skipped: count('skip'),
  };
  summary.status = summary.failed ? 'fail' : summary.warned ? 'warn' : 'pass';
  return { spec: SPEC, summary: { status: summary.status, ...summary }, results };
}

module.exports = { runChecks };
