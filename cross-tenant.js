// Cross-tenant probes: send this tenant's resource token to other tenants' endpoints and expect
// them to reject it. Each target also gets its own public key, so that the gateway apikey check
// passes and only the Bearer token decides.

const { randomBytes } = require('node:crypto');
const { findTargetPooler, isAuthRejection: isPoolerAuthRejection, poolerRegion } = require('./pooler-discovery');
const { signRequest, EMPTY_PAYLOAD_SHA256 } = require('./sigv4');
const {
  GATEWAY_HEADER,
  VARIANTS,
  notForwardedReason,
  variantHeaders,
  normalizeGatewayVersion,
  isForwarded,
  worstResult,
} = require('./gateway-variants');

const PROBE_TIMEOUT_MS = 5000;
const REALTIME_TIMEOUT_MS = 8000;
const S3_PATH = '/storage/v1/s3/';
const S3_CREDENTIAL_CODES = ['SignatureDoesNotMatch', 'InvalidAccessKeyId', 'InvalidSignature'];
const JIT_ROLE = 'postgres';
const HEALTH_PATH = '/auth/v1/health';
const MAX_ERROR_CHARS = 200;
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const ENTRY_FORMAT = '<project ref or https:// URL>=<publishable or anon key>[:<legacy anon key>]';
const TARGETS_HINT = `Set it to comma-separated ${ENTRY_FORMAT} entries for other tenants.`;
const S3_KEY_REASON = 'Storage S3 accepts only the legacy anon key as the S3 secret.';

const isAuthRejection = (status) => status === 401 || status === 403;
// Storage and Realtime can reject with other 4xx codes (Storage answers 400 with an error body).
const isAnyRejection = (status) => status >= 300 && status < 500;

const SERVICES = [
  {
    id: 'rest',
    label: 'REST',
    method: 'GET',
    path: '/rest/v1/countries?select=*&limit=1',
    expected: 'HTTP 401 or 403',
    isRejection: isAuthRejection,
  },
  {
    id: 'auth_admin',
    label: 'Auth admin',
    method: 'GET',
    path: '/auth/v1/admin/users?per_page=1',
    expected: 'HTTP 401 or 403',
    isRejection: isAuthRejection,
  },
  { id: 'storage', label: 'Storage', method: 'GET', path: '/storage/v1/bucket', expected: 'non-2xx', isRejection: isAnyRejection },
  {
    id: 'realtime',
    label: 'Realtime',
    method: 'POST',
    path: '/realtime/v1/api/broadcast',
    body: { messages: [{ topic: 'cross-tenant-probe', event: 'probe', payload: {}, private: true }] },
    expected: 'non-2xx',
    isRejection: isAnyRejection,
  },
  {
    id: 'storage_s3',
    label: 'Storage S3',
    request: `GET ${S3_PATH} (S3 ListBuckets, AWS SigV4, session token)`,
    expected: 'HTTP 401 or 403',
    isRejection: isAuthRejection,
    probe: probeS3,
    regional: true,
  },
  // The websocket upgrade response headers are not visible to the client, so the gateway version cannot be
  // checked. A v2 request could not be told apart from a v1 request, so this probe sends only a v1 request.
  {
    id: 'realtime_ws',
    label: 'Realtime websocket',
    request: 'websocket join of a private channel',
    expected: 'CHANNEL_ERROR',
    noGateway: true,
    probe: probeRealtime,
    classify: classifyRealtime,
  },
];

const firstLabel = (hostname) => hostname.split('.')[0];

function decodeJwtPayload(token) {
  try {
    const parts = token.split('.');
    return parts.length === 3 ? JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) : null;
  } catch {
    return null;
  }
}

// A legacy anon key is a JWT with role anon. When the payload has a ref, it must match the project ref.
function isLegacyAnonKey(key, ref) {
  const payload = decodeJwtPayload(key ?? '');
  if (!payload || typeof payload !== 'object' || payload.role !== 'anon') return false;
  return payload.ref === undefined || ref === undefined || payload.ref === ref;
}

// Targets are reported without their keys.
function parseTargets(spec, ownUrl) {
  const own = new URL(ownUrl);
  const ownRef = firstLabel(own.hostname);
  const domain = own.hostname.split('.').slice(1).join('.');
  const targets = [];
  const errors = [];
  for (const entry of (spec ?? '').split(',').map((e) => e.trim()).filter(Boolean)) {
    const eq = entry.indexOf('=');
    const target = (eq < 0 ? entry : entry.slice(0, eq)).trim();
    const keyPart = eq < 0 ? '' : entry.slice(eq + 1).trim();
    const colon = keyPart.indexOf(':');
    const key = (colon < 0 ? keyPart : keyPart.slice(0, colon)).trim();
    const s3Entry = colon < 0 ? null : keyPart.slice(colon + 1).trim();
    if (!target || !key || s3Entry === '') {
      errors.push({ target: target || null, error: `Entry must be ${ENTRY_FORMAT}.` });
      continue;
    }
    let url;
    if (/^[a-z]+:\/\//i.test(target)) {
      try {
        url = new URL(target);
      } catch {
        errors.push({ target, error: 'Not a valid URL.' });
        continue;
      }
      if (url.protocol !== 'https:') {
        errors.push({ target, error: 'URL must use https://.' });
        continue;
      }
      url = url.origin;
    } else if (LABEL_RE.test(target)) {
      url = `https://${target}.${domain}`;
    } else {
      errors.push({ target, error: 'Not a project ref or an https:// URL.' });
      continue;
    }
    const ref = firstLabel(new URL(url).hostname);
    if (ref === ownRef) {
      errors.push({ target, error: `Same tenant as this deployment (${ownRef}), so it is not a cross-tenant test.` });
      continue;
    }
    if (s3Entry !== null && !isLegacyAnonKey(s3Entry, ref)) {
      errors.push({ target, error: `The key after ":" must be the legacy anon key of ${ref} (a JWT with role anon).` });
      continue;
    }
    const s3Key = s3Entry ?? (isLegacyAnonKey(key, ref) ? key : null);
    targets.push({ ref, url, key, ...(s3Key && { s3Key }) });
  }
  return { own: { ref: ownRef, url: own.origin }, targets, errors };
}

const redact = (text, secrets) => secrets.filter(Boolean).reduce((out, secret) => out.split(secret).join('<redacted>'), text);

// Only these fields of an error body are kept. Each is redacted before it is cut to length.
function summarizeError(text, secrets) {
  const clean = (value) => redact(String(value), secrets).slice(0, MAX_ERROR_CHARS);
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return clean(text);
  }
  if (!body || typeof body !== 'object') return clean(text);
  const pick = (names) =>
    names.map((n) => body[n]).filter((v) => typeof v === 'string' || typeof v === 'number').map(clean).join(' ');
  return [pick(['code', 'error_code', 'error']), pick(['msg', 'message'])].filter(Boolean).join(': ');
}

async function probe(fetchImpl, baseUrl, key, token, service, variant) {
  const started = Date.now();
  try {
    const res = await fetchImpl(`${baseUrl}${service.path}`, {
      method: service.method,
      headers: {
        apikey: key,
        Authorization: `Bearer ${token}`,
        ...variantHeaders(variant),
        ...(service.body && { 'content-type': 'application/json' }),
      },
      ...(service.body && { body: JSON.stringify(service.body) }),
      redirect: 'manual',
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    const header = res.headers.get(GATEWAY_HEADER);
    const result = { status: res.status, gateway_version: normalizeGatewayVersion(header), gateway_header: header };
    // A 2xx body from another tenant can hold its data, so only error bodies are kept.
    if (res.ok) await res.body?.cancel?.();
    else result.error = summarizeError(await res.text(), [token, key]);
    return { ...result, ms: Date.now() - started };
  } catch (err) {
    return { status: null, gateway_version: 'unknown', gateway_header: null, error: redact(err.message, [token, key]).slice(0, MAX_ERROR_CHARS), ms: Date.now() - started };
  }
}

const xmlField = (text, name) => new RegExp(`<${name}>([^<]*)</${name}>`).exec(text)?.[1];

// S3 errors are XML with a Code and a Message. Errors from the api-gateway are JSON.
function summarizeS3Error(text, secrets) {
  const parts = [xmlField(text, 'Code'), xmlField(text, 'Message')].filter(Boolean);
  return parts.length ? parts.map((p) => redact(p, secrets).slice(0, MAX_ERROR_CHARS)).join(': ') : summarizeError(text, secrets);
}

// ListBuckets with the target ref as access key id, the legacy anon key as secret and the token as session token.
// The forwarding header of the v2 request is signed with the other headers.
async function probeS3(deps, { ref, url, s3Key, token, region }, variant) {
  const started = Date.now();
  const secrets = [token, s3Key];
  const extra = { region: region.name, region_source: region.source };
  try {
    const target = `${url}${S3_PATH}`;
    const { headers } = signRequest({
      url: target,
      region: region.name,
      service: 's3',
      accessKeyId: ref,
      secretAccessKey: s3Key,
      sessionToken: token,
      headers: { 'x-amz-content-sha256': EMPTY_PAYLOAD_SHA256, ...variantHeaders(variant) },
      now: deps.now?.(),
    });
    const res = await deps.fetchImpl(target, {
      method: 'GET',
      headers,
      redirect: 'manual',
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    const header = res.headers.get(GATEWAY_HEADER);
    const result = { status: res.status, gateway_version: normalizeGatewayVersion(header), gateway_header: header, ...extra };
    if (res.ok) await res.body?.cancel?.();
    else result.error = summarizeS3Error(await res.text(), secrets);
    return { ...result, ms: Date.now() - started };
  } catch (err) {
    return { status: null, gateway_version: 'unknown', gateway_header: null, ...extra, error: cut(err.message, secrets), ms: Date.now() - started };
  }
}

const REALTIME_OUTCOMES = ['SUBSCRIBED', 'CHANNEL_ERROR', 'TIMED_OUT'];

// Joins a private channel with the target key as apikey and the token as the Realtime access token.
async function probeRealtime(deps, { url, key, token }) {
  const started = Date.now();
  const secrets = [token, key];
  const timeoutMs = deps.realtimeTimeoutMs ?? REALTIME_TIMEOUT_MS;
  let client;
  try {
    client = deps.createClientImpl(url, key, {
      auth: { persistSession: false, autoRefreshToken: false },
      realtime: { transport: globalThis.WebSocket },
    });
    await client.realtime.setAuth(token);
    const outcome = await new Promise((resolve) => {
      const channel = client.channel(`vercel-oidc-xtenant-${randomBytes(6).toString('hex')}`, { config: { private: true } });
      const timer = setTimeout(() => resolve({ status: 'TIMED_OUT', error: `no answer within ${timeoutMs} ms` }), timeoutMs);
      channel.subscribe((status, err) => {
        if (!REALTIME_OUTCOMES.includes(status)) return;
        clearTimeout(timer);
        resolve({ status, ...(err?.message && { error: cut(err.message, secrets) }) });
      });
    });
    return { ...outcome, gateway_version: 'unknown', ms: Date.now() - started };
  } catch (err) {
    return { status: null, gateway_version: 'unknown', error: cut(err.message, secrets), ms: Date.now() - started };
  } finally {
    try {
      await client?.removeAllChannels?.();
      client?.realtime?.disconnect?.();
    } catch {}
  }
}

function probeVariant(deps, tenant, service, variant) {
  return service.probe
    ? service.probe(deps, tenant, variant)
    : probe(deps.fetchImpl, tenant.url, tenant.key, tenant.token, service, variant);
}

// A gateway service answers { v1, v2 }. The websocket probe answers one result.
async function probeService(deps, tenant, service) {
  if (service.noGateway) return probeVariant(deps, tenant, service);
  const results = await Promise.all(VARIANTS.map((v) => probeVariant(deps, tenant, service, v)));
  return Object.fromEntries(VARIANTS.map((v, i) => [v, results[i]]));
}

const perVariant = (service, value) => (service.noGateway ? value : Object.fromEntries(VARIANTS.map((v) => [v, value])));

async function probeAll(deps, tenant, services) {
  const results = await Promise.all(services.map((s) => probeService(deps, tenant, s)));
  return Object.fromEntries(services.map((s, i) => [s.id, results[i]]));
}

// A rejection from a project that does not exist, or that is in another environment, proves nothing.
async function probeHealth(fetchImpl, baseUrl, key) {
  try {
    const res = await fetchImpl(`${baseUrl}${HEALTH_PATH}`, {
      method: 'GET',
      headers: { apikey: key },
      redirect: 'manual',
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    await res.body?.cancel?.();
    return { status: res.status };
  } catch (err) {
    return { status: null, error: err.message };
  }
}

const NO_JIT_TOKEN = 'No JIT resource token was minted.';
const cut = (value, secrets) => redact(String(value), secrets).slice(0, MAX_ERROR_CHARS);
const withError = (error, secrets) => (error ? { error: cut(error, secrets) } : {});

// Only these fields are kept, and the JIT token is removed from the error text.
const cleanMgmt = (r, secrets) => (r?.skipped ? { skipped: r.skipped } : { status: r?.status ?? null, ...withError(r?.error, secrets), ms: r?.ms });

async function probeJitPooler(jit, ref, secrets) {
  const found = await findTargetPooler({
    ownHost: jit.poolerHost,
    ref,
    hint: jit.poolerHints?.[ref],
    cache: jit.poolerCache,
    login: (host, timeoutMs) => jit.loginPooler(ref, host, timeoutMs),
    ...jit.discovery,
  });
  if (found.skipped) return { skipped: found.skipped };
  if (found.none) return { hosts_tried: found.tried, error: cut(found.error, secrets) };
  const { current_user: currentUser, code, error, ms } = found.result;
  return {
    ...(currentUser && { current_user: currentUser }),
    ...(code && { code }),
    ...withError(error, secrets),
    ms,
    pooler_host: found.host,
    region: poolerRegion(found.host),
    hosts_tried: found.tried,
    source: found.source,
  };
}

// The JIT token goes to the Management API and the pooler of each target. Neither answer keeps a body.
async function jitProbes(jit, ref) {
  if (!jit?.token) {
    const skipped = { skipped: jit?.skipped ?? NO_JIT_TOKEN };
    return { jit_mgmt: skipped, jit_pooler: skipped };
  }
  const secrets = [jit.token];
  const [mgmt, pooler] = await Promise.all([jit.requestJit(ref), probeJitPooler(jit, ref, secrets)]);
  return { jit_mgmt: cleanMgmt(mgmt, secrets), jit_pooler: pooler };
}

const defaultCreateClient = (...args) => require('@supabase/supabase-js').createClient(...args);

function notRunnable(spec, token, ownUrl) {
  if (!spec?.trim()) return { skipped: `CROSS_TENANT_TARGETS is not set. ${TARGETS_HINT}` };
  if (!token) return { skipped: 'No resource token was minted.' };
  try {
    new URL(ownUrl);
  } catch {
    return { skipped: 'SUPABASE_URL is missing or invalid.' };
  }
  return null;
}

const NO_KEY = { status: null, gateway_version: 'unknown', error: 'No publishable or anon key is set for this tenant.' };
const noKeyResults = (services) => Object.fromEntries(services.map((s) => [s.id, perVariant(s, NO_KEY)]));

// The regional services need the region of the target, so they run in runCrossTenantS3.
const LOCAL_SERVICES = SERVICES.filter((s) => !s.regional);
const REGIONAL_SERVICES = SERVICES.filter((s) => s.regional);

async function runCrossTenant({
  spec,
  ownUrl,
  ownKey,
  token,
  jit,
  fetchImpl = (...args) => fetch(...args),
  createClientImpl = defaultCreateClient,
  realtimeTimeoutMs,
}) {
  const skipped = notRunnable(spec, token, ownUrl);
  if (skipped) return skipped;
  const { own, targets, errors } = parseTargets(spec, ownUrl);
  const deps = { fetchImpl, createClientImpl, realtimeTimeoutMs };
  const [control, ...probes] = await Promise.all([
    ownKey ? probeAll(deps, { ref: own.ref, url: own.url, key: ownKey, token }, LOCAL_SERVICES) : noKeyResults(LOCAL_SERVICES),
    ...targets.map(async (t) => {
      const [targetProbes, health, jitResults] = await Promise.all([
        probeAll(deps, { ref: t.ref, url: t.url, key: t.key, token }, LOCAL_SERVICES),
        probeHealth(fetchImpl, t.url, t.key),
        jitProbes(jit, t.ref),
      ]);
      return { probes: targetProbes, health, jitResults };
    }),
  ]);
  return {
    own: { ...own, control },
    targets: targets.map((t, i) => ({ ref: t.ref, url: t.url, probes: probes[i].probes, health: probes[i].health, ...probes[i].jitResults })),
    errors,
  };
}

const TARGET_REGION_UNKNOWN = 'target region unknown';
const NO_OWN_S3_KEY = `Set SUPABASE_ANON_KEY to this project's legacy anon key; ${S3_KEY_REASON}`;
const noTargetS3Key = (ref) =>
  `no legacy anon key is set for this target; ${S3_KEY_REASON} Add it as ${ref}=<key>:<legacy anon key>`;
const OWN_REGION_UNKNOWN = 'the region of this tenant is unknown: POSTGRES_POOLER_HOST does not name one';
const regionalResults = (result) => Object.fromEntries(REGIONAL_SERVICES.map((s) => [s.id, perVariant(s, result)]));

// The S3 signature needs the region of the project. regions is { <target ref>: <region> }, from the dashboard,
// which reads it from the pooler host that /api/cross-tenant found. The control region comes from
// POSTGRES_POOLER_HOST (aws-<n>-<region>.pooler...). A target without a region or without a legacy anon key is not
// probed. ownS3Key is the legacy anon key of this tenant.
async function runCrossTenantS3({ spec, ownUrl, ownS3Key, token, ownPoolerHost, regions = {}, fetchImpl = (...args) => fetch(...args), now }) {
  const skipped = notRunnable(spec, token, ownUrl);
  if (skipped) return skipped;
  const { own, targets, errors } = parseTargets(spec, ownUrl);
  const deps = { fetchImpl, now };
  const ownRegion = poolerRegion(ownPoolerHost);
  const control = !ownS3Key
    ? regionalResults({ status: null, gateway_version: 'unknown', error: NO_OWN_S3_KEY })
    : ownRegion
      ? probeAll(deps, { ref: own.ref, url: own.url, s3Key: ownS3Key, token, region: { name: ownRegion, source: 'own_pooler_host' } }, REGIONAL_SERVICES)
      : regionalResults({ status: null, gateway_version: 'unknown', error: OWN_REGION_UNKNOWN });
  const [controlResults, ...probes] = await Promise.all([
    control,
    ...targets.map(async (t) => {
      const region = regions[t.ref];
      const unprobed = !t.s3Key ? noTargetS3Key(t.ref) : !region ? TARGET_REGION_UNKNOWN : null;
      const [targetProbes, health] = await Promise.all([
        unprobed
          ? regionalResults({ status: null, gateway_version: 'unknown', unprobed })
          : probeAll(deps, { ref: t.ref, url: t.url, s3Key: t.s3Key, token, region: { name: region, source: 'regions' } }, REGIONAL_SERVICES),
        probeHealth(fetchImpl, t.url, t.key),
      ]);
      return { probes: targetProbes, health };
    }),
  ]);
  const known = new Set(targets.map((t) => t.ref));
  const ignored = Object.keys(regions).filter((ref) => !known.has(ref));
  return {
    own: { ...own, region: ownRegion, control: controlResults },
    targets: targets.map((t, i) => ({ ref: t.ref, url: t.url, region: regions[t.ref] ?? null, ...probes[i] })),
    errors,
    ...(ignored.length && { ignored_regions: ignored }),
  };
}

// The api-gateway answers this itself, so it does not depend on the target health or on the control.
const GATEWAY_NOT_ISSUED_MESSAGE = 'Vercel OIDC token not issued for this project';

const is2xx = (status) => status >= 200 && status < 300;
const isGatewayRejection = (target) => target?.status === 401 && Boolean(target.error?.includes(GATEWAY_NOT_ISSUED_MESSAGE));

const healthFailure = (health) => ({
  result: 'inconclusive',
  reason: `the target ref or key is not valid in this environment (GET ${HEALTH_PATH} returned ${health?.status ?? health?.error ?? 'no response'})`,
});

const controlFailure = (control, hint) => {
  const detail = control?.error;
  return {
    result: 'inconclusive',
    reason: `control on this tenant returned ${control?.status ?? control?.error ?? 'no response'}; this tenant does not accept the token for this service either, so a rejection by the target proves nothing${detail ? ` (${detail})` : ''}${hint ? `. ${hint}` : ''}`,
  };
};

const REALTIME_RLS_HINT = 'A private channel needs a policy on realtime.messages that allows this token';

function classifyRealtime(service, control, target, health) {
  const s = target?.status ?? null;
  if (s === 'SUBSCRIBED') return { result: 'accepted' };
  if (s === null) return { result: 'inconclusive', reason: `network error: ${target?.error ?? 'no response'}` };
  if (s === 'TIMED_OUT') return { result: 'inconclusive', reason: `no answer from the target (${target.error ?? 'timed out'})` };
  if (!is2xx(health?.status)) return healthFailure(health);
  if (control?.status !== 'SUBSCRIBED') return controlFailure(control, REALTIME_RLS_HINT);
  if (s === 'CHANNEL_ERROR') return { result: 'rejected' };
  return { result: 'inconclusive', reason: `unexpected status ${s}` };
}

function classify(service, control, target, health) {
  if (service.classify) return service.classify(service, control, target, health);
  if (target?.unprobed) return { result: 'inconclusive', reason: target.unprobed };
  const s = target?.status ?? null;
  if (is2xx(s)) return { result: 'accepted' };
  if (service.id === 'rest' && s === 404 && /PGRST205/.test(target?.error ?? '')) {
    return { result: 'accepted', reason: 'PostgREST accepted the token and then did not find the table (PGRST205)' };
  }
  if (s === null) return { result: 'inconclusive', reason: `network error: ${target?.error ?? 'no response'}` };
  if (s >= 500) return { result: 'inconclusive', reason: `HTTP ${s} from the target` };
  if (isGatewayRejection(target)) {
    return { result: 'rejected', reason: `api-gateway rejected the token: ${GATEWAY_NOT_ISSUED_MESSAGE}` };
  }
  if (!is2xx(health?.status)) return healthFailure(health);
  if (!is2xx(control?.status)) return controlFailure(control);
  if (service.id === 'storage_s3' && S3_CREDENTIAL_CODES.some((code) => target?.error?.startsWith(code))) {
    return {
      result: 'inconclusive',
      reason: 'the target rejected the S3 access key or signature before it checked the token, so this proves nothing about the token',
    };
  }
  if (service.isRejection(s)) return { result: 'rejected' };
  return { result: 'inconclusive', reason: `unexpected HTTP ${s}` };
}

// A v2 result counts only when api-gateway v2 answered. A 2xx answer is a regression on any gateway.
function classifyVariant(service, variant, control, target, health) {
  const verdict = classify(service, control, target, health);
  if (verdict.result === 'accepted' || target?.status == null || variant !== 'v2') return verdict;
  if (!isForwarded(variant, target.gateway_version)) return { result: 'inconclusive', reason: notForwardedReason(target.gateway_version) };
  if (verdict.result === 'rejected' && !isGatewayRejection(target) && !isForwarded(variant, control?.gateway_version)) {
    return { result: 'inconclusive', reason: `control on this tenant: ${notForwardedReason(control?.gateway_version)}` };
  }
  return verdict;
}

const controlFields = (control) => ({
  control_status: control?.status ?? null,
  ...(control?.error && { control_error: control.error }),
});

function variantRow(service, control, p, t) {
  const variants = Object.fromEntries(
    VARIANTS.map((v) => [
      v,
      {
        gateway_version: p[v].gateway_version,
        control_gateway_version: control?.[v]?.gateway_version ?? 'unknown',
        ...controlFields(control?.[v]),
        status: p[v].status,
        ...(p[v].error && { error: p[v].error }),
        ...classifyVariant(service, v, control?.[v], p[v], t.health),
      },
    ])
  );
  const regionOf = (r) => r?.v1?.region && { region: r.v1.region, region_source: r.v1.region_source };
  const controlRegion = regionOf(control);
  return {
    target: t.ref,
    result: worstResult(VARIANTS.map((v) => variants[v].result)),
    variants,
    ...regionOf(p),
    ...(controlRegion && { control_region: controlRegion.region, control_region_source: controlRegion.region_source }),
  };
}

function singleRow(service, control, p, t) {
  return {
    target: t.ref,
    gateway_version: p.gateway_version,
    ...controlFields(control),
    status: p.status,
    ...(p.error && { error: p.error }),
    ...classify(service, control, p, t.health),
  };
}

// Compact outcome of each variant, for example "v1 rejected (401), v2 inconclusive (request was not forwarded ...)".
const describeVariants = (row) =>
  VARIANTS.map((v) => {
    const x = row.variants[v];
    return `${v} ${x.result} (${x.result === 'inconclusive' ? x.reason : x.status})`;
  }).join(', ');

function evaluateService(data, service) {
  const control = data.own.control[service.id];
  const rows = data.targets.map((t) =>
    (service.noGateway ? singleRow : variantRow)(service, control, t.probes[service.id], t)
  );
  const accepted = rows.filter((r) => r.result === 'accepted');
  const inconclusive = rows.filter((r) => r.result === 'inconclusive');
  return { rows, accepted, inconclusive };
}

const MGMT_JIT_REJECTIONS = [401, 403, 404];

// The error text can already start with the status (for example "403 bad_jwt: ..."), so it is not repeated.
function describeStatusAndError(status, error) {
  const text = error == null ? '' : String(error);
  if (status == null || status === '') return text;
  return text.startsWith(String(status)) ? text : [status, text].filter(Boolean).join(' ');
}

function classifyMgmtJit(control, target) {
  const s = target.status ?? null;
  if (is2xx(s)) return { result: 'accepted' };
  if (s === null) return { result: 'inconclusive', reason: `network error: ${target.error ?? 'no response'}` };
  if (s >= 500) return { result: 'inconclusive', reason: `HTTP ${s} from the Management API` };
  if (!is2xx(control?.status)) {
    const detail = describeStatusAndError(control?.status, control?.error ?? control?.skipped);
    return {
      result: 'inconclusive',
      reason: `the JIT grant for this tenant (jit_management_api) did not succeed, so a rejection of the target proves nothing${detail ? ` (${detail})` : ''}`,
    };
  }
  if (MGMT_JIT_REJECTIONS.includes(s)) return { result: 'rejected' };
  return { result: 'inconclusive', reason: `unexpected HTTP ${s}` };
}

function classifyPoolerLogin(control, target) {
  if (target.current_user) return { result: 'accepted' };
  if (!isPoolerAuthRejection(target)) return { result: 'inconclusive', reason: target.error ?? 'no answer from a pooler' };
  if (control?.current_user !== JIT_ROLE) {
    const detail = control?.current_user ?? control?.error ?? control?.skipped ?? 'no result';
    return {
      result: 'inconclusive',
      reason: `the JIT pooler login for this tenant (jit_postgres_login) did not run as ${JIT_ROLE}, so a rejection by the target proves nothing (${detail})`,
    };
  }
  return { result: 'rejected' };
}

const poolerNote = (p) =>
  p.pooler_host && `answered by ${p.pooler_host} (${p.hosts_tried} ${p.hosts_tried === 1 ? 'host' : 'hosts'} tried, from ${p.source})`;

const JIT_PROBES = [
  {
    id: 'mgmt_jit',
    label: 'Management API JIT grant',
    description: `Management API does not grant JIT access to other tenants for this tenant's JIT token (POST /v1/projects/<target ref>/database/jit, role ${JIT_ROLE})`,
    expected: 'HTTP 401, 403 or 404 from every target',
    field: 'jit_mgmt',
    control: (jit) => jit?.management_api,
    classify: classifyMgmtJit,
    row: (control, p) => ({
      control_status: control?.status ?? null,
      ...((control?.error ?? control?.skipped) && { control_error: control.error ?? control.skipped }),
      status: p.status,
      ...(p.error && { error: p.error }),
    }),
  },
  {
    id: 'pooler_login',
    label: 'pooler login',
    description: `Pooler login to other tenants (user ${JIT_ROLE}.<target ref>, --jit=true) fails for this tenant's JIT token`,
    expected: 'authentication error from the target pooler for every target',
    field: 'jit_pooler',
    control: (jit) => jit?.postgres_login,
    classify: classifyPoolerLogin,
    row: (control, p) => ({
      control_current_user: control?.current_user ?? null,
      ...((control?.error ?? control?.skipped) && { control_error: control.error ?? control.skipped }),
      ...(p.current_user && { current_user: p.current_user }),
      ...(p.code && { code: p.code }),
      ...(p.error && { error: p.error }),
      ...(p.pooler_host && { pooler_host: p.pooler_host, source: p.source }),
      hosts_tried: p.hosts_tried ?? null,
      ...(poolerNote(p) && { note: poolerNote(p) }),
    }),
  },
];

function evaluateJitProbe(data, jit, probe) {
  const control = probe.control(jit);
  const answered = data.targets.filter((t) => t[probe.field] && !t[probe.field].skipped);
  if (!answered.length) {
    return { skipped: data.targets.map((t) => t[probe.field]?.skipped).find(Boolean) ?? 'JIT probes were not run.' };
  }
  const rows = answered.map((t) => {
    const p = t[probe.field];
    const verdict = probe.classify(control, p);
    const healthBad = verdict.result !== 'accepted' && t.health && !is2xx(t.health.status);
    const health = healthBad
      ? {
          result: 'inconclusive',
          reason: `the target ref or key is not valid in this environment (GET ${HEALTH_PATH} returned ${t.health.status ?? t.health.error ?? 'no response'})`,
        }
      : verdict;
    return { target: t.ref, ...probe.row(control, p), ...health };
  });
  return {
    rows,
    accepted: rows.filter((r) => r.result === 'accepted'),
    inconclusive: rows.filter((r) => r.result === 'inconclusive'),
  };
}

// For each target, the gateway versions that answered the v1 requests and the v2 requests. A target is
// covered when every v1 request was served by api-gateway v1 and every v2 request by api-gateway v2.
// The regional services run in another request, so they are not part of it.
function gatewayCoverage(data) {
  const services = LOCAL_SERVICES.filter((s) => !s.noGateway);
  return data.targets.map((t) => {
    const seen = Object.fromEntries(
      VARIANTS.map((v) => [v, [...new Set(services.map((s) => t.probes[s.id]?.[v]?.gateway_version).filter(Boolean))].sort()])
    );
    const missing = VARIANTS.filter((v) => !seen[v].length || seen[v].some((version) => version !== v));
    return { target: t.ref, ...seen, missing };
  });
}

module.exports = {
  SERVICES,
  JIT_PROBES,
  normalizeGatewayVersion,
  parseTargets,
  isLegacyAnonKey,
  runCrossTenant,
  runCrossTenantS3,
  evaluateService,
  describeVariants,
  evaluateJitProbe,
  gatewayCoverage,
};
