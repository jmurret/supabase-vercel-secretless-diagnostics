// Cross-tenant probes: send this tenant's resource token to other tenants' endpoints and expect
// them to reject it. Each target also gets its own public key, so that the gateway apikey check
// passes and only the Bearer token decides.

const { randomBytes } = require('node:crypto');
const { findTargetPooler, isAuthRejection: isPoolerAuthRejection, poolerRegion, poolerHostCache } = require('./pooler-discovery');
const { signRequest, EMPTY_PAYLOAD_SHA256 } = require('./sigv4');

const PROBE_TIMEOUT_MS = 5000;
const REALTIME_TIMEOUT_MS = 8000;
const S3_PATH = '/storage/v1/s3/';
const DEFAULT_S3_REGION = 'us-east-1';
const S3_CREDENTIAL_CODES = ['SignatureDoesNotMatch', 'InvalidAccessKeyId', 'InvalidSignature'];
const JIT_ROLE = 'postgres';
const GATEWAY_HEADER = 'sb-gateway-version';
const HEALTH_PATH = '/auth/v1/health';
const MAX_ERROR_CHARS = 200;
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const TARGETS_HINT = 'Set it to comma-separated <project ref or https:// URL>=<publishable or anon key> entries for other tenants.';

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
    noGateway: true,
    probe: probeS3,
  },
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

function normalizeGatewayVersion(value) {
  const match = /^v?(\d+)(?:\.\d+)*$/i.exec(String(value ?? '').trim());
  return match ? `v${Number(match[1])}` : 'unknown';
}

const firstLabel = (hostname) => hostname.split('.')[0];

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
    const key = eq < 0 ? '' : entry.slice(eq + 1).trim();
    if (!target || !key) {
      errors.push({ target: target || null, error: 'Entry must be <project ref or https:// URL>=<publishable or anon key>.' });
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
    targets.push({ ref, url, key });
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

async function probe(fetchImpl, baseUrl, key, token, service) {
  const started = Date.now();
  try {
    const res = await fetchImpl(`${baseUrl}${service.path}`, {
      method: service.method,
      headers: {
        apikey: key,
        Authorization: `Bearer ${token}`,
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

const PUBLISHABLE_KEY_NOTE =
  'The S3 secret is a publishable key (sb_publishable_...). Storage S3 may accept only the legacy anon key as the secret access key.';

// ListBuckets with the target ref as access key id, the target key as secret and the token as session token.
async function probeS3(deps, { ref, url, key, token, region, isControl }) {
  const started = Date.now();
  const secrets = [token, key];
  const extra = { region: region.name, region_source: region.source };
  try {
    const target = `${url}${S3_PATH}`;
    const { headers } = signRequest({
      url: target,
      region: region.name,
      service: 's3',
      accessKeyId: ref,
      secretAccessKey: key,
      sessionToken: token,
      headers: { 'x-amz-content-sha256': EMPTY_PAYLOAD_SHA256 },
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
    else {
      const error = summarizeS3Error(await res.text(), secrets);
      const credentialError = S3_CREDENTIAL_CODES.some((code) => error.startsWith(code));
      result.error = isControl && credentialError && key.startsWith('sb_publishable_') ? `${error} ${PUBLISHABLE_KEY_NOTE}` : error;
    }
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

function probeService(deps, tenant, service) {
  return service.probe
    ? service.probe(deps, tenant)
    : probe(deps.fetchImpl, tenant.url, tenant.key, tenant.token, service);
}

async function probeAll(deps, tenant) {
  const results = await Promise.all(SERVICES.map((s) => probeService(deps, tenant, s)));
  return Object.fromEntries(SERVICES.map((s, i) => [s.id, results[i]]));
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

// The S3 signature needs the region of the project. The pooler host names it (aws-<n>-<region>.pooler...).
// A target region is known only from a cached or hinted pooler host, because the pooler search runs at the same time.
function pickRegion(candidates) {
  const found = candidates.map(([source, host]) => ({ name: poolerRegion(host), source })).find((c) => c.name);
  return found ?? { name: DEFAULT_S3_REGION, source: 'default' };
}

async function runCrossTenant({
  spec,
  ownUrl,
  ownKey,
  token,
  jit,
  ownPoolerHost = jit?.poolerHost,
  fetchImpl = (...args) => fetch(...args),
  createClientImpl = defaultCreateClient,
  realtimeTimeoutMs,
  now,
}) {
  if (!spec?.trim()) return { skipped: `CROSS_TENANT_TARGETS is not set. ${TARGETS_HINT}` };
  if (!token) return { skipped: 'No resource token was minted.' };
  try {
    new URL(ownUrl);
  } catch {
    return { skipped: 'SUPABASE_URL is missing or invalid.' };
  }
  const { own, targets, errors } = parseTargets(spec, ownUrl);
  const noKey = { status: null, gateway_version: 'unknown', error: 'No publishable or anon key is set for this tenant.' };
  const deps = { fetchImpl, createClientImpl, realtimeTimeoutMs, now };
  const hostCache = jit?.poolerCache ?? poolerHostCache;
  const ownRegion = pickRegion([['own_pooler_host', ownPoolerHost]]);
  const [control, ...probes] = await Promise.all([
    ownKey
      ? probeAll(deps, { ref: own.ref, url: own.url, key: ownKey, token, region: ownRegion, isControl: true })
      : Object.fromEntries(SERVICES.map((s) => [s.id, noKey])),
    ...targets.map(async (t) => {
      const region = pickRegion([
        ['target_pooler_cache', hostCache.get(t.ref)],
        ['target_pooler_hint', jit?.poolerHints?.[t.ref]],
        ['own_pooler_host', ownPoolerHost],
      ]);
      const [targetProbes, health, jitResults] = await Promise.all([
        probeAll(deps, { ref: t.ref, url: t.url, key: t.key, token, region }),
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

// The api-gateway answers this itself, so it does not depend on the target health or on the control.
const GATEWAY_NOT_ISSUED_MESSAGE = 'Vercel OIDC token not issued for this project';

const is2xx = (status) => status >= 200 && status < 300;

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
  const s = target?.status ?? null;
  if (is2xx(s)) return { result: 'accepted' };
  if (service.id === 'rest' && s === 404 && /PGRST205/.test(target?.error ?? '')) {
    return { result: 'accepted', reason: 'PostgREST accepted the token and then did not find the table (PGRST205)' };
  }
  if (s === null) return { result: 'inconclusive', reason: `network error: ${target?.error ?? 'no response'}` };
  if (s >= 500) return { result: 'inconclusive', reason: `HTTP ${s} from the target` };
  if (s === 401 && target?.error?.includes(GATEWAY_NOT_ISSUED_MESSAGE)) {
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

function evaluateService(data, service) {
  const control = data.own.control[service.id];
  const rows = data.targets.map((t) => {
    const p = t.probes[service.id];
    return {
      target: t.ref,
      gateway_version: p.gateway_version,
      control_status: control?.status ?? null,
      ...(control?.error && { control_error: control.error }),
      ...(control?.region && { control_region: control.region, control_region_source: control.region_source }),
      status: p.status,
      ...(p.error && { error: p.error }),
      ...(p.region && { region: p.region, region_source: p.region_source }),
      ...classify(service, control, p, t.health),
    };
  });
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

function gatewayCoverage(data) {
  const perTarget = data.targets.map((t) => ({
    target: t.ref,
    gateway_versions: [...new Set(SERVICES.filter((s) => !s.noGateway).map((s) => t.probes[s.id].gateway_version))].sort(),
  }));
  const seen = [...new Set(perTarget.flatMap((t) => t.gateway_versions))].sort();
  return { perTarget, seen };
}

module.exports = {
  SERVICES,
  JIT_PROBES,
  normalizeGatewayVersion,
  parseTargets,
  runCrossTenant,
  evaluateService,
  evaluateJitProbe,
  gatewayCoverage,
};
