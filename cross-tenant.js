// Cross-tenant probes: send this tenant's resource token to other tenants' endpoints and expect
// them to reject it. Each target also gets its own public key, so that the gateway apikey check
// passes and only the Bearer token decides.

const PROBE_TIMEOUT_MS = 5000;
const GATEWAY_HEADER = 'sb-gateway-version';
const HEALTH_PATH = '/auth/v1/health';
const MAX_ERROR_CHARS = 200;
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const TARGETS_HINT = 'Set it to comma-separated <project ref or https:// URL>=<publishable or anon key> entries for other tenants.';

const isAuthRejection = (status) => status === 401 || status === 403;
// Storage and Realtime can reject with other 4xx codes (Storage answers 400 with an error body).
const isAnyRejection = (status) => status >= 300 && status < 500;

const SERVICES = [
  { id: 'rest', label: 'REST', method: 'GET', path: '/rest/v1/', expected: 'HTTP 401 or 403', isRejection: isAuthRejection },
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
    else result.error = redact((await res.text()).slice(0, MAX_ERROR_CHARS), token);
    return { ...result, ms: Date.now() - started };
  } catch (err) {
    return { status: null, gateway_version: 'unknown', gateway_header: null, error: redact(err.message, token), ms: Date.now() - started };
  }
}

const redact = (text, token) => (token ? text.split(token).join('<token>') : text);

async function probeAll(fetchImpl, baseUrl, key, token) {
  const results = await Promise.all(SERVICES.map((s) => probe(fetchImpl, baseUrl, key, token, s)));
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

async function runCrossTenant({ spec, ownUrl, ownKey, token, fetchImpl = (...args) => fetch(...args) }) {
  if (!spec?.trim()) return { skipped: `CROSS_TENANT_TARGETS is not set. ${TARGETS_HINT}` };
  if (!token) return { skipped: 'No resource token was minted.' };
  try {
    new URL(ownUrl);
  } catch {
    return { skipped: 'SUPABASE_URL is missing or invalid.' };
  }
  const { own, targets, errors } = parseTargets(spec, ownUrl);
  const noKey = { status: null, gateway_version: 'unknown', error: 'No publishable or anon key is set for this tenant.' };
  const [control, ...probes] = await Promise.all([
    ownKey ? probeAll(fetchImpl, own.url, ownKey, token) : Object.fromEntries(SERVICES.map((s) => [s.id, noKey])),
    ...targets.map(async (t) => {
      const [targetProbes, health] = await Promise.all([probeAll(fetchImpl, t.url, t.key, token), probeHealth(fetchImpl, t.url, t.key)]);
      return { probes: targetProbes, health };
    }),
  ]);
  return {
    own: { ...own, control },
    targets: targets.map((t, i) => ({ ref: t.ref, url: t.url, probes: probes[i].probes, health: probes[i].health })),
    errors,
  };
}

const is2xx = (status) => status >= 200 && status < 300;

function classify(service, control, target, health) {
  const s = target?.status ?? null;
  if (is2xx(s)) return { result: 'accepted' };
  if (s === null) return { result: 'inconclusive', reason: `network error: ${target?.error ?? 'no response'}` };
  if (s >= 500) return { result: 'inconclusive', reason: `HTTP ${s} from the target` };
  if (!is2xx(health?.status)) {
    return {
      result: 'inconclusive',
      reason: `the target ref or key is not valid in this environment (GET ${HEALTH_PATH} returned ${health?.status ?? health?.error ?? 'no response'})`,
    };
  }
  if (!is2xx(control?.status)) {
    return { result: 'inconclusive', reason: `control on this tenant returned ${control?.status ?? control?.error ?? 'no response'}, so the token may be bad` };
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
      status: p.status,
      ...classify(service, control, p, t.health),
    };
  });
  const accepted = rows.filter((r) => r.result === 'accepted');
  const inconclusive = rows.filter((r) => r.result === 'inconclusive');
  return { rows, accepted, inconclusive };
}

function gatewayCoverage(data) {
  const perTarget = data.targets.map((t) => ({
    target: t.ref,
    gateway_versions: [...new Set(Object.values(t.probes).map((p) => p.gateway_version))].sort(),
  }));
  const seen = [...new Set(perTarget.flatMap((t) => t.gateway_versions))].sort();
  return { perTarget, seen };
}

module.exports = {
  SERVICES,
  normalizeGatewayVersion,
  parseTargets,
  runCrossTenant,
  evaluateService,
  gatewayCoverage,
};
