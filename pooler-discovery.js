// A pooler serves only the projects of its own region. To log in to another tenant's pooler,
// the host is found by trying the regional pooler hosts that share this deployment's pooler suffix.

const { RESYNC_HINT } = require('./pooler');

const POOLER_REGIONS = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'sa-east-1',
  'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-central-2', 'eu-north-1',
  'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2',
];
const POOLER_HOST_RE = /^aws-(\d+)-[a-z]{2}-[a-z]+-\d+\.pooler\.([a-z0-9][a-z0-9.-]*)$/;
const PROJECT_REF_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const HOST_TIMEOUT_MS = 4000;
const BUDGET_MS = 20_000;
const MIN_ATTEMPT_MS = 500;
const CONCURRENCY = 4;

// Target ref -> pooler host that gave an answer. Lives as long as the warm function instance.
const poolerHostCache = new Map();

const POOLER_REGION_RE = /^aws-\d+-([a-z]{2}-[a-z]+-\d+)\.pooler\.[a-z0-9][a-z0-9.-]*$/;

const poolerRegion = (host) => POOLER_REGION_RE.exec(host ?? '')?.[1] ?? null;

function candidateHosts(ownHost) {
  const match = POOLER_HOST_RE.exec(ownHost ?? '');
  if (!match) return ownHost ? [ownHost] : [];
  const prefixes = [...new Set([Number(match[1]), 0, 1])];
  const hosts = prefixes.flatMap((prefix) => POOLER_REGIONS.map((region) => `aws-${prefix}-${region}.pooler.${match[2]}`));
  return [...new Set([ownHost, ...hosts])];
}

// "<ref>:<host>,<ref>:<host>". Each host is checked against the candidate hosts before it is used.
function parsePoolerHints(spec) {
  const hints = {};
  for (const entry of (spec ?? '').split(',')) {
    const [ref, host, ...extra] = entry.trim().split(':');
    if (ref && host && !extra.length && PROJECT_REF_RE.test(ref)) hints[ref] = host;
  }
  return hints;
}

// "<ref>:<region>,<ref>:<region>". Only the regions in POOLER_REGIONS are kept.
function parseRegionHints(spec) {
  const regions = {};
  for (const entry of (spec ?? '').split(',')) {
    const [ref, region, ...extra] = entry.trim().split(':');
    if (ref && !extra.length && PROJECT_REF_RE.test(ref) && POOLER_REGIONS.includes(region)) regions[ref] = region;
  }
  return regions;
}

const isAuthRejection = (r) => ['28P01', '28000'].includes(r?.code) || /password authentication failed/i.test(r?.error ?? '');
const isNotFound = (r) => r?.code === 'ENOTFOUND' || /ENOTFOUND|tenant or user not found|tenant not found|user not found/i.test(r?.error ?? '');
const isDefinitive = (r) => Boolean(r?.current_user) || isAuthRejection(r);

const plural = (n) => `${n} host${n === 1 ? '' : 's'}`;

function describeMiss(answers, tried, exhausted) {
  const other = answers.find(({ result }) => !isNotFound(result));
  const base = answers.some(({ result }) => isNotFound(result))
    ? `target not found on any regional pooler tried (${plural(tried)})`
    : `no regional pooler answered (${plural(tried)} tried)`;
  return [base, other && `first error from ${other.host}: ${other.result.error ?? 'no error'}`, exhausted && 'time budget used up']
    .filter(Boolean)
    .join('; ');
}

// login(host, timeoutMs) -> result of a pooler login. The first host to connect, or to answer with an
// authentication error, is the target's pooler. Not found and network errors move on to the next host.
async function findTargetPooler({
  ownHost,
  ref,
  hint,
  login,
  cache = poolerHostCache,
  concurrency = CONCURRENCY,
  budgetMs = BUDGET_MS,
  hostTimeoutMs = HOST_TIMEOUT_MS,
  now = Date.now,
}) {
  if (!ownHost) return { skipped: `POSTGRES_POOLER_HOST is not set. ${RESYNC_HINT}` };
  const candidates = candidateHosts(ownHost);
  const allowed = new Set(candidates);
  const sources = new Map();
  for (const [source, host] of [['cache', cache.get(ref)], ['hint', hint]]) {
    if (host && allowed.has(host) && !sources.has(host)) sources.set(host, source);
  }
  const preferred = [...sources.keys()];
  const rest = candidates.filter((h) => !sources.has(h));
  const chunks = preferred.length ? [preferred] : [];
  for (let i = 0; i < rest.length; i += concurrency) chunks.push(rest.slice(i, i + concurrency));

  const deadline = now() + budgetMs;
  const answers = [];
  let tried = 0;
  let exhausted = false;
  for (const chunk of chunks) {
    const remaining = deadline - now();
    if (remaining < MIN_ATTEMPT_MS) {
      exhausted = true;
      break;
    }
    const results = await Promise.all(chunk.map((host) => login(host, Math.min(hostTimeoutMs, remaining))));
    tried += chunk.length;
    const batch = chunk.map((host, i) => ({ host, result: results[i] }));
    const hit = batch.find(({ result }) => isDefinitive(result));
    if (hit) {
      cache.set(ref, hit.host);
      return { ...hit, tried, source: sources.get(hit.host) ?? 'search' };
    }
    answers.push(...batch);
  }
  cache.delete(ref);
  return { none: true, tried, error: describeMiss(answers, tried, exhausted) };
}

module.exports = {
  POOLER_REGIONS,
  poolerRegion,
  candidateHosts,
  parsePoolerHints,
  parseRegionHints,
  isAuthRejection,
  findTargetPooler,
  poolerHostCache,
};
