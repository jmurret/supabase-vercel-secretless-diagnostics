const test = require('node:test');
const assert = require('node:assert/strict');
const { POOLER_REGIONS, poolerRegion, candidateHosts, parsePoolerHints, parseRegionHints, findTargetPooler } = require('../pooler-discovery');

test('parseRegionHints keeps only known regions for well-formed refs', () => {
  assert.deepEqual(parseRegionHints('abc:eu-west-2, def:ap-southeast-1'), { abc: 'eu-west-2', def: 'ap-southeast-1' });
  assert.deepEqual(parseRegionHints('abc:us-east-9,Bad!:us-east-1,ghi:us-east-1:x,jkl:,:us-east-1,mno'), {});
  assert.deepEqual(parseRegionHints(undefined), {});
  assert.ok(POOLER_REGIONS.every((region) => parseRegionHints(`abc:${region}`).abc === region));
});

test('poolerRegion reads the region from a pooler host', () => {
  assert.equal(poolerRegion('aws-0-ap-southeast-1.pooler.supabase.com'), 'ap-southeast-1');
  assert.equal(poolerRegion('aws-1-us-east-1.pooler.supabase.green'), 'us-east-1');
  for (const host of ['db.abc.supabase.co', 'pooler.supabase.com', '', null, undefined]) assert.equal(poolerRegion(host), null, String(host));
});

const OWN = 'aws-0-us-east-1.pooler.supabase.com';
const REF = 'zyxwvutsrqponmlkjihg';
const NOT_FOUND = { error: 'Tenant or user not found', code: 'XX000' };
const AUTH_FAILED = { error: 'password authentication failed for user "postgres"', code: '28P01' };

function stubLogin(answers) {
  const calls = [];
  const login = async (host, timeoutMs) => {
    calls.push({ host, timeoutMs });
    return answers[host] ?? NOT_FOUND;
  };
  return { login, calls };
}

const find = (opts) => findTargetPooler({ ownHost: OWN, ref: REF, cache: new Map(), ...opts });

test('candidate hosts start with the own host and keep its suffix', () => {
  const hosts = candidateHosts(OWN);
  assert.equal(hosts[0], OWN);
  assert.equal(hosts[1], 'aws-0-us-east-2.pooler.supabase.com');
  assert.ok(hosts.includes('aws-0-ap-southeast-2.pooler.supabase.com'));
  assert.ok(hosts.includes('aws-1-us-east-1.pooler.supabase.com'));
  assert.equal(hosts.length, POOLER_REGIONS.length * 2);
  assert.ok(hosts.every((h) => h.endsWith('.pooler.supabase.com')));
  assert.ok(hosts.indexOf('aws-0-ap-northeast-2.pooler.supabase.com') < hosts.indexOf('aws-1-us-east-1.pooler.supabase.com'));
  assert.ok(candidateHosts('aws-1-eu-west-1.pooler.supabase.green').every((h) => h.endsWith('.pooler.supabase.green')));
  assert.equal(candidateHosts('aws-1-eu-west-1.pooler.supabase.green')[1].startsWith('aws-1-'), true);
});

test('a host that does not match the pattern is the only candidate', () => {
  assert.deepEqual(candidateHosts('pooler.example.com'), ['pooler.example.com']);
  assert.deepEqual(candidateHosts(undefined), []);
});

test('parses pooler hints and drops malformed entries', () => {
  assert.deepEqual(parsePoolerHints(`${REF}:${OWN}, bad entry, :x, ref:host:extra, Bad_Ref!:h`), { [REF]: OWN });
  assert.deepEqual(parsePoolerHints(null), {});
});

test('stops at the first definitive answer', async () => {
  const { login, calls } = stubLogin({ 'aws-0-eu-west-1.pooler.supabase.com': AUTH_FAILED });
  const found = await find({ login });
  assert.equal(found.host, 'aws-0-eu-west-1.pooler.supabase.com');
  assert.equal(found.source, 'search');
  assert.equal(found.tried, 8);
  assert.equal(calls.length, 8);
  assert.ok(!calls.some((c) => c.host === 'aws-0-eu-west-3.pooler.supabase.com'));
});

test('a connected login is definitive', async () => {
  const { login } = stubLogin({ [OWN]: { current_user: 'postgres' } });
  const found = await find({ login });
  assert.deepEqual([found.host, found.tried, found.result.current_user], [OWN, 4, 'postgres']);
});

test('not found and DNS failures on every host are inconclusive', async () => {
  const { login, calls } = stubLogin({ 'aws-1-eu-west-1.pooler.supabase.com': { error: 'getaddrinfo ENOTFOUND x', code: 'ENOTFOUND' } });
  const found = await find({ login });
  assert.equal(found.none, true);
  assert.equal(found.tried, POOLER_REGIONS.length * 2);
  assert.equal(found.error, `target not found on any regional pooler tried (${POOLER_REGIONS.length * 2} hosts)`);
  assert.equal(calls.length, POOLER_REGIONS.length * 2);
});

test('other errors do not stop the search and show in the summary', async () => {
  const { login } = stubLogin({ [OWN]: { error: 'timeout expired' }, 'aws-0-eu-west-2.pooler.supabase.com': AUTH_FAILED });
  const found = await find({ login });
  assert.equal(found.host, 'aws-0-eu-west-2.pooler.supabase.com');
  const none = await find({ login: async () => ({ error: 'connect ECONNREFUSED' }) });
  assert.match(none.error, /^no regional pooler answered \(34 hosts tried\); first error from aws-0-us-east-1\.pooler\.supabase\.com: connect ECONNREFUSED/);
});

test('a hint is tried first and alone', async () => {
  const hint = 'aws-1-eu-west-2.pooler.supabase.com';
  const { login, calls } = stubLogin({ [hint]: AUTH_FAILED });
  const found = await find({ login, hint });
  assert.deepEqual([found.host, found.source, found.tried, calls.length], [hint, 'hint', 1, 1]);
});

test('a hint outside the candidate hosts is ignored', async () => {
  const { login, calls } = stubLogin({ [OWN]: AUTH_FAILED });
  for (const hint of ['evil.example.com', 'aws-0-us-east-1.pooler.evil.com', 'aws-0-mars-north-1.pooler.supabase.com']) {
    const found = await find({ login, hint });
    assert.equal(found.host, OWN);
    assert.equal(found.source, 'search');
  }
  assert.ok(calls.every((c) => candidateHosts(OWN).includes(c.host)));
});

test('a stale hint falls back to the search', async () => {
  const hint = 'aws-1-eu-west-2.pooler.supabase.com';
  const { login, calls } = stubLogin({ 'aws-0-us-west-2.pooler.supabase.com': AUTH_FAILED });
  const found = await find({ login, hint });
  assert.equal(found.host, 'aws-0-us-west-2.pooler.supabase.com');
  assert.equal(calls[0].host, hint);
  assert.equal(found.tried, 5);
});

test('a cache hit skips the search, and a search fills the cache', async () => {
  const cache = new Map();
  const host = 'aws-0-eu-central-1.pooler.supabase.com';
  const first = stubLogin({ [host]: AUTH_FAILED });
  await find({ login: first.login, cache });
  assert.equal(cache.get(REF), host);
  const second = stubLogin({ [host]: AUTH_FAILED });
  const found = await find({ login: second.login, cache });
  assert.deepEqual([found.source, found.tried, second.calls.length], ['cache', 1, 1]);
});

test('a failed search clears a stale cache entry', async () => {
  const cache = new Map([[REF, OWN]]);
  const { login } = stubLogin({});
  const found = await find({ login, cache });
  assert.equal(found.none, true);
  assert.equal(cache.has(REF), false);
});

test('the time budget stops the search', async () => {
  let t = 0;
  const found = await find({
    login: async () => {
      t += 2500;
      return NOT_FOUND;
    },
    now: () => t,
    budgetMs: 20_000,
  });
  assert.equal(found.tried, 8);
  assert.match(found.error, /\(8 hosts\); time budget used up$/);
});

test('an unmatched own host is tried alone', async () => {
  const { login, calls } = stubLogin({});
  const found = await findTargetPooler({ ownHost: 'pooler.example.com', ref: REF, cache: new Map(), login });
  assert.equal(found.error, 'target not found on any regional pooler tried (1 host)');
  assert.equal(calls.length, 1);
});

test('no own host skips the search', async () => {
  const found = await findTargetPooler({ ownHost: undefined, ref: REF, cache: new Map(), login: () => assert.fail('no login') });
  assert.match(found.skipped, /POSTGRES_POOLER_HOST is not set/);
});
