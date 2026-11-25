const test = require('node:test');
const assert = require('node:assert/strict');
const { oidcData, check } = require('./helpers');

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const ctx = { resourceToken: `${b64({ alg: 'RS256' })}.${b64({ sub: 'x' })}.sig` };

const run = (postgres_login_no_jit) =>
  check('jit_postgres_login_no_jit', { data: oidcData({ jit: { resource_token: {}, postgres_login_no_jit } }), ctx });

test('a password rejection without --jit=true is a known-issue warning', async () => {
  const r = await run({ endpoint: 'h:6543', error: 'password authentication failed for user "postgres"', code: '28P01' });
  assert.equal(r.status, 'warn');
  assert.match(r.detail, /CTRL-2151/);
});

test('other login errors without --jit=true still fail', async () => {
  const r = await run({ endpoint: 'h:6543', error: 'connect ECONNREFUSED' });
  assert.equal(r.status, 'fail');
});

test('a successful login without --jit=true passes', async () => {
  const r = await run({ endpoint: 'h:6543', current_user: 'postgres' });
  assert.equal(r.status, 'pass');
});
