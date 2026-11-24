const test = require('node:test');
const assert = require('node:assert/strict');
const { REF, oidcData, check } = require('./helpers');

const POOLER = 'aws-0-us-east-1.pooler.supabase.com';

test('pooler_host passes for a pooler host name', async () => {
  const r = await check('pooler_host', { env: { POSTGRES_POOLER_HOST: POOLER } });
  assert.equal(r.status, 'pass');
  assert.equal(r.actual, POOLER);
});

test('pooler_host fails when unset and tells the user to resync', async () => {
  const r = await check('pooler_host', { env: {} });
  assert.equal(r.status, 'fail');
  assert.match(r.detail, /Resync/);
});

for (const bad of [`https://${POOLER}`, `${POOLER}:6543`, `${POOLER}/postgres`, 'db.abc.supabase.co']) {
  test(`pooler_host fails for ${bad}`, async () => {
    const r = await check('pooler_host', { env: { POSTGRES_POOLER_HOST: bad } });
    assert.equal(r.status, 'fail');
  });
}

test('project_ref passes when it matches SUPABASE_URL', async () => {
  const r = await check('project_ref', { env: { SUPABASE_PROJECT_REF: REF } });
  assert.equal(r.status, 'pass');
});

test('project_ref fails when unset', async () => {
  const r = await check('project_ref', { env: {} });
  assert.equal(r.status, 'fail');
  assert.match(r.detail, /Resync/);
});

for (const bad of ['ABCDEFGHIJKLMNOPQRST', 'abc', 'abcdefghijklmnopqrs1']) {
  test(`project_ref fails for malformed ref ${bad}`, async () => {
    const r = await check('project_ref', { env: { SUPABASE_PROJECT_REF: bad } });
    assert.equal(r.status, 'fail');
  });
}

test('project_ref fails when it differs from SUPABASE_URL', async () => {
  const r = await check('project_ref', { env: { SUPABASE_PROJECT_REF: 'zyxwvutsrqponmlkjihg' } });
  assert.equal(r.status, 'fail');
  assert.match(r.detail, /different Supabase projects/);
});

test('project_ref warns when SUPABASE_URL has no ref', async () => {
  const data = oidcData({ environment: { supabase_url: { env_var: 'SUPABASE_URL', valid: true, host: 'db.example.com', project_ref: null } } });
  const r = await check('project_ref', { data, env: { SUPABASE_PROJECT_REF: REF } });
  assert.equal(r.status, 'warn');
});
