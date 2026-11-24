const test = require('node:test');
const assert = require('node:assert/strict');
const { check } = require('./helpers');

const PASSWORD = 'not-a-real-password';

test('passes with only public keys', async () => {
  const r = await check('no_static_secret', { env: { SUPABASE_ANON_KEY: 'sb_publishable_x', POSTGRES_POOLER_HOST: 'h' } });
  assert.equal(r.status, 'pass');
});

for (const name of ['POSTGRES_URL', 'POSTGRES_PRISMA_URL', 'POSTGRES_URL_NON_POOLING', 'POSTGRES_PASSWORD']) {
  test(`fails when ${name} is set and reports only its name`, async () => {
    const r = await check('no_static_secret', { env: { [name]: `postgres://u:${PASSWORD}@h:5432/postgres` } });
    assert.equal(r.status, 'fail');
    assert.deepEqual(r.actual, [name]);
    assert.ok(!JSON.stringify(r).includes(PASSWORD));
  });
}

test('still warns for a secret key alone', async () => {
  const r = await check('no_static_secret', { env: { SUPABASE_SERVICE_ROLE_KEY: 'sb_secret_x' } });
  assert.equal(r.status, 'warn');
  assert.deepEqual(r.actual, ['SUPABASE_SERVICE_ROLE_KEY']);
});

test('fails and lists both secret keys and Postgres vars', async () => {
  const r = await check('no_static_secret', {
    env: { SUPABASE_SECRET_KEY: 'sb_secret_x', POSTGRES_PASSWORD: PASSWORD },
  });
  assert.equal(r.status, 'fail');
  assert.deepEqual(r.actual, ['SUPABASE_SECRET_KEY', 'POSTGRES_PASSWORD']);
  assert.ok(!JSON.stringify(r).includes(PASSWORD));
});
