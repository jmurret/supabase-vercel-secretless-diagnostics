const test = require('node:test');
const assert = require('node:assert/strict');
const { poolerLoginParams } = require('../pooler');

const REF = 'abcdefghijklmnopqrst';
const HOST = 'aws-0-us-east-1.pooler.supabase.com';

test('builds pooler login parameters from the synced env vars', () => {
  assert.deepEqual(poolerLoginParams({ POSTGRES_POOLER_HOST: HOST, SUPABASE_PROJECT_REF: REF }, 'postgres'), {
    host: HOST,
    port: 6543,
    user: `postgres.${REF}`,
    database: 'postgres',
  });
});

test('builds the user from an explicit ref', () => {
  const p = poolerLoginParams({ POSTGRES_POOLER_HOST: HOST }, 'postgres', 'zyxwvutsrqponmlkjihg');
  assert.equal(p.user, 'postgres.zyxwvutsrqponmlkjihg');
  assert.equal(p.host, HOST);
});

test('uses POSTGRES_DATABASE when set', () => {
  const p = poolerLoginParams({ POSTGRES_POOLER_HOST: HOST, SUPABASE_PROJECT_REF: REF, POSTGRES_DATABASE: 'app' }, 'postgres');
  assert.equal(p.database, 'app');
});

test('ignores POSTGRES_URL', () => {
  const p = poolerLoginParams({ POSTGRES_URL: `postgres://postgres.${REF}:x@other:5432/postgres` }, 'postgres');
  assert.match(p.skipped, /POSTGRES_POOLER_HOST and SUPABASE_PROJECT_REF are not set/);
  assert.match(p.skipped, /Resync/);
});

test('skips when one var is missing', () => {
  assert.match(poolerLoginParams({ POSTGRES_POOLER_HOST: HOST }, 'postgres').skipped, /^SUPABASE_PROJECT_REF is not set/);
  assert.match(poolerLoginParams({ SUPABASE_PROJECT_REF: REF }, 'postgres').skipped, /^POSTGRES_POOLER_HOST is not set/);
});
