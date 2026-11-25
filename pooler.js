const POOLER_PORT = 6543;
const RESYNC_HINT = 'Resync the Supabase integration environment variables in Vercel, then redeploy.';

// OIDC-only resources get no POSTGRES_URL, so the pooler login is built from the non-secret
// POSTGRES_POOLER_HOST and SUPABASE_PROJECT_REF. The pooler finds the project from the user suffix.
function poolerLoginParams(env, role, ref = env.SUPABASE_PROJECT_REF) {
  const missing = [
    ['POSTGRES_POOLER_HOST', env.POSTGRES_POOLER_HOST],
    ['SUPABASE_PROJECT_REF', ref],
  ].filter(([, value]) => !value).map(([name]) => name);
  if (missing.length) {
    return { skipped: `${missing.join(' and ')} ${missing.length > 1 ? 'are' : 'is'} not set. ${RESYNC_HINT}` };
  }
  return {
    host: env.POSTGRES_POOLER_HOST,
    port: POOLER_PORT,
    user: `${role}.${ref}`,
    database: env.POSTGRES_DATABASE || 'postgres',
  };
}

module.exports = { POOLER_PORT, RESYNC_HINT, poolerLoginParams };
