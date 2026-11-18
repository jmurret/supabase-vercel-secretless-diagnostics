# supabase-hello-world
## `GET /api/diagnostics`

Returns JSON (non-secret) describing the current auth context:

- `server_credential` – how the server talks to Supabase:
  - `auth_path: "vercel_oidc"` when a Vercel OIDC token is available (`x-vercel-oidc-token`
    header, falling back to `VERCEL_OIDC_TOKEN`). The token is passed to Supabase via
    third-party auth, and its claims (`iss`, `sub`, `aud`, `owner`, `project`, `environment`, …)
    are shown.
  - `auth_path: "vercel_integration_keys"` otherwise, showing which env var is used
    (`SUPABASE_SERVICE_ROLE_KEY` / `SUPABASE_ANON_KEY` / `NEXT_PUBLIC_SUPABASE_ANON_KEY`) and its role.
- `end_user` – when an `Authorization: Bearer <supabase-jwt>` header is sent, the validated user
  (id, email, role, providers) and token claims.
- `access` – for each identity, whether known tables (`countries`) can be read, with row counts.
- `database_identity` – for each identity, the result of the `public.whoami_vercel()` RPC
  (`supabase/migrations/20261118214000_add-whoami_vercel.sql`), i.e. how Supabase resolved the token on the
  database side: `current_user` (the Postgres role PostgREST switched to), `auth.role()`,
  `auth.uid()`, safe `request.jwt.claims`, whether the role bypasses RLS, and per-table
  RLS/privilege info for the `public` schema. You can also call it directly:
  `select public.whoami_vercel();` in SQL, or `POST /rest/v1/rpc/whoami_vercel` with your token.

Raw tokens, keys and signatures are never returned. Claims are decoded for display only; Supabase
makes the actual access decisions.

To use Vercel OIDC tokens with Supabase, add Vercel's issuer (`https://oidc.vercel.com/<team>`) as a
third-party auth provider in your Supabase project, and write RLS policies that allow that identity.
Vercel tokens don't include a `role` claim, so Supabase may reject them or treat them as `anon`
unless you configure it to accept them.
