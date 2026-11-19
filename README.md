# supabase-hello-world
## `GET /api/diagnostics`

Returns JSON (non-secret) shaped as `{ "data": {...}, "checks": {...} }`. Always HTTP 200.

`data` describes the current auth context:

- `server_credential` – how the server talks to Supabase:
  - `auth_path: "vercel_oidc_marketplace"` when a Vercel OIDC token is available
    (`x-vercel-oidc-token` header, falling back to `getVercelOidcToken()` from
    `@vercel/functions/oidc`). The OIDC token is exchanged for a Marketplace resource token via
    `POST https://api.vercel.com/v1/integrations/marketplace/resources/<MARKETPLACE_RESOURCE_ID>/token`,
    and that resource token is sent to Supabase. Both tokens' headers (`alg`, `kid`) and safe
    claims are shown under `oidc` and `resource_token`, plus mint errors (status/body) if the
    exchange fails. Minted tokens are cached until a minute before they expire.
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

Set `MARKETPLACE_RESOURCE_ID` to the Supabase Marketplace resource ID. Don't send the raw Vercel
OIDC token to Supabase directly — Supabase doesn't trust Vercel's signing keys and rejects it
with `PGRST301` ("No suitable key or wrong key type").

### `checks`

[`checks.js`](./checks.js) validates `data` against the Vercel Marketplace OIDC (secretless) spec:

```json
{
  "spec": "Vercel Marketplace OIDC (spec updated Nov 18)",
  "summary": { "status": "fail", "passed": 19, "warned": 1, "failed": 1, "skipped": 3 },
  "results": [
    { "id": "resource_role", "group": "resource_token", "description": "...",
      "status": "fail", "expected": "authenticated", "actual": null, "detail": "..." }
  ]
}
```

Each result is `pass`, `warn`, `fail` or `skip` (skipped because an earlier step failed).
`summary.status` is the worst status present.

| Group | Checks |
|---|---|
| `path` | `auth_path` (OIDC path in use), `no_static_secret` (warn if a service-role/secret key is set) |
| `vercel_oidc` | `oidc_present`, `oidc_iss`, `oidc_alg_kid` (RS256 + kid), `oidc_not_expired`, `oidc_owner_project` |
| `mint` | `mint_ok` (with hints for spec error codes such as `resource_oidc_not_enabled`) |
| `resource_token` | `resource_alg_kid`, `resource_required_claims` (aud, sub, act, iat, nbf, exp), `resource_iss`, `resource_aud`, `resource_sub`, `resource_role`, `resource_act` (act.sub = deployment OIDC sub), `resource_environment`, `resource_time` (60 s tolerance), `resource_lifetime` (≤ 15 min), `resource_size` (≤ 4 KB), `resource_signature` (verified against `<iss>/jwks.json`) |
| `database` | `db_accepted` (PGRST301 → add the issuer as a Custom OIDC third-party provider), `db_role`, `db_claims_match`, `db_no_rls_bypass` |

Optional env vars for exact matches (otherwise the check only validates the format and warns):

- `VERCEL_INTEGRATION_ID` (`oac_…`) → expected `iss` = `https://integrations.vercel.com/<id>`
- `VERCEL_INTEGRATION_INSTALLATION_ID` (`icfg_…`) → expected `aud`
- `SUPABASE_RESOURCE_ID` → expected `sub`
