# supabase-vercel-secretless-daignostics

## Set up

Use a Vercel project that has the Supabase Marketplace integration. Then do these steps:

1. Link the project: `vercel link`.
2. Run `pnpm run bootstrap`. The script is safe to run again. It does this:
   - Sets `MARKETPLACE_RESOURCE_ID` to the Supabase resource that is connected to the linked project.
   - Removes `SUPABASE_JWT_SECRET`, `SUPABASE_SECRET_KEY` and `SUPABASE_SERVICE_ROLE_KEY` from the project. Code that uses these static secrets stops working.
   - Replaces `.env.local` with the Development variables. It warns if `POSTGRES_URL` is not set.
   - Applies the files in `supabase/migrations` (`public.whoami_vercel()` and `public.countries`). It asks once for a Supabase access token. Use an experimental API token. The token is hidden and is not saved. Press Enter to skip it, or set `SUPABASE_ACCESS_TOKEN` to skip the prompt. The schema step needs the token when the schema is missing.
   - Offers to enable the Supabase IPv4 add-on when `db.<project host>` has no IPv4 address. The add-on is paid. Without it, the direct login check is skipped on Vercel. If the request fails, the script only prints a warning and the manual command.
   - Enables JIT access and SSL enforcement with the same token, until CTRL-2145 and CTRL-2146 are done. If this fails or you skipped the token, the script only prints a warning. Then run `pnpm run enable-jit`. See [Enable JIT by hand](#enable-jit-by-hand-temporary).
   - Redeploys the latest Ready production deployment, because a deployment only sees the variables that existed when it was built. If this fails, the script only prints a warning and the manual command.

## `GET /`

Dashboard ([`dashboard.js`](./dashboard.js)) that calls `/api/diagnostics` and lists every check, grouped,
colored by status: green = pass, yellow = warning, red = fail, gray = skipped. Click a summary pill to show
only that status (click it again, or "Overall", to show all); the filter is kept in the URL hash (e.g. `/#fail`).

## `GET /api/diagnostics`

Handled by [`api/diagnostics.js`](./api/diagnostics.js) (a `(req, res)` handler used by `server.js` locally
and deployable as a Vercel function). Returns JSON (non-secret) shaped as `{ "data": {...}, "checks": {...} }`. Always HTTP 200.

`data` describes the current auth context:

- `server_credential` – how the server talks to Supabase:
  - `auth_path: "vercel_oidc_marketplace"` when a Vercel OIDC token is available
    (`x-vercel-oidc-token` header, falling back to `getVercelOidcToken()` from
    `@vercel/functions/oidc`). The OIDC token is exchanged for a Marketplace resource token via
    `POST https://api.vercel.com/v1/integrations/resources/<MARKETPLACE_RESOURCE_ID>/token`,
    and that resource token is sent to Supabase. Both tokens' headers (`alg`, `kid`) and safe
    claims are shown under `oidc` and `resource_token`, plus mint errors (status/body) if the
    exchange fails. This request has no `role` query parameter, so Vercel issues the default role
    of the resource (`service_role`). Minted tokens are cached by resource and role until a minute
    before they expire. `apikey` describes
    the public key sent in the `apikey` header (`SUPABASE_PUBLISHABLE_KEY` /
    `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` / `SUPABASE_ANON_KEY` / `NEXT_PUBLIC_SUPABASE_ANON_KEY`).
    `controls` holds two control calls to `whoami_vercel()`: `apikey_only` (no bearer token, should
    run as `anon`) and `tampered_token` (resource token with a broken signature, should get `401 PGRST301`).
  - `auth_path: "vercel_integration_keys"` otherwise, showing which env var is used
    (`SUPABASE_SERVICE_ROLE_KEY` / `SUPABASE_ANON_KEY` / `NEXT_PUBLIC_SUPABASE_ANON_KEY`) and its role.
- `jit` – just-in-time database access (OIDC path only). The Management API accepts a token only
  if its role is the same as the requested role. Because of this, the JIT checks use a second
  resource token, minted with `POST .../token?role=postgres`. `resource_token` shows its header and
  safe claims, or the mint error. The default-role token is not used for JIT access.
  `management_api` is `POST <management api>/v1/projects/<ref>/database/jit` (role `postgres`).
  `management_api_default_role` is the same request with the default-role (`service_role`) token.
  It is a control: the Management API must reject it, because the token role is not `postgres`.
  `postgres_login` logs in to the pooler with the JIT token as the password and the startup option
  `--jit=true`. It uses host `POSTGRES_POOLER_HOST`, port 6543, user `postgres.<SUPABASE_PROJECT_REF>`
  and database `POSTGRES_DATABASE` (default `postgres`). It does not use `POSTGRES_URL`. OIDC-only
  resources do not get `POSTGRES_URL`. If `POSTGRES_POOLER_HOST` or `SUPABASE_PROJECT_REF` is not
  set, the login is not attempted: resync the Supabase integration environment variables in Vercel.
  `postgres_login_no_jit` is the same login without the option. `direct_login` logs in as `postgres`
  to `db.<project host>`. It uses the IPv4 address when the host has one (Supabase IPv4 add-on),
  and the IPv6 address otherwise. See [Enable JIT by hand](#enable-jit-by-hand-temporary).
- `environment.supabase_url` – whether `SUPABASE_URL` is set and valid, and the project ref when the
  host is `<ref>.supabase.co`.
- `end_user` – when an `Authorization: Bearer <supabase-jwt>` header is sent, the validated user
  (id, email, role, providers) and token claims.
- `cross_tenant` – the results of the cross-tenant probes and of the control probes on this project.
  Keys and tokens are not included, and a `2xx` response body is not kept. See [Cross-tenant checks](#cross-tenant-checks).
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
  "summary": { "status": "fail", "passed": 19, "warned": 1, "failed": 2, "skipped": 3 },
  "results": [
    { "id": "resource_role", "group": "resource_token", "description": "...",
      "status": "fail", "expected": "service_role", "actual": null, "detail": "..." }
  ]
}
```

Each result is `pass`, `warn`, `fail` or `skip` (skipped because an earlier step failed
or the runtime cannot run the check). `summary.status` is the worst of `fail`, `warn` and `pass`.
`skip` results do not change `summary.status`.

| Group | Checks |
|---|---|
| `config` | `supabase_url`, `apikey_public` (no secret/service-role key in the `apikey` header), `resource_id` (`store_…` / `ir_…`), `pooler_host` (`POSTGRES_POOLER_HOST` is a host name only and contains `.pooler.`), `project_ref` (`SUPABASE_PROJECT_REF` is 20 lowercase letters and equals the ref in `SUPABASE_URL`) |
| `path` | `auth_path` (OIDC path in use), `no_static_secret` (fail if `POSTGRES_URL`, `POSTGRES_PRISMA_URL`, `POSTGRES_URL_NON_POOLING` or `POSTGRES_PASSWORD` is set; warn if a service-role/secret key or `SUPABASE_JWT_SECRET` is set, under any env var name; reports env var names only) |
| `vercel_oidc` | `oidc_present`, `oidc_iss`, `oidc_alg_kid` (RS256 + kid), `oidc_not_expired`, `oidc_owner_project`, `oidc_team` (`VERCEL_TEAM_ID`, if set, = `owner_id`) |
| `mint` | `mint_ok` (with hints for spec error codes such as `resource_oidc_not_enabled`) |
| `resource_token` | `resource_alg_kid`, `resource_required_claims` (aud, sub, act, iat, nbf, exp), `resource_iss`, `resource_aud`, `resource_sub`, `resource_sub_project` (sub = project ref in `SUPABASE_URL`), `resource_role` (`service_role`), `resource_act` (act.sub = deployment OIDC sub), `resource_environment`, `resource_time` (60 s tolerance), `resource_lifetime` (≤ 15 min), `resource_size` (≤ 4 KB), `resource_signature` (verified against `<iss>/jwks.json`) |
| `database` | `db_accepted` (PGRST301 → add the issuer as a Custom OIDC third-party provider), `db_role` (runs as `service_role`), `db_claims_match`, `db_rls_bypass` (`service_role` bypasses RLS), `db_table_access`, `db_anon_control` (apikey only → `anon`), `db_tampered_rejected` (tampered token → `401 PGRST301`) |
| `jit` | `jit_token_role` (the token minted with `?role=postgres` has the role `postgres`), `jit_management_api` (Management API grants JIT access), `jit_default_role_rejected` (Management API rejects JIT access for the default-role token with `403 Token role does not match requested role`), `jit_postgres_login` (pooler login to `POSTGRES_POOLER_HOST:6543` as `postgres.<SUPABASE_PROJECT_REF>` with the JIT token and `--jit=true` runs as `postgres`), `jit_postgres_login_no_jit` (pooler login without `--jit=true`; this check fails until CTRL-2151 is done), `jit_direct_login` (direct login runs as `postgres`; uses the IPv4 address when the host has one, else IPv6; skipped when the host has only an IPv6 address and the runtime has no IPv6 route) |
| `cross_tenant` | `cross_tenant_targets` (`CROSS_TENANT_TARGETS` entries are valid and are other tenants), `cross_tenant_rest`, `cross_tenant_auth_admin`, `cross_tenant_storage`, `cross_tenant_realtime` (other tenants reject this tenant's resource token), `cross_tenant_gateway_coverage` (targets cover api-gateway `v1` and `v2`). See [Cross-tenant checks](#cross-tenant-checks). |

The Supabase integration syncs these non-secret Postgres env vars to the Vercel project. The pooler checks use them:

- `POSTGRES_POOLER_HOST`: the pooler host name, for example `aws-0-us-east-1.pooler.supabase.com`.
- `SUPABASE_PROJECT_REF`: the project ref (20 lowercase letters).
- `POSTGRES_DATABASE`: the database name (`postgres`).
- `POSTGRES_HOST`: the direct host (`db.<ref>.supabase.co`).

The pooler connection string is `postgres://postgres.<SUPABASE_PROJECT_REF>:<token>@<POSTGRES_POOLER_HOST>:6543/<POSTGRES_DATABASE>?sslmode=require`.
OIDC-only resources do not get `POSTGRES_URL`, `POSTGRES_PRISMA_URL`, `POSTGRES_URL_NON_POOLING` or `POSTGRES_PASSWORD`.

Optional env vars for exact matches (otherwise the check only validates the format and warns):

- `VERCEL_INTEGRATION_ID` (`oac_…`) → expected `iss` = `https://integrations.vercel.com/<id>`
- `VERCEL_INTEGRATION_INSTALLATION_ID` (`icfg_…`) → expected `aud`
- `SUPABASE_RESOURCE_ID` → expected `sub`

## Cross-tenant checks

These checks make sure that a resource token for this deployment's tenant (tenant A) gives no access to other tenants. They send the default-role (`service_role`) resource token, the same token that the Data API checks use, to the endpoints of other Supabase projects. Each request sends `apikey: <target key>` and `Authorization: Bearer <token>`. The target key lets the request pass the gateway apikey check, so only the Bearer token decides.

Set `CROSS_TENANT_TARGETS` to a comma-separated list of `<target>=<key>` entries:

- `<target>` is a project ref or a full `https://` URL. For a project ref, the URL is `https://<ref>.` plus the domain of this deployment's `SUPABASE_URL` without its first label. For example, on staging the domain is `supabase.green`.
- `<key>` is the publishable or anon key of that project. It is a public key.

```sh
CROSS_TENANT_TARGETS="abcdefghijklmnopqrst=sb_publishable_...,https://zyxwvutsrqponmlkjihg.supabase.co=eyJ..."
```

If `CROSS_TENANT_TARGETS` is not set, all cross-tenant checks are skipped. An entry for this deployment's own project ref is a configuration error, because it is not a cross-tenant test.

The probes are:

| Check | Request | Rejection |
|---|---|---|
| `cross_tenant_rest` | `GET /rest/v1/` | `401` or `403` |
| `cross_tenant_auth_admin` | `GET /auth/v1/admin/users?per_page=1` | `401` or `403` |
| `cross_tenant_storage` | `GET /storage/v1/bucket` | any `3xx` or `4xx` (Storage can send `400` with an error body) |
| `cross_tenant_realtime` | `POST /realtime/v1/api/broadcast` with one private message on topic `cross-tenant-probe` | any `3xx` or `4xx` |

Each check shows, for each target: the target ref, the gateway version, the control status, the target status and the result.

- A `2xx` response from another tenant means that the tenant accepted tenant A's token. The check fails with `regression: <service> on <ref> (gateway vN) accepted tenant <A>'s token`.
- A network error or a `5xx` response is inconclusive. The check warns.
- The same four probes go to this deployment's own project (own URL and own publishable or anon key) as a positive control. If the control does not return `2xx` for a service, a rejection could mean only that the token is bad. The result for that service is inconclusive and the check warns.

The gateway version comes from the `sb-gateway-version` response header. The values `1` and `1.0` become `v1`, and `2` and `2.0` become `v2`. If the header is missing, the version is `unknown`. `cross_tenant_gateway_coverage` passes when the targets answered with both `v1` and `v2`, and warns otherwise.

Vercel mints resource tokens only for teams on an allow list. Tenant A (this deployment's Vercel team) must be on an allow-listed team, or no token is minted and the cross-tenant checks are skipped.

## Enable JIT by hand (temporary)

The JIT checks need JIT access and SSL enforcement on the Supabase project. The platform will enable both automatically for Vercel Marketplace resources, but it does not do this yet:

- [CTRL-2146](https://linear.app/supabase/issue/CTRL-2146/configure-jit-when-creating-vercel-marketplace-resources): configure JIT when Vercel Marketplace resources are created.
- [CTRL-2145](https://linear.app/supabase/issue/CTRL-2145/support-backfill-on-existing-projects): backfill existing projects.
- [CTRL-2151](https://linear.app/supabase/issue/CTRL-2151/make-pooler-jit-login-work-without-the-jittrue-client-option): pooler JIT login without the `--jit=true` client option.

`pnpm run bootstrap` enables both when it has an access token. To run only this step, for example after you skipped the token:

1. Do the steps in [Set up](#set-up) to link the project and pull `.env.local` (`pnpm run bootstrap`).
2. Run `pnpm run enable-jit`.

The script needs an experimental API token. It enables SSL enforcement, then JIT access, and waits until the change is applied. It is safe to run again.

The pooler can need some minutes more before it accepts JIT logins.

Until CTRL-2151 is done, apps must send `options=--jit=true` through the pooler. The `jit_postgres_login_no_jit` check fails until then. Without the Supabase IPv4 add-on, the direct host is IPv6 only. Vercel functions have no IPv6 route, so the direct check is skipped there unless the project has the IPv4 add-on. `pnpm run bootstrap` offers to enable the add-on.
