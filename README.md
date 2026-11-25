# supabase-vercel-secretless-daignostics

## Set up

Use a Vercel project that has the Supabase Marketplace integration. Then do these steps:

1. Link the project: `vercel link`.
2. Run `pnpm run bootstrap`. The script is safe to run again. It does this:
   - Sets `MARKETPLACE_RESOURCE_ID` to the Supabase resource that is connected to the linked project.
   - Sets `VERCEL_INTEGRATION_ID` (the `oac_…` ID of the integration), `VERCEL_INTEGRATION_INSTALLATION_ID` (the `icfg_…` installation ID) and `SUPABASE_RESOURCE_ID` (the Supabase project ref). The checks use them for exact matches. If the script cannot find a value, it prints a warning and skips that variable.
   - Warns if `SUPABASE_JWT_SECRET`, `SUPABASE_SECRET_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, `POSTGRES_URL`, `POSTGRES_PRISMA_URL`, `POSTGRES_URL_NON_POOLING` or `POSTGRES_PASSWORD` is set on the project. An OIDC-only resource must not sync these static secrets. The script does not remove them, so the `no_static_secret` check can show a resource that syncs them.
   - Reads the Supabase project ref and the integration slug from the Vercel store of the resource. It does not need any Supabase variable value, so the Supabase integration does not need to be connected to the Development environment. The slug `supabase` selects production. The slug `supabase-staging` selects staging. For any other slug, the script asks the Management API with your access token. Without a token, it uses production and prints a warning. To skip this lookup, set `SUPABASE_URL` (for example `https://<ref>.supabase.co`) in the shell before you run the script.
   - Replaces `.env.local` with the Development variables. You need them only to run the app locally. If the integration is not connected to Development, `.env.local` has no Supabase values. The script warns if `POSTGRES_POOLER_HOST` or `SUPABASE_PROJECT_REF` is not set on the Vercel project.
   - Applies the files in `supabase/migrations` (`public.whoami_vercel()` and `public.countries`). It asks once for a Supabase access token. Use an experimental API token. The token is hidden and is not saved. Press Enter to skip it, or set `SUPABASE_ACCESS_TOKEN` to skip the prompt. The schema step checks if the schema exists with the token. Without a token, it checks with the publishable key in `.env.local`, or skips the check. It needs the token to apply the migrations.
   - Offers to enable the Supabase IPv4 add-on when `db.<project host>` has no IPv4 address. The add-on is paid. Without it, the direct login check is skipped on Vercel. If the request fails, the script only prints a warning and the manual command.
   - Enables JIT access and SSL enforcement with the same token, until CTRL-2145 and CTRL-2146 are done. If this fails or you skipped the token, the script only prints a warning. Then run `pnpm run enable-jit`. See [Enable JIT by hand](#enable-jit-by-hand-temporary).
   - With an access token, reads the legacy anon key of this project from the Management API (`GET /v1/projects/<ref>/api-keys`) and sets `SUPABASE_ANON_KEY` to it. It does not change `SUPABASE_ANON_KEY` if the Vercel project already has it. If the key cannot be read (for example, legacy keys are disabled), the script prints a warning. The Storage S3 check is then inconclusive. The script never prints the key.
   - With a terminal, asks for optional cross-tenant targets and sets `CROSS_TENANT_TARGETS`. For each target, it asks for a project ref. With an access token, it reads the publishable key of the target from the Management API. If the token cannot read it, the script asks for the key. It checks that the project accepts the key in the same environment (production or staging) as this project. With an access token, it also prints if the target is in the same organization. Then it gets the legacy anon key of the target for the Storage S3 check. It reads the key with the access token. If the token cannot read it, the script asks for the key. The input is hidden. Leave it empty to skip. The script adds the key to the entry as `<ref>=<key>:<legacy anon key>`. Leave the first ref empty to skip. If `CROSS_TENANT_TARGETS` is already set, an empty answer keeps it. See [Cross-tenant checks](#cross-tenant-checks).
   - Redeploys the latest Ready production deployment, because a deployment only sees the variables that existed when it was built. If this fails, the script only prints a warning and the manual command.

## `GET /`

Dashboard ([`dashboard.js`](./dashboard.js)) that calls `/api/diagnostics` and `/api/cross-tenant` at the same
time and lists every check, grouped, colored by status: green = pass, yellow = warning, red = fail, gray = skipped.
Click a summary pill to show only that status (click it again, or "Overall", to show all); the filter is kept in
the URL hash (e.g. `/#fail`).

The cross-tenant probes can take up to 20 seconds. The dashboard shows the `/api/diagnostics` checks when that
response arrives, with a dashed gray "Loading…" row for the `cross_tenant` group. When `/api/cross-tenant` answers
(the dashboard sends the saved pooler hints), it replaces the row with the `cross_tenant` checks and updates the
summary pills. If that call fails, the row shows a warning with the error message.

The `cross_tenant_storage_s3` check needs the region of each target, so it has its own endpoint,
`/api/cross-tenant-s3`. Until it answers, the dashboard shows the row "Loading… (waiting for target region)".
The dashboard keeps the target refs of the last `/api/cross-tenant` response and the pooler hosts in
`localStorage`. If these give a region for every target, the dashboard calls `/api/cross-tenant-s3` at the same
time as the other endpoints. Otherwise, it waits for `/api/cross-tenant`, takes the region of each target from the
pooler host that it found, and then calls `/api/cross-tenant-s3`. If the targets in the response have regions that
the first call did not send, the dashboard calls it again, and the last call gives the row. The S3 check goes in the
`cross_tenant` group, and the summary pills count it. If the call fails, the row shows a warning with the error message.

## `GET /api/diagnostics`

Handled by [`api/diagnostics.js`](./api/diagnostics.js) (a `(req, res)` handler used by `server.js` locally
and deployable as a Vercel function). Returns JSON (non-secret) shaped as `{ "data": {...}, "checks": {...} }`. Always HTTP 200.
The response does not have the `cross_tenant` data or checks. See [`GET /api/cross-tenant`](#get-apicross-tenant).

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
- `gateway_v2` – the requests of `server_credential` that go through the project api-gateway (`access`,
  `database_identity` and, on the OIDC path, `controls`), sent again with the header `sb-forward-traffic: true`.
  The results have the same form as in `server_credential`. `gateway_versions` has, for each request, the
  gateway version from the `sb-gateway-version` response header (`v1`, `v2` or `unknown`). See
  [api-gateway v1 and v2](#api-gateway-v1-and-v2).
- `environment.supabase_url` – whether `SUPABASE_URL` is set and valid, and the project ref when the
  host is `<ref>.supabase.co`.
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
  "summary": { "status": "fail", "passed": 19, "warned": 1, "failed": 2, "skipped": 3 },
  "results": [
    { "id": "resource_role", "group": "resource_token", "description": "...",
      "status": "fail", "expected": "service_role", "actual": null, "detail": "..." }
  ]
}
```

Each result is `pass`, `warn`, `fail` or `skip` (skipped because an earlier step failed
or the runtime cannot run the check). `summary.status` is the worst of `fail`, `warn` and `pass`.
`skip` results do not change `summary.status`. `/api/diagnostics` runs all groups except `cross_tenant`.
`/api/cross-tenant` runs the `cross_tenant` group without `cross_tenant_storage_s3`. `/api/cross-tenant-s3` runs only
`cross_tenant_storage_s3`. The `summary` of each response covers only its own checks.

| Group | Checks |
|---|---|
| `config` | `supabase_url`, `apikey_public` (no secret/service-role key in the `apikey` header), `resource_id` (`store_…` / `ir_…`), `pooler_host` (`POSTGRES_POOLER_HOST` is a host name only and contains `.pooler.`), `project_ref` (`SUPABASE_PROJECT_REF` is 20 lowercase letters and equals the ref in `SUPABASE_URL`) |
| `path` | `auth_path` (OIDC path in use), `gateway_v2_forwarding` (every request with `sb-forward-traffic: true` was answered by api-gateway v2; warns otherwise, for example on a staging deployment without forwarding), `no_static_secret` (fail if `POSTGRES_URL`, `POSTGRES_PRISMA_URL`, `POSTGRES_URL_NON_POOLING` or `POSTGRES_PASSWORD` is set; warn if a service-role/secret key or `SUPABASE_JWT_SECRET` is set, under any env var name; reports env var names only) |
| `vercel_oidc` | `oidc_present`, `oidc_iss`, `oidc_alg_kid` (RS256 + kid), `oidc_not_expired`, `oidc_owner_project`, `oidc_team` (`VERCEL_TEAM_ID`, if set, = `owner_id`) |
| `mint` | `mint_ok` (with hints for spec error codes such as `resource_oidc_not_enabled`) |
| `resource_token` | `resource_alg_kid`, `resource_required_claims` (aud, sub, act, iat, nbf, exp), `resource_iss`, `resource_aud`, `resource_sub`, `resource_sub_project` (sub = project ref in `SUPABASE_URL`), `resource_role` (`service_role`), `resource_act` (act.sub = deployment OIDC sub), `resource_environment`, `resource_time` (60 s tolerance), `resource_lifetime` (≤ 15 min), `resource_size` (≤ 4 KB), `resource_signature` (verified against `<iss>/jwks.json`) |
| `database` | `db_accepted` (PGRST301 → add the issuer as a Custom OIDC third-party provider), `db_role` (runs as `service_role`), `db_claims_match`, `db_rls_bypass` (`service_role` bypasses RLS), `db_table_access`, `db_anon_control` (apikey only → `anon`), `db_tampered_rejected` (tampered token → `401 PGRST301`). Each check runs on api-gateway v1 and v2. |
| `jit` | `jit_token_role` (the token minted with `?role=postgres` has the role `postgres`), `jit_management_api` (Management API grants JIT access), `jit_default_role_rejected` (Management API rejects JIT access for the default-role token with `403 Token role does not match requested role`), `jit_postgres_login` (pooler login to `POSTGRES_POOLER_HOST:6543` as `postgres.<SUPABASE_PROJECT_REF>` with the JIT token and `--jit=true` runs as `postgres`), `jit_postgres_login_no_jit` (pooler login without `--jit=true`; this check warns until CTRL-2151 is done), `jit_direct_login` (direct login runs as `postgres`; uses the IPv4 address when the host has one, else IPv6; skipped when the host has only an IPv6 address and the runtime has no IPv6 route) |
| `cross_tenant` | `cross_tenant_targets` (`CROSS_TENANT_TARGETS` entries are valid and are other tenants), `cross_tenant_rest`, `cross_tenant_auth_admin`, `cross_tenant_storage`, `cross_tenant_realtime`, `cross_tenant_storage_s3`, `cross_tenant_realtime_ws` (other tenants reject this tenant's resource token), `cross_tenant_mgmt_jit` (the Management API does not grant JIT access to another tenant for this tenant's JIT token), `cross_tenant_pooler_login` (the pooler of another tenant does not accept a login as `postgres.<target ref>` with this tenant's JIT token and `--jit=true`), `cross_tenant_gateway_coverage` (for each target, the v1 requests reached api-gateway `v1` and the v2 requests reached api-gateway `v2`). See [Cross-tenant checks](#cross-tenant-checks). |

### api-gateway v1 and v2 in `/api/diagnostics`

api-gateway v1 forwards a request with the header `sb-forward-traffic` to api-gateway v2 (see [api-gateway v1 and v2](#api-gateway-v1-and-v2)). The `database` checks use requests to the project api-gateway, so `/api/diagnostics` sends each of these requests twice: once without the header (`v1`, results in `server_credential`) and once with `sb-forward-traffic: true` (`v2`, results in `gateway_v2`).

Each `database` check runs on the `v1` results and on the `v2` results. If the `sb-gateway-version` header of a `v2` request that the check uses is not `v2`, the `v2` result is a warning with the detail `request was not forwarded to api-gateway v2`. The status of the check is the worst of the two results: `fail`, then `warn`, then `pass`. The check is skipped only when both results are skipped. The detail shows the two results, for example `v1 pass, v2 warn (request was not forwarded to api-gateway v2)`. `actual` is `{ "v1": ..., "v2": ... }`, and `variants` has the full `v1` and `v2` results.

The checks that do not use the project api-gateway do not change: the Vercel OIDC token, the mint, the resource token claims, the Management API JIT requests and the Postgres logins. `end_user` (sent only with an `Authorization` header) is not sent to v2, because no check uses it.

The Supabase integration syncs these non-secret Postgres env vars to the Vercel project. The pooler checks use them:

- `POSTGRES_POOLER_HOST`: the pooler host name, for example `aws-0-us-east-1.pooler.supabase.com`.
- `SUPABASE_PROJECT_REF`: the project ref (20 lowercase letters).
- `POSTGRES_DATABASE`: the database name (`postgres`).
- `POSTGRES_HOST`: the direct host (`db.<ref>.supabase.co`).

The pooler connection string is `postgres://postgres.<SUPABASE_PROJECT_REF>:<token>@<POSTGRES_POOLER_HOST>:6543/<POSTGRES_DATABASE>?sslmode=require`.
OIDC-only resources do not get `POSTGRES_URL`, `POSTGRES_PRISMA_URL`, `POSTGRES_URL_NON_POOLING` or `POSTGRES_PASSWORD`.

`pnpm run bootstrap` sets these env vars for exact matches. Without them, the check only validates the format and warns:

- `VERCEL_INTEGRATION_ID` (`oac_…`) → expected `iss` = `https://integrations.vercel.com/<id>`
- `VERCEL_INTEGRATION_INSTALLATION_ID` (`icfg_…`) → expected `aud`
- `SUPABASE_RESOURCE_ID` → expected `sub`

## Cross-tenant checks

These checks make sure that a resource token for this deployment's tenant (tenant A) gives no access to other tenants. They send the default-role (`service_role`) resource token, the same token that the Data API checks use, to the endpoints of other Supabase projects. Each request sends `apikey: <target key>` and `Authorization: Bearer <token>`. The target key lets the request pass the gateway apikey check, so only the Bearer token decides.

Set `CROSS_TENANT_TARGETS` to a comma-separated list of `<target>=<key>[:<legacy anon key>]` entries:

- `<target>` is a project ref or a full `https://` URL. For a project ref, the URL is `https://<ref>.` plus the domain of this deployment's `SUPABASE_URL` without its first label. For example, on staging the domain is `supabase.green`.
- `<key>` is the publishable or anon key of that project. It is a public key.
- `<legacy anon key>` is the legacy anon key of that project. It is optional. Only the Storage S3 check uses it. Put it after a `:`.

```sh
CROSS_TENANT_TARGETS="abcdefghijklmnopqrst=sb_publishable_...:eyJ...,https://zyxwvutsrqponmlkjihg.supabase.co=eyJ..."
```

The legacy anon key is a JWT. Its payload has `role` `anon`. If the payload has a `ref`, the `ref` must be the target ref. Other keys after the `:` are an entry error. If `<key>` is itself a legacy anon key, the S3 check uses it, and the second key is not needed. A target without a legacy anon key is not probed by the Storage S3 check. Its result is inconclusive.

The Storage S3 check also needs `SUPABASE_ANON_KEY` (or `NEXT_PUBLIC_SUPABASE_ANON_KEY`) on this deployment. It must hold the legacy anon key of this project. The S3 control on this tenant uses it. Without it, the control is not sent and the S3 result is inconclusive.

`pnpm run bootstrap` can build this list for you. If `CROSS_TENANT_TARGETS` is not set, all cross-tenant checks are skipped. An entry for this deployment's own project ref is a configuration error, because it is not a cross-tenant test.

### `GET /api/cross-tenant`

Handled by [`api/cross-tenant.js`](./api/cross-tenant.js), with the same handler style as `/api/diagnostics`. The probes can take up to 20 seconds, because of the JIT pooler discovery. Because of this, they are not part of `/api/diagnostics`.

The response is `{ "data": {...}, "checks": {...} }`:

- `data.cross_tenant` has the results of the cross-tenant probes and of the control probes on this project. Keys and tokens are not included, and a `2xx` response body is not kept.
- `data.jit` has `management_api` and `postgres_login`, the two JIT results that the cross-tenant checks use as controls.
- `checks` has the `cross_tenant` group without `cross_tenant_storage_s3`. `checks.summary` counts only these checks.

The query parameter `pooler_hints` is a list of `<target ref>:<pooler host>` entries, separated by commas. The pooler check tries these hosts first. The dashboard saves the hosts that answered and sends them on the next load.

For each target, `data.cross_tenant.targets[].jit_pooler` has the pooler host that answered (`pooler_host`) and its region (`region`, from `aws-<n>-<region>.pooler...`). The dashboard sends this region to `/api/cross-tenant-s3`.

### `GET /api/cross-tenant-s3`

Handled by [`api/cross-tenant-s3.js`](./api/cross-tenant-s3.js), with the same handler style. It runs only the `cross_tenant_storage_s3` probes, because the SigV4 signature needs the region of the target, and the region is known only after the pooler search of `/api/cross-tenant`.

The query parameter `regions` is a list of `<target ref>:<region>` entries, separated by commas, for example `?regions=zyxwvutsrqponmlkjihg:eu-west-2`. The endpoint keeps only the regions in the list of Supabase AWS regions (`POOLER_REGIONS` in [`pooler-discovery.js`](./pooler-discovery.js)) and only well-formed refs. A region for a ref that is not in `CROSS_TENANT_TARGETS` is not used, and `data.cross_tenant_s3.ignored_regions` lists the ref. A target without a valid region is not probed: its result is inconclusive with the reason `target region unknown`. The endpoint does not guess a region. The control on this tenant uses the region of `POSTGRES_POOLER_HOST`. If that host does not name a region, the control is not sent and the results are inconclusive.

The response is `{ "data": { "cross_tenant_s3": {...} }, "checks": {...} }`. `checks` has only `cross_tenant_storage_s3` (group `cross_tenant`). `data.cross_tenant_s3` has the same form as `data.cross_tenant`, with the region of each target (`targets[].region`) and of this tenant (`own.region`). The endpoint also sends `GET /auth/v1/health` to each target.

The probes are:

| Check | Request | Rejection |
|---|---|---|
| `cross_tenant_rest` | `GET /rest/v1/countries?select=*&limit=1` | `401` or `403` |
| `cross_tenant_auth_admin` | `GET /auth/v1/admin/users?per_page=1` | `401` or `403` |
| `cross_tenant_storage` | `GET /storage/v1/bucket` | any `3xx` or `4xx` (Storage can send `400` with an error body) |
| `cross_tenant_realtime` | `POST /realtime/v1/api/broadcast` with one private message on topic `cross-tenant-probe` | any `3xx` or `4xx` |

Two more checks use the default-role token in a different way. They show the same fields for each target, with the same redaction, target health check and control on this tenant. `cross_tenant_storage_s3` goes through the api-gateway and has a v1 and a v2 request, as the checks above. `cross_tenant_realtime_ws` sends only a v1 request, and `cross_tenant_gateway_coverage` ignores it. The Node.js `WebSocket` can send the `sb-forward-traffic` header, but the client cannot read the headers of the websocket upgrade response. Because of this, the check cannot tell which gateway answered. The v2 path of Realtime is checked by `cross_tenant_realtime` (the broadcast request).

| Check | Request | Rejection |
|---|---|---|
| `cross_tenant_storage_s3` | `GET /storage/v1/s3/` (S3 `ListBuckets`, path style) signed with AWS SigV4. The access key id is the target ref. The secret access key is the legacy anon key of the target. The token is the session token (`x-amz-security-token`). | `401` or `403` with an S3 error, such as `AccessDenied`. The S3 error code is in the result. `InvalidAccessKeyId`, `SignatureDoesNotMatch` and `InvalidSignature` give a warning, because the target rejected the key or signature before it checked the token. A `2xx` response fails the check. |
| `cross_tenant_realtime_ws` | Websocket join of a private channel `vercel-oidc-xtenant-<random>` with `@supabase/supabase-js`. The client uses the target key, and `realtime.setAuth` sets the token. | `CHANNEL_ERROR`. The error message is in the result. `SUBSCRIBED` fails the check. No answer in 8 seconds (`TIMED_OUT`) is inconclusive. |

For `cross_tenant_storage_s3`, the signature uses the region of the project. The target region comes from the `regions` query parameter of [`/api/cross-tenant-s3`](#get-apicross-tenant-s3) (`region_source` `regions`). The control region comes from `POSTGRES_POOLER_HOST` (`control_region_source` `own_pooler_host`). Without a target region, the result is inconclusive (`target region unknown`). The control uses the same request on this tenant, with the legacy anon key from `SUPABASE_ANON_KEY` as the secret. Storage S3 accepts only the legacy anon key as the secret, so a publishable key gives `SignatureDoesNotMatch`. A target without a legacy anon key, or a missing key for this tenant, is not probed. The result is inconclusive and states which key to add.

For `cross_tenant_realtime_ws`, the control joins a private channel on this tenant. It can fail with `CHANNEL_ERROR` if this project has no policy on `realtime.messages` for the token. The control error shows the message.

Two more checks use the JIT token (role `postgres`, the same token as the `jit` checks). They are in the same group. They do not use the gateway version, and `cross_tenant_gateway_coverage` ignores them. They are skipped when the JIT token was not minted. They show the same fields for each target. The JIT token is removed from all error text.

| Check | Request | Rejection |
|---|---|---|
| `cross_tenant_mgmt_jit` | `POST <management api>/v1/projects/<target ref>/database/jit`, with the same body as `jit_management_api` | `401`, `403` or `404`. A `2xx` response fails the check. The control is the `jit_management_api` result. If it did not succeed, the result is inconclusive. |
| `cross_tenant_pooler_login` | Pooler login as `postgres.<target ref>` with the JIT token as the password and `--jit=true`, then `select current_user` | An authentication error (`28P01`, `28000` or `password authentication failed`). A login that connects fails the check. The control is the `jit_postgres_login` result. If it did not run as `postgres`, the result is inconclusive. It is skipped when `POSTGRES_POOLER_HOST` is not set. |

A pooler knows only the projects of its own region. The pooler check first tries `POSTGRES_POOLER_HOST`. If the pooler answers `Tenant or user not found` or the host does not exist, it tries other regional pooler hosts with the same suffix, `aws-0-` and `aws-1-` names, four at a time, for at most 20 seconds. It stops at the first host that connects or gives an authentication error. If no host gives such an answer, the result is inconclusive (`target not found on any regional pooler tried`). If `POSTGRES_POOLER_HOST` does not have the form `aws-<n>-<region>.pooler.<suffix>`, only that host is tried. The host that answered is cached for the life of the function instance. The dashboard also keeps it in `localStorage` and sends it as `?pooler_hints=<ref>:<host>,...`. The server uses a hint only when it is one of the hosts it would try itself. The result shows the host that answered, how many hosts were tried and whether the host came from the cache, a hint or the search.

### api-gateway v1 and v2

api-gateway v1 forwards a request that has the header `sb-forward-traffic` (any value except `false`) to api-gateway v2. Production has forwarding configured, so v2 can be reached on every project, also when v2 serves no project directly. Staging can have no forwarding.

Each check that goes through the api-gateway over HTTP (`cross_tenant_rest`, `cross_tenant_auth_admin`, `cross_tenant_storage`, `cross_tenant_realtime` and `cross_tenant_storage_s3`) sends two requests to each target:

- `v1`: the request without the header.
- `v2`: the same request with `sb-forward-traffic: true`. For Storage S3, the header is signed with the other headers.

The control on this tenant also has a `v1` and a `v2` request. The `v1` target result uses the `v1` control, and the `v2` target result uses the `v2` control. The target health check runs once for each target.

The `sb-gateway-version` response header shows which gateway answered. If the answer to a `v2` request does not show `v2` (it shows `v1`, or there is no header), the `v2` result is inconclusive with the reason `request was not forwarded to api-gateway v2`. If the `v2` control was not forwarded, a `v2` rejection that depends on the control is inconclusive for the same reason. A `2xx` answer is a regression on any gateway.

For each target, `actual` has `result` and `variants: { v1: {...}, v2: {...} }`. Each variant has `status`, `error`, `result`, `reason`, `gateway_version`, `control_status`, `control_error` and `control_gateway_version`. `result` is the worst variant result: `accepted` (fail), then `inconclusive` (warn), then `rejected` (pass). The check status is the worst result of all targets. The detail shows each variant, for example `<ref>: v1 rejected (401), v2 inconclusive (request was not forwarded to api-gateway v2)`.

### Results

Each check shows, for each target: the target ref, the gateway version, the control status, the target status and the result. For the gateway checks, these fields are in each variant.

- A `2xx` response from another tenant means that the tenant accepted tenant A's token. The check fails with `regression: <service> on <ref> accepted tenant <A>'s token (v1 ..., v2 ...)`. For `cross_tenant_realtime_ws`, the text is `regression: <service> on <ref> (gateway unknown) accepted tenant <A>'s token`.
- A network error or a `5xx` response is inconclusive. The check warns.
- A `401` response from a target with the message `Vercel OIDC token not issued for this project` is a definitive rejection by the api-gateway. The result is `rejected` with the reason `api-gateway rejected the token: Vercel OIDC token not issued for this project`, also when the target health check or the control on this tenant fails.
- Each target also gets `GET /auth/v1/health` with its key as `apikey`. If this is not `2xx`, the target ref or key is not valid in this environment (wrong ref, wrong key, paused project, or a project in the other environment, such as a staging project on a production deployment). A rejection from such a target proves nothing, so the result for that target is inconclusive and the check warns. A `2xx` response to the token is still a regression.
- The same probes go to this deployment's own project (own URL and own publishable or anon key) as a positive control. If the control does not return `2xx` for a service, this tenant does not accept the token for that service either, so a rejection by a target proves nothing. The result for that service is inconclusive and the check warns. The REST probe reads the `public.countries` table, which this project creates in its migrations. Auth admin can be inconclusive if Supabase Auth does not accept resource tokens on this tenant. The control error, such as `PGRST301: ...`, shows why.

The gateway version comes from the `sb-gateway-version` response header. The values `1` and `1.0` become `v1`, and `2` and `2.0` become `v2`. If the header is missing, the version is `unknown`. `cross_tenant_gateway_coverage` passes when, for each target, every `v1` request was answered by `v1` and every `v2` request was answered by `v2`. Otherwise it warns and names the targets and the gateways that answered, for example `<ref>: v2 requests were answered by v1`. It uses the requests of `/api/cross-tenant`, so `cross_tenant_storage_s3` is not part of it. `actual` has, for each target, the versions that answered the `v1` and the `v2` requests, and `missing` (the variants that did not reach their gateway).

Vercel mints resource tokens only for teams on an allow list. Tenant A (this deployment's Vercel team) must be on an allow-listed team, or no token is minted and the cross-tenant checks are skipped.

## Enable JIT by hand (temporary)

The JIT checks need JIT access and SSL enforcement on the Supabase project. The platform will enable both automatically for Vercel Marketplace resources, but it does not do this yet:

- [CTRL-2146](https://linear.app/supabase/issue/CTRL-2146/configure-jit-when-creating-vercel-marketplace-resources): configure JIT when Vercel Marketplace resources are created.
- [CTRL-2145](https://linear.app/supabase/issue/CTRL-2145/support-backfill-on-existing-projects): backfill existing projects.
- [CTRL-2151](https://linear.app/supabase/issue/CTRL-2151/make-pooler-jit-login-work-without-the-jittrue-client-option): pooler JIT login without the `--jit=true` client option.

`pnpm run bootstrap` enables both when it has an access token. To run only this step, for example after you skipped the token:

1. Set `SUPABASE_URL` in the shell (for example `https://<ref>.supabase.co`, or `https://<ref>.supabase.red` for staging), or have it in `.env.local`.
2. Run `pnpm run enable-jit`.

The script needs an experimental API token. It enables SSL enforcement, then JIT access, and waits until the change is applied. It is safe to run again.

The pooler can need some minutes more before it accepts JIT logins.

Until CTRL-2151 is done, apps must send `options=--jit=true` through the pooler. The `jit_postgres_login_no_jit` check warns until then when the pooler rejects the password. Other errors fail. Without the Supabase IPv4 add-on, the direct host is IPv6 only. Vercel functions have no IPv6 route, so the direct check is skipped there unless the project has the IPv4 add-on. `pnpm run bootstrap` offers to enable the add-on.
