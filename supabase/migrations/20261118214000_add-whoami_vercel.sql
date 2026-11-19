-- Reports how Supabase/PostgREST resolved the caller's JWT into a database identity.
-- SECURITY INVOKER so current_user reflects the role the request is actually running as.
create or replace function public.whoami_vercel()
returns jsonb
language sql
stable
security invoker
set search_path = ''
as $$
  with claims as (
    select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb as c
  )
  select jsonb_build_object(
    'current_user', current_user,
    'session_user', session_user,
    'auth_role', auth.role(),
    -- auth.uid() casts sub to uuid, which fails for third-party subjects (e.g. Vercel OIDC).
    'auth_uid', case
      when (select c->>'sub' from claims) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        then auth.uid()
    end,
    'jwt_sub', (select c->>'sub' from claims),
    'jwt_claims', (
      select coalesce(jsonb_object_agg(key, value), '{}'::jsonb)
      from claims, jsonb_each(claims.c)
      where key in (
        'iss', 'sub', 'aud', 'role', 'exp', 'iat', 'nbf', 'email', 'aal', 'is_anonymous', 'session_id',
        'owner', 'owner_id', 'project', 'project_id', 'environment', 'act'
      )
    ),
    'member_of', (
      select coalesce(jsonb_agg(r.rolname order by r.rolname), '[]'::jsonb)
      from pg_catalog.pg_roles r
      where pg_catalog.pg_has_role(current_user, r.oid, 'member')
        and r.rolname <> current_user
        and r.rolname not like 'pg\_%'
    ),
    'bypasses_rls', (select rolbypassrls from pg_catalog.pg_roles where rolname = current_user),
    'tables', (
      select coalesce(jsonb_agg(jsonb_build_object(
        'table', c.relname,
        'rls_enabled', c.relrowsecurity,
        'select', pg_catalog.has_table_privilege(c.oid, 'SELECT'),
        'insert', pg_catalog.has_table_privilege(c.oid, 'INSERT'),
        'update', pg_catalog.has_table_privilege(c.oid, 'UPDATE'),
        'delete', pg_catalog.has_table_privilege(c.oid, 'DELETE')
      ) order by c.relname), '[]'::jsonb)
      from pg_catalog.pg_class c
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public' and c.relkind in ('r', 'p', 'v', 'm')
    )
  );
$$;

revoke all on function public.whoami_vercel() from public;
grant execute on function public.whoami_vercel() to anon, authenticated, service_role;

