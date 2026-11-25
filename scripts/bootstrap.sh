#!/usr/bin/env bash
# Set up the linked Vercel project and the Supabase schema. Safe to run many times.
# Step 1 finds the Supabase resource connected to the linked project and reads its project
# ref from the Vercel store. It sets MARKETPLACE_RESOURCE_ID, VERCEL_INTEGRATION_ID,
# VERCEL_INTEGRATION_INSTALLATION_ID and SUPABASE_RESOURCE_ID (a missing value only prints a
# warning), warns about static secrets (it does not remove them) and about missing Supabase
# variable names, and pulls a new .env.local. It does not read any Supabase variable value
# from Vercel, so the Supabase integration does not need to be connected to the Development
# environment.
# Step 2 asks once for a Supabase access token (or reads SUPABASE_ACCESS_TOKEN). Press Enter
# to skip it. It then selects the Supabase environment (production or staging) from the
# integration slug. If the slug is unknown, it probes the Management API with the token.
# Set SUPABASE_URL in the shell to skip the lookup and the selection.
# Step 3 applies supabase/migrations through the Management API, unless public.whoami_vercel()
# and public.countries already exist. It checks with the token, or with the Data API when
# .env.local has a publishable key. It needs the token to apply the migrations.
# Step 4 offers to enable the Supabase IPv4 add-on when db.<project host> has no A record.
# Step 5 enables JIT with scripts/enable-jit.sh.
# Step 6 sets SUPABASE_ANON_KEY to the legacy anon key of this project when it is not set and
# the token can read it (the Storage S3 cross-tenant check needs it). It then asks for optional
# cross-tenant targets (other Supabase projects) and sets CROSS_TENANT_TARGETS. For each target
# it reads the legacy anon key with the token, or asks for it (hidden). The target prompts run
# only with a terminal.
# Step 7 redeploys production.
# A failure in step 4, 5, 6 or 7 only prints a warning.
# Needs: vercel CLI, node, curl. Run `vercel link` once before.
set -euo pipefail
cd "$(dirname "$0")/.."

environments="production,preview,development"
secrets=(
  SUPABASE_JWT_SECRET SUPABASE_SECRET_KEY SUPABASE_SERVICE_ROLE_KEY
  POSTGRES_URL POSTGRES_PRISMA_URL POSTGRES_URL_NON_POOLING POSTGRES_PASSWORD
)
hl="" reset=""
if [ -t 2 ]; then hl=$'\033[1;33m'; reset=$'\033[0m'; fi

for cmd in vercel node curl; do
  command -v "$cmd" >/dev/null || { echo "Install $cmd first." >&2; exit 1; }
done
[ -f .vercel/project.json ] || [ -f .vercel/repo.json ] || { echo "Run 'vercel link' first, then run this script again." >&2; exit 1; }

echo "==> Step 1: Vercel project" >&2
info="$(vercel integration list --integration supabase --json | node -e '
  const fs = require("fs");
  let p;
  if (fs.existsSync(".vercel/project.json")) {
    p = require("./.vercel/project.json");
  } else {
    const links = require("./.vercel/repo.json").projects || [];
    const l = links.find((x) => x.directory === ".") || (links.length === 1 && links[0]);
    if (!l) {
      console.error("Cannot find the linked project for this directory in .vercel/repo.json. Run vercel link again.");
      process.exit(1);
    }
    p = { projectName: l.name, projectId: l.id, orgId: l.orgId };
  }
  const all = JSON.parse(require("fs").readFileSync(0, "utf8")).resources || [];
  const mine = all.filter((r) => (r.projects || []).includes(p.projectName));
  if (mine.length !== 1) {
    console.error(`Expected 1 Supabase resource connected to ${p.projectName}, found ${mine.length}.`);
    for (const r of all) console.error(`  ${r.id}  ${r.name}  projects: ${(r.projects || []).join(", ")}`);
    process.exit(1);
  }
  console.log([p.projectName, p.projectId, p.orgId, mine[0].id, mine[0].configurationId || "-", `${mine[0].name} (${mine[0].product})`].join("\t"));
')"
IFS=$'\t' read -r project project_id org_id id installation_id label <<<"$info"
[ "$installation_id" != "-" ] || installation_id=""

team_query=""
case "$org_id" in team_*) team_query="?teamId=$org_id" ;; esac
ref="" slug="" host="" url=""
if [ -n "${SUPABASE_URL:-}" ]; then
  url="${SUPABASE_URL%/}"
  host="${url#*://}"
  host="${host%%/*}"
  ref="${host%%.*}"
else
  store_json="$(vercel api "/v1/storage/stores/$id$team_query" --raw 2>/dev/null || true)"
  store_ref=""
  store_installation_id=""
  read -r store_ref slug store_installation_id <<<"$(printf '%s' "$store_json" | node -e '
    const s = require("fs").readFileSync(0, "utf8");
    const i = s.indexOf("{");
    if (i < 0) process.exit(0);
    let j;
    try { j = JSON.parse(s.slice(i)); } catch { process.exit(0); }
    j = j.store || j;
    const ref = String(j.externalResourceId || "");
    if (!/^[a-z]{20}$/.test(ref)) process.exit(0);
    const p = j.product || {};
    const slugOf = (x) => (typeof x === "string" ? x : x && x.slug);
    const named = String(p.name || "").match(/\((supabase[a-z0-9-]*)\)/);
    console.log(ref, slugOf(p.integration) || slugOf(j.integration) || (named && named[1]) || "-", p.integrationConfigurationId || j.integrationConfigurationId || "-");
  ' || true)"
  [ -n "$installation_id" ] || [ "$store_installation_id" = "-" ] || installation_id="$store_installation_id"
  [ -n "$store_ref" ] || {
    echo "Cannot read the Supabase project ref from Vercel store $id. Set SUPABASE_URL (for example https://<ref>.supabase.co) and run this script again." >&2
    exit 1
  }
  ref="$store_ref"
  [ "$slug" != "-" ] || slug=""
  if [[ "$label" =~ \((supabase[a-z0-9-]*)\)\)?$ ]]; then slug="${BASH_REMATCH[1]}"; fi
fi
[ -n "$ref" ] || { echo "Cannot find the Supabase project ref in SUPABASE_URL." >&2; exit 1; }

integration_id=""
if [ -n "$installation_id" ]; then
  integration_id="$(vercel api "/v1/integrations/configuration/$installation_id$team_query" --raw 2>/dev/null | node -e '
    const s = require("fs").readFileSync(0, "utf8");
    const i = s.indexOf("{");
    if (i < 0) process.exit(0);
    try { console.log(JSON.parse(s.slice(i)).integrationId || ""); } catch {}
  ' || true)"
fi
[[ "$installation_id" =~ ^icfg_[A-Za-z0-9]+$ ]] || installation_id=""
[[ "$integration_id" =~ ^oac_[A-Za-z0-9]+$ ]] || integration_id=""
resource_ref=""
[[ "$ref" =~ ^[a-z]{20}$ ]] && resource_ref="$ref"

cat >&2 <<EOF
Target:
  Vercel project  $project ($project_id, team $org_id)
  Resource        $id $label
  Supabase ref    $ref${slug:+ (integration $slug)}
Changes in $environments:
  set     MARKETPLACE_RESOURCE_ID=$id
  set     VERCEL_INTEGRATION_ID=${integration_id:-(not found, skipped)}
  set     VERCEL_INTEGRATION_INSTALLATION_ID=${installation_id:-(not found, skipped)}
  set     SUPABASE_RESOURCE_ID=${resource_ref:-(not found, skipped)}
  replace .env.local with the Development variables (optional, for local development)
  enable  JIT access (SSL enforcement + JIT) on the Supabase project
  set     SUPABASE_ANON_KEY to the legacy anon key (if not set and the token can read it)
  ask     for optional CROSS_TENANT_TARGETS (with a terminal)
  redeploy production
EOF
if [ -t 0 ]; then
  read -r -p "Continue? [y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]] || { echo "Stopped. Nothing changed." >&2; exit 1; }
fi

set_config_env() {
  vercel env add "$1" --environment "$environments" --value "$2" --type config --force --yes
}
set_config_env MARKETPLACE_RESOURCE_ID "$id"
for pair in "VERCEL_INTEGRATION_ID:$integration_id" "VERCEL_INTEGRATION_INSTALLATION_ID:$installation_id" "SUPABASE_RESOURCE_ID:$resource_ref"; do
  if [ -n "${pair#*:}" ]; then
    set_config_env "${pair%%:*}" "${pair#*:}"
  else
    echo "${hl}Warning: cannot find the value for ${pair%%:*}. Skipped. The matching check only validates the format.${reset}" >&2
  fi
done
names="$(vercel env ls 2>/dev/null | awk '{print $1}' || true)"
present="$(printf '%s\n' "$names" | grep -Fx -f <(printf '%s\n' "${secrets[@]}") | sort -u | tr '\n' ' ' || true)"
if [ -n "$present" ]; then
  cat >&2 <<EOF
${hl}Warning: static secrets are set on $project: $present${reset}
  An OIDC-only Supabase resource must not sync them, and they can authenticate without OIDC.
  Bootstrap does not remove them. The no_static_secret check fails while they are set.
EOF
fi
rm -f .env.local
vercel env pull .env.local --yes

env_value() {
  local name
  for name in "$@"; do
    grep -E "^$name=" .env.local | tail -n 1 | cut -d= -f2- | sed -E 's/^"(.*)"$/\1/' || true
  done | head -n 1
}
if [ -z "$(env_value SUPABASE_URL NEXT_PUBLIC_SUPABASE_URL)" ]; then
  echo "The Supabase integration is not connected to the Development environment, so .env.local has no Supabase values. You need them only to run the app locally." >&2
fi
for name in POSTGRES_POOLER_HOST SUPABASE_PROJECT_REF; do
  printf '%s\n' "$names" | grep -Fx "$name" >/dev/null || echo "Warning: $name is not set on the Vercel project. The JIT login checks need it. Resync the Supabase integration env vars." >&2
done

echo >&2
echo "==> Step 2: Supabase access token" >&2
key="$(env_value SUPABASE_PUBLISHABLE_KEY NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY SUPABASE_ANON_KEY NEXT_PUBLIC_SUPABASE_ANON_KEY)"

if [ -n "${SUPABASE_URL:-}" ]; then
  case "$host" in
    *.supabase.red) env_kind=staging ;;
    *) env_kind=production ;;
  esac
  env_fixed=1
else
  env_fixed=""
  case "$slug" in
    supabase-staging) env_kind=staging ;;
    supabase) env_kind=production ;;
    *) env_kind="" ;;
  esac
fi

use_env() {
  case "$1" in
    staging)
      url="https://$ref.supabase.red" mgmt=https://api.supabase.green dashboard=https://supabase.green/dashboard ;;
    *)
      url="https://$ref.supabase.co" mgmt=https://api.supabase.com dashboard=https://supabase.com/dashboard ;;
  esac
  host="${url#*://}"
}
mgmt_status() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" "$mgmt/v1/projects/$ref" || true
}

if [ -n "$env_fixed" ]; then
  case "$host" in
    *.supabase.red) mgmt=https://api.supabase.green dashboard=https://supabase.green/dashboard ;;
    *) mgmt=https://api.supabase.com dashboard=https://supabase.com/dashboard ;;
  esac
  token_pages="$dashboard/account/tokens"
elif [ -n "$env_kind" ]; then
  use_env "$env_kind"
  token_pages="$dashboard/account/tokens"
else
  token_pages="https://supabase.com/dashboard/account/tokens (production) or https://supabase.green/dashboard/account/tokens (staging)"
fi

if [ -z "${SUPABASE_ACCESS_TOKEN:-}" ] && [ -t 0 ]; then
  cat >&2 <<EOF
A Supabase access token lets bootstrap apply the schema if missing, enable the IPv4 add-on if missing, and enable JIT.
  ${hl}Use an experimental API token. It is used for this run only and is not saved.${reset}
  Create one at $token_pages, or set SUPABASE_ACCESS_TOKEN to skip this prompt.
EOF
  read -rs -p "Supabase access token (input hidden, press Enter to skip): " SUPABASE_ACCESS_TOKEN || SUPABASE_ACCESS_TOKEN=""
  echo >&2
fi
export SUPABASE_ACCESS_TOKEN="${SUPABASE_ACCESS_TOKEN:-}"
[ -n "$SUPABASE_ACCESS_TOKEN" ] || echo "No access token. The schema, IPv4 add-on and JIT steps cannot make changes." >&2

if [ -z "$env_fixed" ]; then
  if [ -z "$env_kind" ] && [ -n "$SUPABASE_ACCESS_TOKEN" ]; then
    for kind in production staging; do
      use_env "$kind"
      if [ "$(mgmt_status)" = 200 ]; then env_kind="$kind"; break; fi
    done
  elif [ -n "$env_kind" ] && [ -n "$SUPABASE_ACCESS_TOKEN" ]; then
    [ "$(mgmt_status)" = 200 ] || echo "${hl}Warning: $mgmt did not return project $ref with this token. Check that the token and the Supabase environment ($env_kind) match.${reset}" >&2
  fi
  if [ -z "$env_kind" ]; then
    env_kind=production
    echo "${hl}Warning: cannot tell the Supabase environment from integration '${slug:-unknown}'. Using production. Set SUPABASE_URL to override.${reset}" >&2
  fi
  use_env "$env_kind"
fi
echo "Supabase project $ref ($env_kind): $url" >&2

echo >&2
echo "==> Step 3: Supabase schema" >&2
status() { curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "apikey: $key" "$@" || true; }
schema=unknown
if [ -n "$SUPABASE_ACCESS_TOKEN" ]; then
  schema=missing
  check_body="$(cat <<'EOF'
{"query":"select to_regclass('public.countries') is not null and to_regprocedure('public.whoami_vercel()') is not null as ok"}
EOF
)"
  check_out="$(curl -sS --max-time 30 -X POST \
    -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" \
    -H 'Content-Type: application/json' \
    -d "$check_body" \
    "$mgmt/v1/projects/$ref/database/query" 2>/dev/null || true)"
  if [[ "$check_out" =~ \"ok\"[[:space:]]*:[[:space:]]*true ]]; then schema=present; fi
elif [ -n "$key" ]; then
  schema=missing
  if [ "$(status "$url/rest/v1/countries?select=id&limit=1")" = 200 ] &&
    [ "$(status -X POST -H 'Content-Type: application/json' -d '{}' "$url/rest/v1/rpc/whoami_vercel")" = 200 ]; then
    schema=present
  fi
fi
if [ "$schema" = present ]; then
  echo "public.whoami_vercel() and public.countries already exist. Skipped." >&2
elif [ "$schema" = unknown ]; then
  echo "Cannot check the schema without an access token or a publishable key in .env.local. Skipped. Set SUPABASE_ACCESS_TOKEN and run this script again to check it." >&2
else
  [ -n "$SUPABASE_ACCESS_TOKEN" ] || {
    echo "Applying supabase/migrations to project $ref needs a Supabase access token. Set SUPABASE_ACCESS_TOKEN and run this script again." >&2
    exit 1
  }
  for file in supabase/migrations/*.sql; do
    base="${file##*/}"
    name="${base%.sql}"
    name="${name#*_}"
    out="$(node -e 'process.stdout.write(JSON.stringify({ query: require("fs").readFileSync(process.argv[1], "utf8"), name: process.argv[2] }))' "$file" "$name" |
      curl -sS --fail-with-body -X POST \
        -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" \
        -H 'Content-Type: application/json' \
        --data-binary @- \
        "$mgmt/v1/projects/$ref/database/migrations")" || { echo "Migration $base failed: $out" >&2; exit 1; }
    echo "Applied $base" >&2
  done
  echo "Schema created. Later runs find it and do not ask for a token." >&2
fi

echo >&2
echo "==> Step 4: IPv4 address for the direct database host" >&2
ipv4_warning() {
  echo "WARNING: IPv4 add-on not enabled. $1" >&2
  cat >&2 <<EOF
Enable it later with:
  curl -X PATCH "$mgmt/v1/projects/$ref/billing/addons" -H "Authorization: Bearer \$SUPABASE_ACCESS_TOKEN" -H "Content-Type: application/json" -d '{"addon_type":"ipv4","addon_variant":"ipv4_default"}'
EOF
}

if node -e 'require("node:dns").promises.resolve4(process.argv[1]).then((a) => process.exit(a.length ? 0 : 1), () => process.exit(1))' "db.$host" >/dev/null 2>&1; then
  echo "IPv4 address for the direct host exists. Skipped." >&2
else
  echo "${hl}The direct database host has only an IPv6 address. Vercel functions cannot reach it, so the direct login check is skipped. The IPv4 add-on adds an IPv4 address (paid).${reset}" >&2
  if [ ! -t 0 ]; then
    ipv4_warning "No terminal to ask for confirmation."
  else
    read -r -p "Enable the IPv4 add-on? [y/N] " answer || answer=""
    if [[ ! "$answer" =~ ^[Yy]$ ]]; then
      ipv4_warning "Declined."
    else
      if [ -z "$SUPABASE_ACCESS_TOKEN" ]; then
        ipv4_warning "No access token."
      else
        rc=0
        out="$(curl -sS --max-time 30 -X PATCH \
          -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" \
          -H 'Content-Type: application/json' \
          -d '{"addon_type":"ipv4","addon_variant":"ipv4_default"}' \
          -w $'\n%{http_code}' \
          "$mgmt/v1/projects/$ref/billing/addons" 2>&1)" || rc=$?
        code="${out##*$'\n'}"
        body="${out%$'\n'*}"
        if [ "$rc" -ne 0 ]; then
          ipv4_warning "curl failed (exit $rc): $out"
        elif [[ "$code" =~ ^2[0-9][0-9]$ ]]; then
          echo "IPv4 add-on requested. The A record can take some minutes to appear." >&2
        elif [ "$code" = 401 ] || [ "$code" = 403 ]; then
          ipv4_warning "HTTP $code: $body. Use an experimental API token."
        else
          ipv4_warning "HTTP $code: $body"
        fi
      fi
    fi
  fi
fi

echo >&2
echo "==> Step 5: JIT access" >&2
jit_warning() {
  echo "WARNING: JIT is not enabled; the JIT checks will fail. $1" >&2
  echo "Run \`pnpm run enable-jit\` later (needed until CTRL-2145/CTRL-2146)." >&2
}
export SUPABASE_URL="$url"
if [ -z "$SUPABASE_ACCESS_TOKEN" ]; then
  jit_warning "No access token."
elif ! bash scripts/enable-jit.sh </dev/null; then
  jit_warning "scripts/enable-jit.sh failed."
fi

echo >&2
echo "==> Step 6: Cross-tenant targets" >&2
health_status() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "apikey: $2" "https://$1/auth/v1/health" || true
}
check_target() {
  local t_ref="$1" t_key="$2" suffix="${host#*.}" other_suffix="" other_kind=production code other_code=000
  case "$suffix" in
    supabase.co) other_suffix=supabase.red other_kind=staging ;;
    supabase.red) other_suffix=supabase.co ;;
  esac
  code="$(health_status "$t_ref.$suffix" "$t_key")"
  if [[ "$code" =~ ^2[0-9][0-9]$ ]]; then return 0; fi
  if [ -n "$other_suffix" ]; then
    other_code="$(health_status "$t_ref.$other_suffix" "$t_key")"
    if [[ "$other_code" =~ ^2[0-9][0-9]$ ]]; then
      echo "$t_ref is a $other_kind project, but this project is $env_kind. Use a target in the same environment." >&2
      return 1
    fi
  fi
  if [ "$code" = 000 ] && [ "$other_code" = 000 ]; then
    echo "${hl}Warning: cannot reach $t_ref.$suffix. The ref and key are not verified.${reset}" >&2
    return 0
  fi
  echo "The ref and key for $t_ref were not accepted (wrong ref, wrong key or paused project)." >&2
  return 1
}
org_of() {
  curl -s --max-time 15 -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" "$mgmt/v1/projects/$1" 2>/dev/null |
    node -e 'try { const o = JSON.parse(require("fs").readFileSync(0, "utf8")).organization_id; if (typeof o === "string") console.log(o); } catch {}' || true
}

legacy_anon_key() {
  curl -s --max-time 15 -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" "$mgmt/v1/projects/$1/api-keys" 2>/dev/null |
    node -e '
      try {
        const keys = JSON.parse(require("fs").readFileSync(0, "utf8"));
        for (const k of Array.isArray(keys) ? keys : []) {
          if (k.name !== "anon" || typeof k.api_key !== "string") continue;
          const p = JSON.parse(Buffer.from(k.api_key.split(".")[1] || "", "base64url").toString("utf8"));
          if (p.role === "anon" && (p.ref === undefined || p.ref === process.argv[1])) {
            process.stdout.write(k.api_key);
            break;
          }
        }
      } catch {}
    ' "$1" || true
}
publishable_key() {
  curl -s --max-time 15 -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" "$mgmt/v1/projects/$1/api-keys" 2>/dev/null |
    node -e '
      try {
        const keys = JSON.parse(require("fs").readFileSync(0, "utf8"));
        const k = (Array.isArray(keys) ? keys : []).find((k) => k.type === "publishable" && /^sb_publishable_[A-Za-z0-9_-]+$/.test(k.api_key ?? ""));
        if (k) process.stdout.write(k.api_key);
      } catch {}
    ' || true
}
is_legacy_anon_key() {
  printf '%s' "$1" | node -e '
    try {
      const p = JSON.parse(Buffer.from(require("fs").readFileSync(0, "utf8").split(".")[1] || "", "base64url").toString("utf8"));
      process.exit(p.role === "anon" && (p.ref === undefined || p.ref === process.argv[1]) ? 0 : 1);
    } catch {
      process.exit(1);
    }
  ' "$2"
}

s3_control_warning() {
  echo "${hl}Warning: $1 The Storage S3 cross-tenant check will be inconclusive until SUPABASE_ANON_KEY holds the legacy anon key of $ref.${reset}" >&2
}
if printf '%s\n' "$names" | grep -Fx SUPABASE_ANON_KEY >/dev/null; then
  echo "SUPABASE_ANON_KEY is already set. The Storage S3 control uses it, so it must be the legacy anon key of $ref." >&2
elif [ -z "$SUPABASE_ACCESS_TOKEN" ]; then
  s3_control_warning "No access token, so the legacy anon key was not read."
else
  own_anon="$(legacy_anon_key "$ref")"
  if [ -z "$own_anon" ]; then
    s3_control_warning "The token cannot read a legacy anon key for $ref (legacy keys may be disabled)."
  elif set_config_env SUPABASE_ANON_KEY "$own_anon"; then
    echo "SUPABASE_ANON_KEY set to the legacy anon key of $ref." >&2
  else
    s3_control_warning "SUPABASE_ANON_KEY was not set. The Vercel CLI failed."
  fi
fi

if [ ! -t 0 ]; then
  echo "No terminal. Skipped. Set CROSS_TENANT_TARGETS on the Vercel project to enable the cross-tenant checks." >&2
else
  if printf '%s\n' "$names" | grep -Fx CROSS_TENANT_TARGETS >/dev/null; then
    echo "CROSS_TENANT_TARGETS is already set. Leave the first ref empty to keep it. Any target you enter replaces it." >&2
  fi
  echo "Cross-tenant targets are other Supabase projects. The checks send this project's token to them and expect a rejection." >&2
  own_org=""
  [ -z "$SUPABASE_ACCESS_TOKEN" ] || own_org="$(org_of "$ref")"
  targets="" entered=" "
  while true; do
    read -r -p "Cross-tenant project ref (leave empty to skip): " t_ref || t_ref=""
    [ -n "$t_ref" ] || break
    if [[ ! "$t_ref" =~ ^[a-z]{20}$ ]]; then
      echo "A project ref is 20 lowercase letters." >&2
      continue
    elif [ "$t_ref" = "$ref" ]; then
      echo "$t_ref is this project. A cross-tenant target must be another project." >&2
      continue
    elif [[ "$entered" == *" $t_ref "* ]]; then
      echo "$t_ref is already entered." >&2
      continue
    fi
    t_key=""
    [ -z "$SUPABASE_ACCESS_TOKEN" ] || t_key="$(publishable_key "$t_ref")"
    if [ -n "$t_key" ]; then
      echo "Found the publishable key for $t_ref." >&2
    else
      read -r -p "Publishable key for $t_ref: " t_key || t_key=""
    fi
    if [ -z "$t_key" ]; then
      echo "The publishable key is required." >&2
      continue
    fi
    check_target "$t_ref" "$t_key" || continue
    if [ -z "$SUPABASE_ACCESS_TOKEN" ]; then
      echo "No access token. The organization of $t_ref was not checked." >&2
    else
      t_org="$(org_of "$t_ref")"
      if [ -z "$t_org" ] || [ -z "$own_org" ]; then
        echo "Organization not visible to your token for $t_ref or this project." >&2
      elif [ "$t_org" = "$own_org" ]; then
        echo "$t_ref is in the same organization as this project." >&2
      else
        echo "$t_ref is in a different organization than this project." >&2
      fi
    fi
    t_anon=""
    if is_legacy_anon_key "$t_key" "$t_ref"; then
      echo "The key for $t_ref is a legacy anon key. The Storage S3 check uses it." >&2
    else
      [ -z "$SUPABASE_ACCESS_TOKEN" ] || t_anon="$(legacy_anon_key "$t_ref")"
      if [ -n "$t_anon" ]; then
        echo "Found the legacy anon key for $t_ref." >&2
      else
        echo "The Storage S3 check needs the legacy anon key of $t_ref as the S3 secret." >&2
        while true; do
          read -rs -p "Legacy anon key for $t_ref (input hidden, leave empty to skip): " t_anon || t_anon=""
          echo >&2
          [ -n "$t_anon" ] || break
          is_legacy_anon_key "$t_anon" "$t_ref" && break
          echo "That is not the legacy anon key of $t_ref (a JWT with role anon). Try again, or leave empty to skip." >&2
        done
        [ -n "$t_anon" ] || echo "No legacy anon key for $t_ref. The Storage S3 check will be inconclusive for it." >&2
      fi
    fi
    targets="${targets:+$targets,}$t_ref=$t_key${t_anon:+:$t_anon}"
    entered="$entered$t_ref "
    read -r -p "Add another target? [y/N] " more || more=""
    [[ "$more" =~ ^[Yy]$ ]] || break
  done
  if [ -z "$targets" ]; then
    echo "No target entered. CROSS_TENANT_TARGETS is unchanged." >&2
  elif set_config_env CROSS_TENANT_TARGETS "$targets"; then
    echo "CROSS_TENANT_TARGETS set." >&2
  else
    echo "WARNING: CROSS_TENANT_TARGETS was not set. The Vercel CLI failed." >&2
  fi
fi

echo >&2
echo "==> Step 7: Redeploy production" >&2
# A deployment only sees the variables that existed when it was built.
redeploy_warning() {
  echo "WARNING: Production was not redeployed. $1" >&2
  echo "Run \`vercel redeploy <production deployment url> --environment production\` later." >&2
}
scope=""
case "$org_id" in team_*) scope="&teamId=$org_id" ;; esac
dep_url="$(vercel api -X GET "/v6/deployments?projectId=$project_id&target=production&state=READY&limit=1$scope" --raw 2>/dev/null |
  node -e 'try { const d = (JSON.parse(require("fs").readFileSync(0, "utf8")).deployments || [])[0]; if (d) console.log(d.url); } catch {}')" || dep_url=""
if [ -z "$dep_url" ]; then
  redeploy_warning "Could not find a Ready production deployment."
elif ! vercel redeploy "$dep_url" --environment production; then
  redeploy_warning "The Vercel CLI failed."
fi
