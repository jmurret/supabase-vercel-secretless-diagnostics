#!/usr/bin/env bash
# Set up the linked Vercel project and the Supabase schema. Safe to run many times.
# Step 1 sets MARKETPLACE_RESOURCE_ID to the Supabase resource connected to the linked
# project, removes the static secrets, and pulls a new .env.local.
# Step 2 mints a postgres-role resource token from VERCEL_OIDC_TOKEN for the Management API.
# If the Management API rejects it, the script asks once for a Supabase access token (or reads
# SUPABASE_ACCESS_TOKEN). Press Enter to skip it. See scripts/lib.sh.
# Step 3 applies supabase/migrations through the Management API, unless the Data API
# shows that public.whoami_vercel() and public.countries already exist.
# Step 4 sets SUPABASE_POOLER_HOST, SUPABASE_POOLER_PORT and SUPABASE_POOLER_USER (no password)
# from the Management API, for the JIT pooler login checks.
# Step 5 offers to enable the Supabase IPv4 add-on when db.<project host> has no A record.
# Step 6 enables JIT with scripts/enable-jit.sh.
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
source scripts/lib.sh

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
  console.log([p.projectName, p.projectId, p.orgId, mine[0].id, `${mine[0].name} (${mine[0].product})`].join("\t"));
')"
IFS=$'\t' read -r project project_id org_id id label <<<"$info"

cat >&2 <<EOF
Target:
  Vercel project  $project ($project_id, team $org_id)
  Resource        $id $label
Changes in $environments:
  set     MARKETPLACE_RESOURCE_ID=$id
  remove  ${secrets[*]}
          ${hl}Static secrets can authenticate without OIDC, so we remove them to ensure only OIDC is used.${reset}
  replace .env.local with the Development variables
  set     SUPABASE_POOLER_HOST, SUPABASE_POOLER_PORT, SUPABASE_POOLER_USER (no password)
  enable  JIT access (SSL enforcement + JIT) on the Supabase project
  redeploy production
EOF
if [ -t 0 ]; then
  read -r -p "Continue? [y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]] || { echo "Stopped. Nothing changed." >&2; exit 1; }
fi

vercel env add MARKETPLACE_RESOURCE_ID --environment "$environments" --value "$id" --type config --force --yes
for name in "${secrets[@]}"; do
  if vercel env rm "$name" --confirm-name "$name" >/dev/null 2>&1; then
    echo "Removed $name" >&2
  else
    echo "Did not remove $name (not set, or removal failed)" >&2
  fi
done
rm -f .env.local
vercel env pull .env.local --yes

case "$(env_value SUPABASE_URL NEXT_PUBLIC_SUPABASE_URL)" in
  https://*) ;;
  *)
    cat >&2 <<EOF
${hl}The Development variables have no SUPABASE_URL: the Supabase integration is not connected to the Development environment.${reset}
  Vercel cannot pull its Secret values from Preview or Production, so bootstrap needs Development.
  In Vercel, open Storage > $label > Projects, edit the connection to $project, and add Development.
  Then run 'pnpm run bootstrap' again. Step 1 is safe to repeat.
EOF
    exit 1
    ;;
esac
[ -n "$(env_value VERCEL_OIDC_TOKEN)" ] || echo "Warning: VERCEL_OIDC_TOKEN is not in .env.local. Enable OIDC Federation (Secure backend access) in the Vercel project settings." >&2

echo >&2
echo "==> Step 2: Management API credential" >&2
load_supabase_project
key="$(env_value SUPABASE_PUBLISHABLE_KEY NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY SUPABASE_ANON_KEY NEXT_PUBLIC_SUPABASE_ANON_KEY)"
mint_resource_token
export SUPABASE_RESOURCE_TOKEN
[ -z "${SUPABASE_ACCESS_TOKEN:-}" ] || echo "SUPABASE_ACCESS_TOKEN is set. It is used only if the Management API rejects the resource token." >&2
has_mgmt_credential || echo "No Management API credential. The schema, pooler, IPv4 add-on and JIT steps cannot make changes." >&2

echo >&2
echo "==> Step 3: Supabase schema" >&2
status() { curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "apikey: $key" "$@" || true; }
if [ -n "$key" ] &&
  [ "$(status "$url/rest/v1/countries?select=id&limit=1")" = 200 ] &&
  [ "$(status -X POST -H 'Content-Type: application/json' -d '{}' "$url/rest/v1/rpc/whoami_vercel")" = 200 ]; then
  echo "public.whoami_vercel() and public.countries already exist. Skipped." >&2
else
  for file in supabase/migrations/*.sql; do
    base="${file##*/}"
    name="${base%.sql}"
    name="${name#*_}"
    mgmt_api POST database/migrations "$(node -e 'process.stdout.write(JSON.stringify({ query: require("fs").readFileSync(process.argv[1], "utf8"), name: process.argv[2] }))' "$file" "$name")"
    if ! mgmt_ok; then
      echo "Migration $base failed: HTTP $MGMT_STATUS $MGMT_BODY" >&2
      [[ ! "$MGMT_STATUS" =~ ^(000|401|403)$ ]] || echo "Set SUPABASE_ACCESS_TOKEN (an experimental API token) and run this script again." >&2
      exit 1
    fi
    echo "Applied $base ($MGMT_AUTH)" >&2
  done
  echo "Schema created. Later runs find it and skip this step." >&2
fi

echo >&2
echo "==> Step 4: Pooler connection settings" >&2
# The JIT pooler login reads these instead of POSTGRES_URL, which holds a static password.
pooler_warning() {
  echo "WARNING: Pooler settings not set; the JIT pooler login checks are skipped. $1" >&2
}
mgmt_api GET config/database/pooler
if ! mgmt_ok; then
  pooler_warning "GET config/database/pooler: HTTP $MGMT_STATUS $MGMT_BODY"
elif ! pooler="$(printf '%s' "$MGMT_BODY" | node -e '
  const all = JSON.parse(require("fs").readFileSync(0, "utf8"));
  const p = (Array.isArray(all) ? all : [all]).find((x) => x.database_type === "PRIMARY") || all[0];
  if (!p?.db_host || !p?.db_port || !p?.db_user) process.exit(1);
  console.log([p.db_host, p.db_port, p.db_user].join("\t"));
')"; then
  pooler_warning "The response has no db_host, db_port and db_user."
else
  IFS=$'\t' read -r pooler_host pooler_port pooler_user <<<"$pooler"
  if [ "$(env_value SUPABASE_POOLER_HOST)" = "$pooler_host" ] &&
    [ "$(env_value SUPABASE_POOLER_PORT)" = "$pooler_port" ] &&
    [ "$(env_value SUPABASE_POOLER_USER)" = "$pooler_user" ]; then
    echo "Pooler settings are up to date ($pooler_user@$pooler_host:$pooler_port). Skipped." >&2
  else
    vercel env add SUPABASE_POOLER_HOST --environment "$environments" --value "$pooler_host" --type config --force --yes
    vercel env add SUPABASE_POOLER_PORT --environment "$environments" --value "$pooler_port" --type config --force --yes
    vercel env add SUPABASE_POOLER_USER --environment "$environments" --value "$pooler_user" --type config --force --yes
    vercel env pull .env.local --yes
    echo "Set the pooler settings ($pooler_user@$pooler_host:$pooler_port)." >&2
  fi
fi

echo >&2
echo "==> Step 5: IPv4 address for the direct database host" >&2
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
      mgmt_api PATCH billing/addons '{"addon_type":"ipv4","addon_variant":"ipv4_default"}'
      if mgmt_ok; then
        echo "IPv4 add-on requested. The A record can take some minutes to appear." >&2
      elif [ "$MGMT_STATUS" = 401 ] || [ "$MGMT_STATUS" = 403 ]; then
        ipv4_warning "HTTP $MGMT_STATUS: $MGMT_BODY. Use an experimental API token."
      else
        ipv4_warning "HTTP $MGMT_STATUS: $MGMT_BODY"
      fi
    fi
  fi
fi

echo >&2
echo "==> Step 6: JIT access" >&2
jit_warning() {
  echo "WARNING: JIT is not enabled; the JIT checks will fail. $1" >&2
  echo "Run \`pnpm run enable-jit\` later (needed until CTRL-2145/CTRL-2146)." >&2
}
if [ -z "$SUPABASE_RESOURCE_TOKEN" ] && [ -z "${SUPABASE_ACCESS_TOKEN:-}" ]; then
  jit_warning "No Management API credential."
elif ! bash scripts/enable-jit.sh </dev/null; then
  jit_warning "scripts/enable-jit.sh failed."
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
