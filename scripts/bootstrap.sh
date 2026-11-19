#!/usr/bin/env bash
# Set up the linked Vercel project and the Supabase schema. Safe to run many times.
# Step 1 sets MARKETPLACE_RESOURCE_ID to the Supabase resource connected to the linked
# project, removes the static secrets, and pulls a new .env.local.
# Step 2 applies supabase/migrations through the Management API, unless the Data API
# shows that public.whoami_vercel() and public.countries already exist.
# Needs: vercel CLI, node, curl. Run `vercel link` once before.
set -euo pipefail
cd "$(dirname "$0")/.."

environments="production,preview,development"
secrets=(SUPABASE_JWT_SECRET SUPABASE_SECRET_KEY SUPABASE_SERVICE_ROLE_KEY)
hl="" reset=""
if [ -t 2 ]; then hl=$'\033[1;33m'; reset=$'\033[0m'; fi

for cmd in vercel node curl; do
  command -v "$cmd" >/dev/null || { echo "Install $cmd first." >&2; exit 1; }
done
[ -f .vercel/project.json ] || { echo "Run 'vercel link' first, then run this script again." >&2; exit 1; }

echo "==> Step 1: Vercel project" >&2
info="$(vercel integration list --integration supabase --json | node -e '
  const p = require("./.vercel/project.json");
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

env_value() {
  local name
  for name in "$@"; do
    grep -E "^$name=" .env.local | tail -n 1 | cut -d= -f2- | sed -E 's/^"(.*)"$/\1/' || true
  done | head -n 1
}
[ -n "$(env_value POSTGRES_URL)" ] || echo "Warning: POSTGRES_URL is not set. The JIT login checks need it from the Supabase integration." >&2

echo >&2
echo "==> Step 2: Supabase schema" >&2
url="$(env_value SUPABASE_URL NEXT_PUBLIC_SUPABASE_URL)"
url="${url%/}"
key="$(env_value SUPABASE_PUBLISHABLE_KEY NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY SUPABASE_ANON_KEY NEXT_PUBLIC_SUPABASE_ANON_KEY)"
host="${url#*://}"
ref="${host%%.*}"
[ -n "$ref" ] || { echo "SUPABASE_URL is not in .env.local." >&2; exit 1; }

status() { curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "apikey: $key" "$@" || true; }
if [ -n "$key" ] &&
  [ "$(status "$url/rest/v1/countries?select=id&limit=1")" = 200 ] &&
  [ "$(status -X POST -H 'Content-Type: application/json' -d '{}' "$url/rest/v1/rpc/whoami_vercel")" = 200 ]; then
  echo "public.whoami_vercel() and public.countries already exist. Skipped." >&2
else
  case "$host" in
    *.supabase.red) mgmt=https://api.supabase.green dashboard=https://supabase.green/dashboard ;;
    *) mgmt=https://api.supabase.com dashboard=https://supabase.com/dashboard ;;
  esac
  if [ -z "${SUPABASE_ACCESS_TOKEN:-}" ]; then
    cat >&2 <<EOF
Applying supabase/migrations to project $ref needs a Supabase personal access token.
  ${hl}OIDC tokens cannot change the schema. The token is used for these requests only and is not saved.${reset}
  Create one at $dashboard/account/tokens, or set SUPABASE_ACCESS_TOKEN to skip this prompt.
EOF
    read -rs -p "Supabase access token (input hidden): " SUPABASE_ACCESS_TOKEN
    echo >&2
  fi
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
echo "Run \`pnpm run enable-jit\` to enable JIT (needed for the JIT checks until CTRL-2145/CTRL-2146)." >&2
echo "Redeploy so existing deployments get the changes." >&2
