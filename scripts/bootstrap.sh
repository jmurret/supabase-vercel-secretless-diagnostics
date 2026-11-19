#!/usr/bin/env bash
# Set up the linked Vercel project and the Supabase schema. Safe to run many times.
# Step 1 sets MARKETPLACE_RESOURCE_ID to the Supabase resource connected to the linked
# project, removes the static secrets, and pulls a new .env.local.
# Step 2 asks once for a Supabase access token (or reads SUPABASE_ACCESS_TOKEN). Press Enter
# to skip it.
# Step 3 applies supabase/migrations through the Management API, unless the Data API
# shows that public.whoami_vercel() and public.countries already exist. It needs the token.
# Step 4 offers to enable the Supabase IPv4 add-on when db.<project host> has no A record.
# Step 5 enables JIT with scripts/enable-jit.sh.
# A failure in step 4 or 5 only prints a warning.
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
  enable  JIT access (SSL enforcement + JIT) on the Supabase project
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
[ -n "$(env_value POSTGRES_URL)" ] || echo "Warning: POSTGRES_URL is not set. The JIT login checks need it from the Supabase integration." >&2

echo >&2
echo "==> Step 2: Supabase access token" >&2
url="$(env_value SUPABASE_URL NEXT_PUBLIC_SUPABASE_URL)"
url="${url%/}"
key="$(env_value SUPABASE_PUBLISHABLE_KEY NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY SUPABASE_ANON_KEY NEXT_PUBLIC_SUPABASE_ANON_KEY)"
host="${url#*://}"
ref="${host%%.*}"
[ -n "$ref" ] || { echo "SUPABASE_URL is not in .env.local." >&2; exit 1; }

case "$host" in
  *.supabase.red) mgmt=https://api.supabase.green dashboard=https://supabase.green/dashboard ;;
  *) mgmt=https://api.supabase.com dashboard=https://supabase.com/dashboard ;;
esac

if [ -z "${SUPABASE_ACCESS_TOKEN:-}" ] && [ -t 0 ]; then
  cat >&2 <<EOF
A Supabase access token lets bootstrap apply the schema if missing, enable the IPv4 add-on if missing, and enable JIT.
  ${hl}Use an experimental API token. It is used for this run only and is not saved.${reset}
  Create one at $dashboard/account/tokens, or set SUPABASE_ACCESS_TOKEN to skip this prompt.
EOF
  read -rs -p "Supabase access token (input hidden, press Enter to skip): " SUPABASE_ACCESS_TOKEN || SUPABASE_ACCESS_TOKEN=""
  echo >&2
fi
export SUPABASE_ACCESS_TOKEN="${SUPABASE_ACCESS_TOKEN:-}"
[ -n "$SUPABASE_ACCESS_TOKEN" ] || echo "No access token. The schema, IPv4 add-on and JIT steps cannot make changes." >&2

echo >&2
echo "==> Step 3: Supabase schema" >&2
status() { curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "apikey: $key" "$@" || true; }
if [ -n "$key" ] &&
  [ "$(status "$url/rest/v1/countries?select=id&limit=1")" = 200 ] &&
  [ "$(status -X POST -H 'Content-Type: application/json' -d '{}' "$url/rest/v1/rpc/whoami_vercel")" = 200 ]; then
  echo "public.whoami_vercel() and public.countries already exist. Skipped." >&2
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
if [ -z "$SUPABASE_ACCESS_TOKEN" ]; then
  jit_warning "No access token."
elif ! bash scripts/enable-jit.sh </dev/null; then
  jit_warning "scripts/enable-jit.sh failed."
fi

echo >&2
echo "Redeploy so existing deployments get the changes." >&2
