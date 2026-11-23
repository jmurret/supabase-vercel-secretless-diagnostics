#!/usr/bin/env bash
# Enable JIT database access on the Supabase project in .env.local.
# Workaround until the platform does this for Vercel Marketplace resources
# (CTRL-2145, CTRL-2146). Safe to run many times.
# Needs: curl, node and a .env.local from `pnpm run bootstrap`. Calls the Management API with a
# resource token minted from VERCEL_OIDC_TOKEN; asks for an experimental API token only if the
# Management API rejects it (see scripts/lib.sh).
set -euo pipefail
cd "$(dirname "$0")/.."

source scripts/lib.sh

[ -f .env.local ] || { echo "Run 'pnpm run bootstrap' first." >&2; exit 1; }
load_supabase_project
[ -n "${SUPABASE_RESOURCE_TOKEN:-}" ] || mint_resource_token

# Runs in the current shell (not in $(...)) so an access token entered at the prompt is kept.
api() {
  mgmt_api "$@"
  mgmt_ok && return 0
  echo "$1 $2 failed: HTTP $MGMT_STATUS $MGMT_BODY" >&2
  if [ "$MGMT_STATUS" = 401 ] || [ "$MGMT_STATUS" = 403 ]; then
    echo "Use an experimental API token (set SUPABASE_ACCESS_TOKEN)." >&2
  fi
  exit 1
}
jit_state() {
  api GET jit-access
  read -r state applied reason <<<"$(printf '%s' "$MGMT_BODY" | node -e '
    const d = JSON.parse(require("fs").readFileSync(0, "utf8"));
    console.log([d.state, d.appliedSuccessfully === true, d.unavailableReason || ""].join(" "));
  ')"
}

jit_state
echo "JIT on $ref: state=$state appliedSuccessfully=$applied${reason:+ reason=$reason}" >&2
if [ "$state" = enabled ] && [ "$applied" = true ]; then
  echo "JIT is already enabled. Nothing to do." >&2
  exit 0
fi
if [ "$state" = unavailable ] && [ "$reason" != ssl_enforcement_required ]; then
  echo "JIT is unavailable for this project: $reason" >&2
  exit 1
fi

cat >&2 <<EOF
Target:
  Project  $ref ($mgmt)
Changes:
  enable  SSL enforcement for the database (JIT logins apply only to SSL connections)
  enable  JIT access
EOF
if [ -t 0 ]; then
  read -r -p "Continue? [y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]] || { echo "Stopped. Nothing changed." >&2; exit 1; }
fi

api PUT ssl-enforcement '{"requestedConfig":{"database":true}}'
echo "SSL enforcement enabled." >&2
api PUT jit-access '{"state":"enabled"}'
echo "JIT access requested." >&2

for _ in 1 2 3 4 5 6; do
  jit_state
  if [ "$state" = enabled ] && [ "$applied" = true ]; then
    echo "JIT is enabled. The pooler can need some minutes more before it accepts JIT logins." >&2
    exit 0
  fi
  sleep 5
done
echo "JIT is not applied yet: state=$state appliedSuccessfully=$applied${reason:+ reason=$reason}. Run this script again later." >&2
exit 1
