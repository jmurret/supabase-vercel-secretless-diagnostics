#!/usr/bin/env bash
# Enable JIT database access on the Supabase project in SUPABASE_URL.
# Workaround until the platform does this for Vercel Marketplace resources
# (CTRL-2145, CTRL-2146). Safe to run many times.
# `pnpm run bootstrap` sets SUPABASE_URL for this script. To run it alone, set
# SUPABASE_URL in the shell, or have it in .env.local. Use *.supabase.red for staging.
# Needs: curl, node, and an experimental API token.
set -euo pipefail
cd "$(dirname "$0")/.."

hl="" reset=""
if [ -t 2 ]; then hl=$'\033[1;33m'; reset=$'\033[0m'; fi

url="${SUPABASE_URL:-}"
if [ -z "$url" ] && [ -f .env.local ]; then
  url="$(grep -E '^SUPABASE_URL=' .env.local | tail -n 1 | cut -d= -f2- | sed -E 's/^"(.*)"$/\1/' || true)"
fi
host="${url#*://}"
host="${host%%/*}"
ref="${host%%.*}"
[ -n "$ref" ] || { echo "SUPABASE_URL is not set and .env.local has none. Set SUPABASE_URL (for example https://<ref>.supabase.co) or run 'pnpm run bootstrap'." >&2; exit 1; }
case "$host" in
  *.supabase.red) mgmt=https://api.supabase.green dashboard=https://supabase.green/dashboard ;;
  *) mgmt=https://api.supabase.com dashboard=https://supabase.com/dashboard ;;
esac

if [ -z "${SUPABASE_ACCESS_TOKEN:-}" ]; then
  cat >&2 <<EOF
Enabling JIT on project $ref needs a Supabase access token.
  ${hl}The token must be an experimental API token. It is used for this run only and is not saved.${reset}
  Create one at $dashboard/account/tokens, or set SUPABASE_ACCESS_TOKEN to skip this prompt.
EOF
  read -rs -p "Supabase access token (input hidden): " SUPABASE_ACCESS_TOKEN
  echo >&2
fi

api() {
  local method="$1" path="$2" body="${3:-}" out status
  out="$(curl -sS -w '\n%{http_code}' -X "$method" \
    -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" \
    -H 'Content-Type: application/json' \
    ${body:+-d "$body"} \
    "$mgmt/v1/projects/$ref/$path")" || { echo "$method $path failed: could not reach $mgmt" >&2; exit 1; }
  status="${out##*$'\n'}"
  out="${out%$'\n'*}"
  if [ "${status:0:1}" != 2 ]; then
    echo "$method $path failed: HTTP $status $out" >&2
    if [ "$status" = 401 ] || [ "$status" = 403 ]; then
      echo "Use an experimental API token." >&2
    fi
    exit 1
  fi
  printf '%s' "$out"
}
jit_state() {
  local json
  json="$(api GET jit-access)" || exit 1
  printf '%s' "$json" | node -e '
    const d = JSON.parse(require("fs").readFileSync(0, "utf8"));
    console.log([d.state, d.appliedSuccessfully === true, d.unavailableReason || ""].join(" "));
  '
}

info="$(jit_state)"
read -r state applied reason <<<"$info"
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

api PUT ssl-enforcement '{"requestedConfig":{"database":true}}' >/dev/null
echo "SSL enforcement enabled." >&2
api PUT jit-access '{"state":"enabled"}' >/dev/null
echo "JIT access requested." >&2

for _ in 1 2 3 4 5 6; do
  info="$(jit_state)"
  read -r state applied reason <<<"$info"
  if [ "$state" = enabled ] && [ "$applied" = true ]; then
    echo "JIT is enabled. The pooler can need some minutes more before it accepts JIT logins." >&2
    exit 0
  fi
  sleep 5
done
echo "JIT is not applied yet: state=$state appliedSuccessfully=$applied${reason:+ reason=$reason}. Run this script again later." >&2
exit 1
