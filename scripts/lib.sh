# Shared helpers for bootstrap.sh and enable-jit.sh. Source it from the repository root.
#
# Management API credentials, in this order:
#   1. A Marketplace resource token (role postgres), minted from VERCEL_OIDC_TOKEN and
#      MARKETPLACE_RESOURCE_ID in .env.local. No static secret is needed.
#   2. SUPABASE_ACCESS_TOKEN, only when the Management API rejects the resource token (HTTP 401/403).
#      It is asked for once, when a terminal is available, and is never saved.

hl="" reset=""
if [ -t 2 ]; then hl=$'\033[1;33m'; reset=$'\033[0m'; fi

env_value() {
  local name
  for name in "$@"; do
    grep -E "^$name=" .env.local 2>/dev/null | tail -n 1 | cut -d= -f2- | sed -E 's/^"(.*)"$/\1/' || true
  done | head -n 1
}

# Sets url, host, ref, mgmt and dashboard from SUPABASE_URL (and SUPABASE_PROJECT_REF) in .env.local.
load_supabase_project() {
  url="$(env_value SUPABASE_URL NEXT_PUBLIC_SUPABASE_URL)"
  url="${url%/}"
  host="${url#*://}"
  host="${host%%/*}"
  ref="$(env_value SUPABASE_PROJECT_REF)"
  ref="${ref:-${host%%.*}}"
  [ -n "$ref" ] || { echo "SUPABASE_URL is not in .env.local." >&2; return 1; }
  case "$host" in
    *.supabase.red) mgmt=https://api.supabase.green dashboard=https://supabase.green/dashboard ;;
    *) mgmt=https://api.supabase.com dashboard=https://supabase.com/dashboard ;;
  esac
}

# Sets SUPABASE_RESOURCE_TOKEN. Prints a warning and leaves it empty when the mint fails.
mint_resource_token() {
  SUPABASE_RESOURCE_TOKEN=""
  local oidc resource_id out
  oidc="$(env_value VERCEL_OIDC_TOKEN)"
  resource_id="$(env_value MARKETPLACE_RESOURCE_ID)"
  if [ -z "$oidc" ] || [ -z "$resource_id" ]; then
    echo "No VERCEL_OIDC_TOKEN or MARKETPLACE_RESOURCE_ID in .env.local. Run 'pnpm run bootstrap' (step 1) to pull them." >&2
    return 0
  fi
  if ! out="$(curl -sS --max-time 15 --fail-with-body -X POST \
    -H "Authorization: Bearer $oidc" \
    -H 'Content-Type: application/json' \
    "https://api.vercel.com/v1/integrations/resources/$resource_id/token?role=postgres" 2>&1)"; then
    echo "Could not mint a resource token from VERCEL_OIDC_TOKEN: $out" >&2
    return 0
  fi
  SUPABASE_RESOURCE_TOKEN="$(printf '%s' "$out" | node -e 'try { process.stdout.write(JSON.parse(require("fs").readFileSync(0, "utf8")).token || "") } catch {}')"
  if [ -n "$SUPABASE_RESOURCE_TOKEN" ]; then
    echo "Minted a postgres-role resource token from VERCEL_OIDC_TOKEN." >&2
  else
    echo "The resource token response did not include a token." >&2
  fi
}

access_token_asked=""
ask_access_token() {
  [ -z "${SUPABASE_ACCESS_TOKEN:-}" ] || return 0
  [ -z "$access_token_asked" ] && [ -t 0 ] || return 0
  access_token_asked=1
  cat >&2 <<EOF
The Management API rejected the OIDC resource token. A Supabase access token is the fallback.
  ${hl}Use an experimental API token. It is used for this run only and is not saved.${reset}
  Create one at $dashboard/account/tokens, or set SUPABASE_ACCESS_TOKEN to skip this prompt.
EOF
  read -rs -p "Supabase access token (input hidden, press Enter to skip): " SUPABASE_ACCESS_TOKEN || SUPABASE_ACCESS_TOKEN=""
  echo >&2
  export SUPABASE_ACCESS_TOKEN
}

has_mgmt_credential() {
  [ -n "${SUPABASE_RESOURCE_TOKEN:-}" ] || [ -n "${SUPABASE_ACCESS_TOKEN:-}" ] || [ -t 0 ]
}

# mgmt_api METHOD PATH [BODY] calls $mgmt/v1/projects/$ref/PATH. Sets MGMT_STATUS (000 when the
# request could not be sent), MGMT_BODY and MGMT_AUTH (oidc or access_token). Never exits.
mgmt_api() {
  local method="$1" path="$2" body="${3:-}" kind token out
  MGMT_STATUS=000 MGMT_BODY="no Management API credential" MGMT_AUTH=""
  for kind in oidc access_token; do
    if [ "$kind" = oidc ]; then
      token="${SUPABASE_RESOURCE_TOKEN:-}"
    else
      ask_access_token
      token="${SUPABASE_ACCESS_TOKEN:-}"
    fi
    [ -n "$token" ] || continue
    out="$(curl -sS --max-time 30 -w $'\n%{http_code}' -X "$method" \
      -H "Authorization: Bearer $token" \
      -H 'Content-Type: application/json' \
      ${body:+--data-binary "$body"} \
      "$mgmt/v1/projects/$ref/$path" 2>&1)" || out="$out"$'\n000'
    MGMT_STATUS="${out##*$'\n'}" MGMT_BODY="${out%$'\n'*}" MGMT_AUTH="$kind"
    if [ "$kind" = oidc ] && { [ "$MGMT_STATUS" = 401 ] || [ "$MGMT_STATUS" = 403 ]; }; then
      echo "$method $path: the Management API rejected the OIDC resource token (HTTP $MGMT_STATUS)." >&2
      continue
    fi
    return 0
  done
  return 0
}

mgmt_ok() { [[ "$MGMT_STATUS" =~ ^2[0-9][0-9]$ ]]; }
