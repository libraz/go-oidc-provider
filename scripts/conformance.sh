#!/usr/bin/env bash
# conformance.sh — driver for OpenID Foundation Conformance Suite (OFCS) runs.
#
# Sub-commands:
#   certs       Generate a self-signed ECDSA P-256 cert covering localhost
#               and host.docker.internal. Writes conformance/certs/{cert,key}.pem.
#   op-up       Start cmd/op-demo with TLS, listening on 127.0.0.1:9443.
#               Seeds the demo client with redirect URIs for all three plans.
#               Logs go to conformance/op-demo.log; PID lands in
#               conformance/op-demo.pid so op-down can stop it.
#   op-down     Stop the background op-demo started by op-up.
#   op-status   Print whether op-demo is running.
#   drive <url> Walk an OFCS test through op-demo's SSR interaction:
#               GET <authorize-url> -> POST credentials -> POST consent
#               -> forward callback to OFCS -> POST implicit-bridge body.
#               OFCS_DEMO_USER / OFCS_DEMO_PASS env vars override the
#               default "demo"/"demo" credentials seeded by op-demo.
#   help        Show this help text.
#
# OFCS itself is NOT started by this script — see conformance/README.md
# for the recommended setup (clone openid/conformance-suite, run its own
# docker-compose). Once OFCS is up at https://localhost:8443, run
# `op-up`, import a plan from conformance/plans/, and execute it through
# the OFCS web UI. Headless plan submission via OFCS REST API is
# deferred to the E2-green wave because the API surface is not version-
# stable across releases.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF="${ROOT}/conformance"
CERTS="${CONF}/certs"
PIDFILE="${CONF}/op-demo.pid"
LOGFILE="${CONF}/op-demo.log"
BINFILE="${CONF}/op-demo.bin"

CERT_FILE="${CERTS}/localhost.pem"
KEY_FILE="${CERTS}/localhost-key.pem"
CFG_FILE="${CERTS}/openssl.cnf"

# host.docker.internal lets the OFCS container reach op-demo running on
# the host. macOS / Windows Docker Desktop wires this DNS name out of
# the box; on Linux we add an extras_hosts entry in OFCS docker-compose.
ISSUER="https://host.docker.internal:9443"
LISTEN=":9443"
MOUNT="/oidc"
CLIENT_ID="demo-client"

# Each OFCS plan gets a callback path keyed on the plan alias; seed
# every alias up front so a single op-demo run covers all three
# profiles without restarting between plans.
REDIRECT_URIS="\
https://localhost.emobix.co.uk:8443/test/a/go-oidc-oidcc-basic/callback,\
https://localhost.emobix.co.uk:8443/test/a/go-oidc-fapi2-baseline/callback,\
https://localhost.emobix.co.uk:8443/test/a/go-oidc-fapi2-msg-signing/callback"

usage() {
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e 's/^# \{0,1\}//' -e '$d'
}

cmd_certs() {
  mkdir -p "${CERTS}"
  if [[ -f "${CERT_FILE}" && -f "${KEY_FILE}" ]]; then
    echo "[certs] already present at ${CERTS} (delete the directory to regenerate)"
    return 0
  fi
  cat > "${CFG_FILE}" <<'EOF'
[req]
distinguished_name = req_dn
x509_extensions    = v3
prompt             = no
[req_dn]
CN = localhost
[v3]
basicConstraints       = CA:FALSE
keyUsage               = digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = @san
[san]
DNS.1 = localhost
DNS.2 = host.docker.internal
IP.1  = 127.0.0.1
IP.2  = ::1
EOF
  openssl ecparam -name prime256v1 -genkey -noout -out "${KEY_FILE}"
  openssl req -new -x509 -days 30 \
    -key "${KEY_FILE}" \
    -out "${CERT_FILE}" \
    -config "${CFG_FILE}" \
    -extensions v3
  chmod 0600 "${KEY_FILE}"
  echo "[certs] wrote ${CERT_FILE} and ${KEY_FILE}"
}

cmd_op_up() {
  if [[ -f "${PIDFILE}" ]] && kill -0 "$(cat "${PIDFILE}")" 2>/dev/null; then
    echo "[op-up] already running (pid $(cat "${PIDFILE}"))"
    return 0
  fi
  if [[ ! -f "${CERT_FILE}" || ! -f "${KEY_FILE}" ]]; then
    echo "[op-up] missing TLS material; run \"$0 certs\" first" >&2
    exit 1
  fi
  mkdir -p "${CONF}"

  # Pre-build a binary instead of `go run`. `go run` keeps a parent
  # process alive that forks the actual binary as a child; killing the
  # parent does not always reap the child, which leaks a listener on
  # ${LISTEN}. Building once and exec-ing the binary directly means
  # the captured PID is the only process to manage.
  echo "[op-up] building ${BINFILE}"
  ( cd "${ROOT}" && go build -o "${BINFILE}" ./cmd/op-demo )

  echo "[op-up] starting op-demo on ${LISTEN} (issuer=${ISSUER})"
  "${BINFILE}" \
    -listen "${LISTEN}" \
    -issuer "${ISSUER}" \
    -mount "${MOUNT}" \
    -client-id "${CLIENT_ID}" \
    -redirect-uri "${REDIRECT_URIS}" \
    -tls-cert "${CERT_FILE}" \
    -tls-key  "${KEY_FILE}" \
    > "${LOGFILE}" 2>&1 &
  echo $! > "${PIDFILE}"
  sleep 1
  if ! kill -0 "$(cat "${PIDFILE}")" 2>/dev/null; then
    echo "[op-up] failed to start; tail of ${LOGFILE}:" >&2
    tail -20 "${LOGFILE}" >&2 || true
    rm -f "${PIDFILE}"
    exit 1
  fi
  echo "[op-up] pid $(cat "${PIDFILE}"), log ${LOGFILE}"
  echo "[op-up] discovery: ${ISSUER}/.well-known/openid-configuration"
}

cmd_op_down() {
  if [[ ! -f "${PIDFILE}" ]]; then
    echo "[op-down] no pid file at ${PIDFILE}"
    return 0
  fi
  pid="$(cat "${PIDFILE}")"
  if kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}"
    for _ in 1 2 3 4 5; do
      if ! kill -0 "${pid}" 2>/dev/null; then break; fi
      sleep 0.5
    done
    kill -9 "${pid}" 2>/dev/null || true
    echo "[op-down] stopped pid ${pid}"
  else
    echo "[op-down] pid ${pid} not running"
  fi
  rm -f "${PIDFILE}"
}

cmd_op_status() {
  if [[ -f "${PIDFILE}" ]] && kill -0 "$(cat "${PIDFILE}")" 2>/dev/null; then
    echo "running (pid $(cat "${PIDFILE}"))"
  else
    echo "stopped"
  fi
}

# extract_field <html> <name> -> first <input name="..." value="..."> match.
extract_field() {
  printf '%s' "$1" \
    | grep -oE "name=\"$2\" value=\"[^\"]*\"" \
    | head -1 \
    | sed -E "s/.*value=\"([^\"]*)\"/\1/"
}

# split_body <raw-response> -> body (stripping the HTTP header block).
split_body() {
  printf '%s' "$1" | awk 'flag{print} /^[[:space:]]*$/{flag=1}'
}

cmd_drive() {
  local auth_url="${1:-}"
  if [[ -z "$auth_url" ]]; then
    echo "[drive] usage: $0 drive <authorize-url>" >&2
    echo "[drive] obtain the URL from the OFCS test runner ('Browser' link)" >&2
    exit 1
  fi

  local user="${OFCS_DEMO_USER:-demo}"
  local pass="${OFCS_DEMO_PASS:-demo}"
  local cookies
  cookies="$(mktemp /tmp/ofcs-cookies.XXXXXX)"
  # Expand $cookies at trap-set time: by EXIT it is out of scope (local).
  trap "rm -f '$cookies'" EXIT

  # --resolve forces host.docker.internal to localhost from the host so
  # the same DNS name works inside and outside docker. -k is required
  # because conformance/certs/localhost.pem is self-signed.
  local curl_base=(curl -sk
    --resolve "host.docker.internal:9443:127.0.0.1"
    --cookie-jar "$cookies" --cookie "$cookies")

  echo "[drive 1/3] GET ${auth_url}"
  local prompt interaction_url body state_ref csrf
  prompt="$("${curl_base[@]}" -L "$auth_url" -i \
    -w '\n__EFFECTIVE_URL__=%{url_effective}\n')"
  interaction_url="$(printf '%s' "$prompt" \
    | awk -F= '/^__EFFECTIVE_URL__=/{print $2}')"
  prompt="$(printf '%s' "$prompt" | grep -v '^__EFFECTIVE_URL__=')"
  body="$(split_body "$prompt")"

  # Error-path tests (e.g. response-type-missing) trigger a direct
  # redirect from /authorize back to the OFCS callback host; there is
  # no SSR prompt to walk. Detect that and jump to the forward step.
  if [[ "$interaction_url" == https://localhost.emobix.co.uk:8443/* ]]; then
    echo "[drive 1/3] /authorize landed on OFCS callback (error-path)"
    forward_implicit_bridge "$interaction_url" "$body"
    return 0
  fi

  state_ref="$(extract_field "$body" state_ref)"
  csrf="$(extract_field "$body" csrf_token)"

  if [[ -z "$state_ref" || -z "$csrf" || -z "$interaction_url" ]]; then
    echo "[drive] failed to parse interaction state from initial prompt" >&2
    exit 1
  fi
  echo "[drive 1/3] interaction_url=${interaction_url}"

  echo "[drive 2/3] POST credentials (user=${user})"
  local pwd_resp body2 state_ref2 csrf2 approved
  pwd_resp="$("${curl_base[@]}" -X POST "$interaction_url" \
    -H "Origin: ${ISSUER}" \
    --data-urlencode "state_ref=$state_ref" \
    --data-urlencode "csrf_token=$csrf" \
    --data-urlencode "username=$user" \
    --data-urlencode "password=$pass" -i)"
  body2="$(split_body "$pwd_resp")"
  state_ref2="$(extract_field "$body2" state_ref)"
  csrf2="$(extract_field "$body2" csrf_token)"
  approved="$(extract_field "$body2" approved_scopes)"

  if [[ -z "$state_ref2" ]]; then
    echo "[drive] login failed; consent prompt missing state_ref" >&2
    printf '%s\n' "$body2" | head -40 >&2
    exit 1
  fi

  echo "[drive 3/3] POST consent (approved_scopes=${approved})"
  # -L would follow the success redirect into OFCS where session cookies
  # don't apply; capture redirect_url instead and re-issue ourselves.
  local final redirect
  set +e
  final="$(curl -sk \
    --resolve "host.docker.internal:9443:127.0.0.1" \
    --cookie-jar "$cookies" --cookie "$cookies" \
    -X POST "$interaction_url" \
    -H "Origin: ${ISSUER}" \
    --data-urlencode "state_ref=$state_ref2" \
    --data-urlencode "csrf_token=$csrf2" \
    --data-urlencode "approved_scopes=$approved" \
    -o /dev/null -w '%{http_code} %{redirect_url}\n')"
  set -e
  echo "[drive 3/3] response=${final}"
  redirect="$(printf '%s' "$final" | awk '{print $2}')"
  if [[ -z "$redirect" \
    || "$redirect" != https://localhost.emobix.co.uk:8443/* ]]; then
    echo "[drive] no OFCS callback redirect; aborting" >&2
    exit 1
  fi

  forward_implicit_bridge "$redirect" ""
}

# forward_implicit_bridge <ofcs-callback-url> [callback-html]
# Posts the OFCS implicit-bridge body that submits the callback query
# string back to the test runner. If <callback-html> is empty the
# function fetches the callback page itself.
forward_implicit_bridge() {
  local redirect="$1" cb_html="$2" impl alias_base query
  if [[ -z "$cb_html" ]]; then
    echo "[drive forward] GET ${redirect}"
    cb_html="$(curl -sk "$redirect")"
  fi
  # OFCS HTML-escapes the slash in the implicit-bridge URL.
  impl="$(printf '%s' "$cb_html" \
    | grep -oE 'implicit\\?/[A-Za-z0-9]+' | head -1 | tr -d '\\')"
  if [[ -z "$impl" ]]; then
    echo "[drive forward] callback page has no implicit-bridge URL"
    return 0
  fi
  alias_base="$(printf '%s' "$redirect" | sed -E 's|/callback\?.*$||')"
  query="$(printf '%s' "$redirect" | sed -E 's|^[^?]*\?|?|')"
  echo "[drive forward] POST ${alias_base}/${impl}"
  curl -sk -X POST "${alias_base}/${impl}" \
    -H 'Content-Type: text/plain' \
    --data-binary "$query" \
    -o /dev/null -w '[drive forward] implicit_post=%{http_code}\n'
}

case "${1:-help}" in
  certs)     cmd_certs ;;
  op-up)     cmd_op_up ;;
  op-down)   cmd_op_down ;;
  op-status) cmd_op_status ;;
  drive)     shift; cmd_drive "$@" ;;
  help|-h|--help) usage ;;
  *)
    echo "unknown sub-command: $1" >&2
    usage >&2
    exit 1
    ;;
esac
