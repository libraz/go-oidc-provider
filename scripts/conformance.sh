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

case "${1:-help}" in
  certs)     cmd_certs ;;
  op-up)     cmd_op_up ;;
  op-down)   cmd_op_down ;;
  op-status) cmd_op_status ;;
  help|-h|--help) usage ;;
  *)
    echo "unknown sub-command: $1" >&2
    usage >&2
    exit 1
    ;;
esac
