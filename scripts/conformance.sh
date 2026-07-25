#!/usr/bin/env bash
# conformance.sh — driver for OpenID Foundation Conformance Suite (OFCS) runs.
#
# Sub-commands:
#   certs       Generate a self-signed RSA-2048 cert covering localhost and
#               host.docker.internal for the OP listener, plus a pair of
#               RSA-2048 PKCS#8 client certs (fapi-client.{cert,key}.pem
#               and fapi-client-2.{cert,key}.pem) used by the FAPI 2.0
#               second-client mTLS slot, plus a JKS truststore the
#               bundled OFCS server mounts so it trusts the OP's
#               self-signed cert. All material lands in
#               conformance/certs/.
#   ofcs-up     Bring up the OFCS containers (mongo + nginx + server)
#               from conformance/docker-compose.yml at a pinned release
#               tag. Waits for https://localhost:8443 to answer.
#   ofcs-down   Tear down the OFCS containers and wipe the mongo volume.
#   ofcs-status Print "running" / "stopped" for the OFCS stack.
#   up          One-shot: certs + ofcs-up + op-up + seed-plans. The
#               canonical "from a clean clone, get conformance running"
#               command. Pulls images on first run.
#   down        One-shot: op-down + ofcs-down.
#   op-up       Start cmd/op-demo with TLS, listening on 127.0.0.1:9443.
#               Seeds the demo client with redirect URIs for all three plans.
#               Logs go to conformance/op-demo.log; PID lands in
#               conformance/op-demo.pid so op-down can stop it.
#   op-down     Stop the background op-demo started by op-up.
#   op-status   Print whether op-demo is running.
#   seed-plans  Re-create the OFCS plans from conformance/plans/*.json,
#               injecting mtls/mtls2 PEM material from conformance/certs/
#               into the FAPI 2.0 plans. Plan IDs are written to
#               conformance/.plan-ids.json. (delegates to Python)
#   drive <url> Walk an OFCS test through op-demo's SSR interaction.
#               (delegates to Python)
#   batch <plan-id> <module> [module...]
#               Run each module under the given plan, drive every URL
#               OFCS exposes, poll until terminal, and print
#               pass/fail/skip per module plus a summary line.
#               (delegates to Python)
#   baseline [label]
#               Run every module in every seeded plan and write a
#               deterministic JSON snapshot to
#               conformance/baselines/<UTC-date>-<label>.json.
#               (delegates to Python)
#   baseline-diff <old.json> <new.json>
#               Compare two snapshots produced by `baseline`. Exits
#               non-zero on regressions. (delegates to Python)
#   release-verify <reference.json> <candidate.json> [--exclusions <file>]
#               Strict release gate: require an unchanged module catalog
#               and PASSED results except for exact, unexpired entries in
#               a checked-in exclusion manifest. (delegates to Python)
#   help        Show this help text.
#
# OFCS runs from conformance/docker-compose.yml against pinned image
# tags published to registry.gitlab.com/openid/conformance-suite. The
# Python module under tools/conformance/ owns OFCS REST interaction,
# SSR drive flow, REVIEW screenshot upload, and baseline diff; this
# bash script owns openssl/docker-compose/op-demo orchestration only.
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
TRUSTSTORE_FILE="${CERTS}/truststore.jks"
# OFCS_CA_FILE is the OFCS nginx self-signed cert, extracted via
# `docker exec ... cat /etc/ssl/certs/nginx-selfsigned.crt`. op-up
# passes this to op-demo's -extra-ca-bundle so the JWKS fetcher can
# reach the runner-controlled jwks_uri values OFCS publishes at
# https://localhost.emobix.co.uk:8443/test/<id>/jwks. Absent file
# means oidcc-dynamic / FAPI tests that depend on jwks_uri fail with
# a TLS verification error; the file is dev-only and gitignored.
OFCS_CA_FILE="${CERTS}/ofcs-ca.pem"

# Compose stack — pinned. The image tag lives in
# conformance/docker-compose.yml's IMAGE_TAG default. We re-export it
# here so a `COMPOSE_IMAGE_TAG=release-vX.Y.Z` override on the command
# line propagates to docker compose without editing the YAML.
COMPOSE_FILE="${CONF}/docker-compose.yml"
COMPOSE_PROJECT="go-oidc-ofcs"
TRUSTSTORE_BUILDER_IMAGE="${TRUSTSTORE_BUILDER_IMAGE:-eclipse-temurin:17}"

# host.docker.internal lets the OFCS container reach op-demo running on
# the host. macOS / Windows Docker Desktop wires this DNS name out of
# the box; on Linux we add an extras_hosts entry in OFCS docker-compose.
ISSUER="https://host.docker.internal:9443"
LISTEN=":9443"
MOUNT="/oidc"
CLIENT_ID="demo-client"

# Each OFCS plan gets a callback path keyed on the plan alias; seed
# every alias up front so a single op-demo run covers every profile
# without restarting between plans. Aliases that exercise logout (RP-
# initiated and back-channel) reuse the same /callback shape — op-demo
# derives the matching /post_logout_redirect URI from the suffix.
REDIRECT_URIS="\
https://localhost.emobix.co.uk:8443/test/a/go-oidc-oidcc-basic/callback,\
https://localhost.emobix.co.uk:8443/test/a/go-oidc-oidcc-config/callback,\
https://localhost.emobix.co.uk:8443/test/a/go-oidc-oidcc-dynamic/callback,\
https://localhost.emobix.co.uk:8443/test/a/go-oidc-oidcc-formpost/callback,\
https://localhost.emobix.co.uk:8443/test/a/go-oidc-oidcc-rp-init-logout/callback,\
https://localhost.emobix.co.uk:8443/test/a/go-oidc-oidcc-bc-logout/callback,\
https://localhost.emobix.co.uk:8443/test/a/go-oidc-fapi2-baseline/callback,\
https://localhost.emobix.co.uk:8443/test/a/go-oidc-fapi2-msg-signing/callback,\
https://localhost.emobix.co.uk:8443/test/a/go-oidc-fapi-ciba/callback"

OFCS_API="${OFCS_API:-https://localhost:8443}"
export OFCS_API

usage() {
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e 's/^# \{0,1\}//' -e '$d'
}

cmd_certs() {
  mkdir -p "${CERTS}"
  if [[ -f "${CERT_FILE}" && -f "${KEY_FILE}" ]]; then
    echo "[certs] OP cert already present at ${CERTS} (delete the file to regenerate)"
  else
    cmd_certs_op
  fi
  cmd_certs_fapi_clients
  cmd_certs_truststore
}

# cmd_certs_op writes the listener's RSA-2048 self-signed cert and key.
cmd_certs_op() {
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
  # RSA-2048 (not ECDSA) — OFCS's FAPI 1.0 RW cipher allowlist (still
  # applied under FAPI 2.0 by DisallowInsecureCipher) only contains
  # TLS_DHE_RSA_* and TLS_ECDHE_RSA_* GCM suites. An ECDSA cert can
  # only negotiate TLS_ECDHE_ECDSA_* ciphers, which OFCS treats as
  # "non-permitted" and fails the test on. RSA keeps the cipher within
  # the OFCS-recognised allowlist.
  openssl genrsa -out "${KEY_FILE}" 2048
  openssl req -new -x509 -days 30 \
    -key "${KEY_FILE}" \
    -out "${CERT_FILE}" \
    -config "${CFG_FILE}" \
    -extensions v3
  chmod 0600 "${KEY_FILE}"
  echo "[certs] wrote ${CERT_FILE} and ${KEY_FILE}"
}

# cmd_certs_fapi_clients writes per-client RSA-2048 PKCS#8 cert/key
# pairs used by OFCS's mtls / mtls2 plan slots. OFCS's
# ExtractMTLSCertificates2FromConfiguration is wired into every FAPI
# 2.0 plan regardless of client_authentication_type, and the mTLS
# keystore builder feeds the key bytes into Java's RSAPrivateCrtKeyImpl
# — i.e. ECDSA keys throw at load. The OP itself does not validate
# these certs (sender_constrain=dpop), so any well-formed pair
# satisfies the plan.
cmd_certs_fapi_clients() {
  local client base cert_file key_file tmp_pkcs1
  for client in "fapi-client" "fapi-client-2"; do
    base="${CERTS}/${client}"
    cert_file="${base}.cert.pem"
    key_file="${base}.key.pem"
    if [[ -f "${cert_file}" && -f "${key_file}" ]]; then
      echo "[certs] ${client} mTLS pair already present"
      continue
    fi
    tmp_pkcs1="${base}.key.pkcs1.pem"
    openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
      -keyout "${tmp_pkcs1}" -out "${cert_file}" \
      -subj "/CN=${client}"
    openssl pkcs8 -topk8 -nocrypt -in "${tmp_pkcs1}" -out "${key_file}"
    rm -f "${tmp_pkcs1}"
    chmod 0600 "${key_file}"
    echo "[certs] wrote ${cert_file} and ${key_file}"
  done
}

# cmd_certs_truststore builds a JKS at ${TRUSTSTORE_FILE} that bundles
# the system cacerts (from the eclipse-temurin:17 base used by the
# OFCS server image) plus the OP's self-signed cert. The OFCS server
# container mounts this file read-only and points the JVM at it via
# JAVA_EXTRA_ARGS so https://host.docker.internal:9443 resolves
# without trust errors. Regenerated whenever ${CERT_FILE} is newer
# than the truststore so cert rotations propagate.
cmd_certs_truststore() {
  if [[ ! -f "${CERT_FILE}" ]]; then
    echo "[certs-truststore] missing ${CERT_FILE}; run \`$0 certs\` first" >&2
    exit 1
  fi
  if [[ -f "${TRUSTSTORE_FILE}" && "${TRUSTSTORE_FILE}" -nt "${CERT_FILE}" ]]; then
    echo "[certs-truststore] ${TRUSTSTORE_FILE} already up to date"
    return 0
  fi
  if ! command -v docker >/dev/null 2>&1; then
    echo "[certs-truststore] docker not on PATH; cannot build JKS" >&2
    exit 1
  fi
  echo "[certs-truststore] building ${TRUSTSTORE_FILE} via ${TRUSTSTORE_BUILDER_IMAGE}"
  # Run keytool in a one-shot temurin container so we do not require
  # a JDK on the host. Copy the system cacerts as the seed (so OFCS
  # still trusts the public web), then import the OP cert under a
  # known alias. -noprompt suppresses the "trust this cert?" question.
  docker run --rm \
    -v "${CERTS}:/work" \
    --entrypoint bash \
    "${TRUSTSTORE_BUILDER_IMAGE}" \
    -c '
set -euo pipefail
cp "$JAVA_HOME/lib/security/cacerts" /work/truststore.jks
chmod 0644 /work/truststore.jks
keytool -delete -alias go-oidc-op \
  -keystore /work/truststore.jks -storepass changeit >/dev/null 2>&1 || true
keytool -importcert -trustcacerts -noprompt \
  -keystore /work/truststore.jks -storepass changeit \
  -alias go-oidc-op -file /work/localhost.pem
'
  echo "[certs-truststore] wrote ${TRUSTSTORE_FILE}"
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
  # OPDEMO_RACE=1 builds op-demo with -race so the manual
  # release-prep run can catch concurrent accesses that pass under
  # the unit test suite. The default (unset) is a normal build —
  # -race adds CPU + memory overhead OFCS does not need on every
  # iteration. The flag is silent when unset so casual op-up still
  # builds quickly.
  build_args=()
  if [[ "${OPDEMO_RACE:-}" == "1" ]]; then
    build_args+=(-race)
    echo "[op-up] OPDEMO_RACE=1; building with -race"
  fi
  echo "[op-up] building ${BINFILE}"
  # op-demo is its own module: it links storage drivers (MySQL, Redis)
  # that must not appear in the library's dependency list, so the build
  # runs from its directory rather than from the repository root.
  ( cd "${ROOT}/cmd/op-demo" && GOWORK=off go build "${build_args[@]}" -o "${BINFILE}" . )

  # OP_ENABLE_DCR controls Dynamic Client Registration. Required by
  # the oidcc-dynamic plan and by oidcc-back-channel-rp-initiated-
  # logout's dynamic_client variant; harmless to other plans because
  # they ignore registration_endpoint when present in discovery. The
  # default is therefore "1" (on) so a single op-up serves every
  # seeded plan without the operator having to remember to set the
  # env var per-plan. Set OP_ENABLE_DCR=0 to opt out (e.g. when
  # measuring discovery surface against a non-DCR profile).
  # Op-demo prints the resulting IAT to stdout (captured in ${LOGFILE})
  # so the operator can paste it into OFCS.
  dcr_flag=()
  if [[ "${OP_ENABLE_DCR:-1}" == "1" ]]; then
    dcr_flag+=(-enable-dcr)
  fi

  # OFCS publishes RP-side jwks_uri / request_uri endpoints behind its
  # nginx self-signed cert. Without -extra-ca-bundle the JWKS fetcher's
  # TLS dial rejects those URLs and the oidcc-registration-jwks-uri /
  # oidcc-refresh-token-rp-key-rotation modules surface a verification
  # error before they can complete. The file is optional: missing it
  # silently keeps the system trust store unchanged so a non-OFCS
  # smoke run still works.
  ca_flag=()
  if [[ -f "${OFCS_CA_FILE}" ]]; then
    ca_flag+=(-extra-ca-bundle "${OFCS_CA_FILE}")
  fi

  # OP_PROFILE selects the security profile op-demo runs under. The
  # default ("") = vanilla OIDC Core. Override with
  #   OP_PROFILE=fapi2-baseline scripts/conformance.sh op-up
  # to drive the FAPI 2.0 Baseline plan; the binary then activates
  # WithProfile + the features the profile demands (PAR / DPoP).
  # OP_PROFILE=fapi-ciba activates the FAPI-CIBA profile and the
  # auto-approving CIBA substore wrapper.
  # OP_STORE selects the storage op-demo runs on. The default (inmem)
  # is what the automated gate uses: nothing to run alongside the
  # binary, so a conformance run has no external state to reset
  # between modules. OP_STORE=composite points the durable substores
  # at MySQL and the volatile ones at Redis, which is how a
  # deployment-shaped baseline is captured:
  #
  #   OP_STORE=composite OP_MYSQL_DSN=... OP_REDIS_DSN=... \
  #     scripts/conformance.sh op-up
  #
  # The engines must be reachable before op-up and their state reset
  # between baseline captures — records surviving from a previous run
  # change what replay and reuse modules observe.
  store_flags=(-store "${OP_STORE:-inmem}")
  if [[ -n "${OP_MYSQL_DSN:-}" ]]; then
    store_flags+=(-mysql-dsn "${OP_MYSQL_DSN}")
  fi
  if [[ -n "${OP_REDIS_DSN:-}" ]]; then
    store_flags+=(-redis-dsn "${OP_REDIS_DSN}")
  fi

  echo "[op-up] starting op-demo on ${LISTEN} (issuer=${ISSUER}, profile=${OP_PROFILE:-basic}, dcr=${OP_ENABLE_DCR:-1}, store=${OP_STORE:-inmem})"
  "${BINFILE}" \
    -listen "${LISTEN}" \
    -issuer "${ISSUER}" \
    -mount "${MOUNT}" \
    -client-id "${CLIENT_ID}" \
    -redirect-uri "${REDIRECT_URIS}" \
    -tls-cert "${CERT_FILE}" \
    -tls-key  "${KEY_FILE}" \
    -profile "${OP_PROFILE:-}" \
    -fapi-client-jwks "${ROOT}/conformance/keys/fapi-client.jwks.json" \
    -fapi-client-2-jwks "${ROOT}/conformance/keys/fapi-client-2.jwks.json" \
    "${store_flags[@]}" \
    "${dcr_flag[@]}" \
    "${ca_flag[@]}" \
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

# compose_cmd echoes the docker compose invocation with the project
# name + compose file pinned, so callers can run `$(compose_cmd) up -d`
# without repeating the flags.
compose_cmd() {
  printf 'docker compose -p %q -f %q' "${COMPOSE_PROJECT}" "${COMPOSE_FILE}"
}

extract_ofcs_ca() {
  # Pin the live OFCS nginx self-signed cert into OFCS_CA_FILE so
  # op-demo's JWKS fetcher trusts the runner-controlled jwks_uri
  # endpoints OFCS serves over TLS. The nginx image ships its own cert,
  # which changes whenever the pinned IMAGE_TAG is bumped; extracting it
  # from the running listener here (rather than relying on a hand-copied
  # file) keeps the bundle from going stale against the current suite and
  # silently failing the jwks_uri-dependent modules
  # (oidcc-registration-jwks-uri / oidcc-refresh-token-rp-key-rotation),
  # which surface only as an INTERRUPTED result with no OP-side error.
  local hostport="${OFCS_API#*://}"
  local pem
  if pem="$(printf '' | openssl s_client -connect "${hostport}" \
        -servername localhost.emobix.co.uk 2>/dev/null \
        | openssl x509 2>/dev/null)" && [[ -n "${pem}" ]]; then
    printf '%s\n' "${pem}" > "${OFCS_CA_FILE}"
    echo "[ofcs-up] pinned OFCS CA -> ${OFCS_CA_FILE}"
  else
    echo "[ofcs-up] WARNING: could not extract OFCS CA from ${hostport}; jwks_uri modules may fail" >&2
  fi
}

cmd_ofcs_up() {
  if [[ ! -f "${TRUSTSTORE_FILE}" ]]; then
    echo "[ofcs-up] missing ${TRUSTSTORE_FILE}; run \`$0 certs\` first" >&2
    exit 1
  fi
  if ! command -v docker >/dev/null 2>&1; then
    echo "[ofcs-up] docker not on PATH" >&2
    exit 1
  fi
  echo "[ofcs-up] starting OFCS stack from ${COMPOSE_FILE}"
  eval "$(compose_cmd) up -d"
  echo "[ofcs-up] waiting for ${OFCS_API} to answer (this can take ~60s on a cold start)"
  local i
  for i in $(seq 1 90); do
    if curl -sk --max-time 2 -o /dev/null -w '%{http_code}' \
         "${OFCS_API}/" 2>/dev/null | grep -qE '^(200|302|401|403|404)$'; then
      echo "[ofcs-up] OFCS UI reachable after ${i}s"
      extract_ofcs_ca
      return 0
    fi
    sleep 1
  done
  echo "[ofcs-up] timed out waiting for OFCS; tail of server logs:" >&2
  eval "$(compose_cmd) logs --tail=40 server" >&2 || true
  exit 1
}

cmd_ofcs_down() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "[ofcs-down] docker not on PATH" >&2
    exit 1
  fi
  echo "[ofcs-down] stopping OFCS stack and clearing mongo volume"
  # `down -v` wipes the named mongo volume so the next `up` starts
  # from a clean OFCS state (no leftover plans / test instances).
  eval "$(compose_cmd) down -v"
}

cmd_ofcs_status() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "stopped (docker not on PATH)"
    return 0
  fi
  local running
  running="$(eval "$(compose_cmd) ps --status=running --services" 2>/dev/null || true)"
  if [[ -z "${running}" ]]; then
    echo "stopped"
  else
    echo "running (services: $(echo "${running}" | paste -sd, -))"
  fi
}

# wait_op_healthy polls the OP discovery doc until it answers, so the
# subsequent seed-plans step does not race the listener boot. OIDC
# Discovery 1.0 puts /.well-known/openid-configuration at the issuer
# root regardless of the mount path.
wait_op_healthy() {
  local i
  for i in $(seq 1 30); do
    if curl -sk --max-time 2 -o /dev/null -w '%{http_code}' \
         "https://127.0.0.1:9443/.well-known/openid-configuration" 2>/dev/null \
         | grep -qE '^200$'; then
      echo "[op-up] discovery reachable after ${i}s"
      return 0
    fi
    sleep 1
  done
  echo "[op-up] timed out waiting for OP discovery" >&2
  return 1
}

cmd_up() {
  cmd_certs
  cmd_ofcs_up
  cmd_op_up
  wait_op_healthy
  py seed-plans
  echo
  echo "[up] OFCS at ${OFCS_API} (UI: open https://localhost:8443)"
  echo "[up] OP at ${ISSUER} (discovery: ${ISSUER}${MOUNT}/.well-known/openid-configuration)"
  echo "[up] next: scripts/conformance.sh batch <plan-id> <module>..."
}

cmd_down() {
  cmd_op_down || true
  cmd_ofcs_down || true
}

# py forwards <subcommand> to the Python driver. The Python module
# owns OFCS REST interaction, SSR drive flow, REVIEW screenshot
# upload, and baseline diff; this bash script keeps openssl/docker/op
# orchestration only.
py() {
  ( cd "${ROOT}" && exec python3 -m tools.conformance "$@" )
}

case "${1:-help}" in
  certs)        cmd_certs ;;
  ofcs-up)      cmd_ofcs_up ;;
  ofcs-down)    cmd_ofcs_down ;;
  ofcs-status)  cmd_ofcs_status ;;
  up)           cmd_up ;;
  down)         cmd_down ;;
  op-up)        cmd_op_up ;;
  op-down)      cmd_op_down ;;
  op-status)    cmd_op_status ;;
  seed-plans|drive|batch|baseline|baseline-diff|release-verify)
                py "$@" ;;
  help|-h|--help) usage ;;
  *)
    echo "unknown sub-command: $1" >&2
    usage >&2
    exit 1
    ;;
esac
