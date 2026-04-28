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
#   seed-plans  Re-create the OFCS plans from conformance/plans/*.json,
#               injecting mtls/mtls2 PEM material from conformance/certs/
#               into the FAPI 2.0 plans. Prints the new plan IDs. The
#               OFCS REST endpoint requires the variant via URL parameter
#               (the JSON body is the configuration only).
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
#   batch <plan-id> <module> [module...]
#               Trigger each named OFCS module under the given plan,
#               drive every browser URL OFCS exposes (handles
#               multi-step tests like prompt-none / max-age /
#               id-token-hint / refresh-token), poll until terminal,
#               and report pass/fail per module plus a summary line.
#               The variant defaults to client_secret_basic + code +
#               default response_mode; oidcc-server-client-secret-post
#               is auto-promoted to client_secret_post.
#   baseline [label]
#               Run every module in every seeded plan and write a
#               deterministic JSON snapshot to
#               conformance/baselines/<UTC-date>-<label>.json. The
#               module list per plan is queried from OFCS at runtime
#               (so catalog drift is captured automatically). Plan
#               IDs come from conformance/.plan-ids.json which
#               seed-plans writes on every successful seed.
#               LABEL defaults to "snapshot"; pass any short slug
#               that names the moment in time (e.g. "pre-loginflow").
#               Set BASELINE_FILTER to a regex to limit modules
#               (matched against module name).
#   baseline-diff <old-baseline.json> <new-baseline.json>
#               Compare two snapshots produced by `baseline`. Prints
#               regressions (modules that lost PASSED) and fixes
#               (modules that gained PASSED), and exits non-zero on
#               any regression. Pure JSON comparison — does NOT
#               require OFCS to be running.
#   help        Show this help text.
#
# OFCS runs from conformance/docker-compose.yml against pinned image
# tags published to registry.gitlab.com/openid/conformance-suite. The
# `up` sub-command brings up the whole stack (OFCS + OP) end-to-end;
# the legacy "clone the OFCS repo and run mvn install" path is no
# longer required.
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
  echo "[op-up] building ${BINFILE}"
  ( cd "${ROOT}" && go build -o "${BINFILE}" ./cmd/op-demo )

  # OP_PROFILE selects the security profile op-demo runs under. The
  # default ("") = vanilla OIDC Core. Override with
  #   OP_PROFILE=fapi2-baseline scripts/conformance.sh op-up
  # to drive the FAPI 2.0 Baseline plan; the binary then activates
  # WithProfile + the features the profile demands (PAR / DPoP).
  echo "[op-up] starting op-demo on ${LISTEN} (issuer=${ISSUER}, profile=${OP_PROFILE:-basic})"
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
  echo "[ofcs-up] waiting for https://localhost:8443 to answer (this can take ~60s on a cold start)"
  local i
  for i in $(seq 1 90); do
    if curl -sk --max-time 2 -o /dev/null -w '%{http_code}' \
         "${OFCS_API}/" 2>/dev/null | grep -qE '^(200|302|401|403|404)$'; then
      echo "[ofcs-up] OFCS UI reachable after ${i}s"
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
  cmd_seed_plans
  echo
  echo "[up] OFCS at ${OFCS_API} (UI: open https://localhost:8443)"
  echo "[up] OP at ${ISSUER} (discovery: ${ISSUER}${MOUNT}/.well-known/openid-configuration)"
  echo "[up] next: scripts/conformance.sh batch <plan-id> <module>..."
}

cmd_down() {
  cmd_op_down || true
  cmd_ofcs_down || true
}

# cmd_seed_plans posts each conformance/plans/*.json to OFCS as a fresh
# plan, embedding RSA mTLS material (generated by `certs`) into the
# mtls / mtls2 slots for FAPI 2.0 plans. OFCS only reads the variant
# from the URL parameter, so we strip it from the JSON body and pass
# it separately. Prints one "[seed] <plan-name> -> plan_id=<id>" line
# per plan; existing OFCS plans are left untouched (OFCS does not
# expose a delete endpoint via REST).
cmd_seed_plans() {
  local plans_dir="${CONF}/plans"
  local tmpdir
  tmpdir="$(mktemp -d "/tmp/ofcs-seed-plans.XXXXXX")"
  # NB: do not use `trap RETURN` here — the handler captures ${tmpdir}
  # by name and persists past this function's lifetime, firing on the
  # next function return when the variable is already out of scope and
  # tripping `set -u`. Clean up explicitly at the end of the function
  # via a tail-only `_seed_plans_cleanup` sentinel.
  local entry f plan_name plan_file body_file variant resp id alias_name
  # plan_ids_json accumulates {plan_name: {id, alias, planFile}} so the
  # baseline sub-command can find every seeded plan without re-asking the
  # operator. The mapping is rewritten on every successful seed run so a
  # stale entry from a prior OFCS instance never leaks.
  local plan_ids_file="${CONF}/.plan-ids.json"
  local plan_ids_tmp
  plan_ids_tmp="$(mktemp "/tmp/ofcs-plan-ids.XXXXXX")"
  printf '{}' > "${plan_ids_tmp}"
  # File → OFCS planName mapping. OFCS does not expose a "list plan
  # definitions" endpoint, so the names are baked in here.
  for entry in \
      "oidcc-basic.json|oidcc-basic-certification-test-plan" \
      "fapi2-baseline.json|fapi2-security-profile-id2-test-plan" \
      "fapi2-message-signing.json|fapi2-message-signing-id1-test-plan"; do
    f="${entry%|*}"
    plan_name="${entry#*|}"
    plan_file="${plans_dir}/${f}"
    if [[ ! -f "${plan_file}" ]]; then
      echo "[seed] missing ${plan_file}; skipping"
      continue
    fi
    PLAN_FILE="${plan_file}" \
    CERTS_DIR="${CERTS}" \
    OUT_DIR="${tmpdir}" \
    PLAN_KEY="${f}" \
      python3 - <<'PY'
import json, os, pathlib, urllib.parse
plan_file = pathlib.Path(os.environ["PLAN_FILE"])
out_dir   = pathlib.Path(os.environ["OUT_DIR"])
certs_dir = pathlib.Path(os.environ["CERTS_DIR"])
key       = os.environ["PLAN_KEY"]
cfg = json.loads(plan_file.read_text())
variant = cfg.pop("variant", None) or {}
if key.startswith("fapi2-"):
    for slot, base in [("mtls", "fapi-client"), ("mtls2", "fapi-client-2")]:
        cert_p = certs_dir / f"{base}.cert.pem"
        key_p  = certs_dir / f"{base}.key.pem"
        if cert_p.exists() and key_p.exists():
            cfg[slot] = {"cert": cert_p.read_text(), "key": key_p.read_text()}
    # The Baseline plan hardcodes fapi_request_method=unsigned and
    # fapi_response_mode=plain_response — passing them at plan creation
    # is rejected with "Variant '...' has been set by user, but test
    # plan already has them set". The Message Signing plan instead
    # requires both at plan-level (signed_non_repudiation + jarm) so
    # the modules apply the right shape. Filter for Baseline only.
    if key == "fapi2-baseline.json":
        for drop in ("fapi_request_method", "fapi_response_mode"):
            variant.pop(drop, None)
elif key == "oidcc-basic.json" and not variant:
    # The oidcc-basic plan refuses creation without a server_metadata /
    # client_registration variant. The seed JSON omits them because the
    # OFCS UI fills them in interactively; supply the defaults here.
    variant = {"server_metadata": "discovery", "client_registration": "static_client"}
(out_dir / "body.json").write_text(json.dumps(cfg))
(out_dir / "variant.txt").write_text(urllib.parse.quote(json.dumps(variant)))
PY
    body_file="${tmpdir}/body.json"
    variant="$(cat "${tmpdir}/variant.txt")"
    resp="$(curl -sk -X POST \
      "${OFCS_API}/api/plan?planName=${plan_name}&variant=${variant}" \
      -H 'Content-Type: application/json' \
      --data-binary "@${body_file}")"
    id="$(printf '%s' "$resp" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))' \
      2>/dev/null || true)"
    if [[ -z "${id}" ]]; then
      echo "[seed] failed for ${f}: ${resp:0:200}" >&2
      continue
    fi
    alias_name="$(python3 -c 'import json,pathlib,sys; print(json.loads(pathlib.Path(sys.argv[1]).read_text()).get("alias",""))' "${plan_file}")"
    echo "[seed] ${plan_name} -> plan_id=${id} (alias=${alias_name})"
    PLAN_IDS_FILE="${plan_ids_tmp}" PLAN_NAME="${plan_name}" PLAN_ID="${id}" \
    ALIAS_NAME="${alias_name}" PLAN_KEY_FILE="${f}" \
      python3 - <<'PY'
import json, os, pathlib
p = pathlib.Path(os.environ["PLAN_IDS_FILE"])
data = json.loads(p.read_text() or "{}")
data[os.environ["PLAN_NAME"]] = {
    "id":       os.environ["PLAN_ID"],
    "alias":    os.environ["ALIAS_NAME"],
    "planFile": os.environ["PLAN_KEY_FILE"],
}
p.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
PY
  done
  mv "${plan_ids_tmp}" "${plan_ids_file}"
  echo "[seed] plan IDs written to ${plan_ids_file}"
  rm -rf "${tmpdir}"
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
  # Multi-step OFCS tests (prompt-none, max-age, id-token-hint) call
  # /authorize twice and rely on the first call to plant a session
  # cookie the second uses for silent re-auth. Honor OFCS_DRIVE_COOKIES
  # so a wrapping runner can pin one cookie jar across both drives;
  # otherwise allocate a per-call temp file and clean up on exit.
  if [[ -n "${OFCS_DRIVE_COOKIES:-}" ]]; then
    cookies="$OFCS_DRIVE_COOKIES"
    [[ -e "$cookies" ]] || touch "$cookies"
    # No EXIT cleanup — the caller owns the file's lifetime.
  else
    cookies="$(mktemp /tmp/ofcs-cookies.XXXXXX)"
    # Expand $cookies at trap-set time: by EXIT it is out of scope (local).
    trap "rm -f '$cookies'" EXIT
  fi

  # --resolve forces host.docker.internal to localhost from the host so
  # the same DNS name works inside and outside docker. -k is required
  # because conformance/certs/localhost.pem is self-signed.
  local curl_base=(curl -sk
    --resolve "host.docker.internal:9443:127.0.0.1"
    --cookie-jar "$cookies" --cookie "$cookies")

  # Tests that need ≥2 visits to the same authorize URL before
  # authentication completes (RFC 9126 §2.2 reuse-before-completion)
  # tell us via OFCS_DRIVE_DOUBLE_VISIT. We cannot fire two real GETs
  # because each would create a new interaction state behind the
  # scenes; OFCS only checks getVisited()'s frequency for the URL, so
  # we register both visits through the runner browser API. The OP is
  # responsible for accepting the second resolution of the same
  # request_uri (Find, not Consume, until code emission); the unit
  # test [TestEndToEnd_PAR_AuthorizeRejectsReplay] anchors that
  # contract.
  if [[ "${OFCS_DRIVE_DOUBLE_VISIT:-0}" == "1" && -n "${OFCS_RUNNER_ID:-}" ]]; then
    echo "[drive pre] register two browser visits for reuse-before-auth"
    for visit_n in 1 2; do
      curl -sk -X POST "${OFCS_API}/api/runner/browser/${OFCS_RUNNER_ID}/visit" \
        --data-urlencode "url=${auth_url}" \
        -o /dev/null -w "[drive pre] visit#${visit_n}=%{http_code}\n"
    done
  fi

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

  # Pre-redirect-trust error: /authorize returns 400 with a JSON
  # envelope when something is wrong before the redirect_uri is
  # validated (PAR-required without request_uri, unknown client_id,
  # malformed parameters, …). There is no interaction prompt to walk
  # and no callback to forward to — OFCS will detect the rejection
  # by polling /api/info and rule the test on its own (typically as
  # WAITING/REVIEW for a manual screenshot upload). Return 0 so the
  # outer batch keeps moving instead of bailing the whole run.
  if printf '%s' "$body" | grep -q '"error":'; then
    echo "[drive 1/3] /authorize returned a JSON error envelope; OFCS will rule via REVIEW"
    return 0
  fi

  state_ref="$(extract_field "$body" state_ref)"
  csrf="$(extract_field "$body" csrf_token)"

  if [[ -z "$state_ref" || -z "$csrf" || -z "$interaction_url" ]]; then
    echo "[drive] failed to parse interaction state from initial prompt" >&2
    return 0
  fi
  echo "[drive 1/3] interaction_url=${interaction_url}"

  # OFCS_DRIVE_REJECT=1 simulates the user pressing "cancel" on the
  # consent screen. The library's interaction handler responds to a
  # DELETE on the interaction URL by emitting an access_denied
  # redirect — exactly what the OFCS user-rejects-authentication
  # module asserts on. Forward the resulting OFCS callback URL.
  if [[ "${OFCS_DRIVE_REJECT:-0}" == "1" ]]; then
    echo "[drive reject] DELETE ${interaction_url}"
    local reject_resp reject_redirect
    set +e
    reject_resp="$(curl -sk \
      --resolve "host.docker.internal:9443:127.0.0.1" \
      --cookie-jar "$cookies" --cookie "$cookies" \
      -X DELETE "$interaction_url" \
      -o /dev/null -w '%{http_code} %{redirect_url}\n')"
    set -e
    echo "[drive reject] response=${reject_resp}"
    reject_redirect="$(printf '%s' "$reject_resp" | awk '{print $2}')"
    if [[ -z "$reject_redirect" \
      || "$reject_redirect" != https://localhost.emobix.co.uk:8443/* ]]; then
      echo "[drive reject] no OFCS callback redirect; aborting" >&2
      return 0
    fi
    forward_implicit_bridge "$reject_redirect" ""
    return 0
  fi

  echo "[drive 2/3] POST credentials (user=${user})"
  local pwd_resp body2 state_ref2 csrf2 approved pwd_redirect
  pwd_resp="$("${curl_base[@]}" -X POST "$interaction_url" \
    -H "Origin: ${ISSUER}" \
    --data-urlencode "state_ref=$state_ref" \
    --data-urlencode "csrf_token=$csrf" \
    --data-urlencode "username=$user" \
    --data-urlencode "password=$pass" -i)"
  # If the OP granted consent silently (cookie-stored prior consent,
  # prompt=login on a session that already approved this client) the
  # credentials POST returns a 302 straight to the OFCS callback —
  # there is no consent prompt to walk. Forward the implicit-bridge.
  pwd_redirect="$(printf '%s' "$pwd_resp" \
    | awk 'tolower($1)=="location:"{print $2; exit}' | tr -d '\r')"
  if [[ "$pwd_redirect" == https://localhost.emobix.co.uk:8443/* ]]; then
    echo "[drive 2/3] OP skipped consent (silent approval) — redirect=${pwd_redirect}"
    forward_implicit_bridge "$pwd_redirect" ""
    return 0
  fi
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
  # When the redirect target carries the response in the query string
  # (code flow / response_mode=query), the implicit-bridge body must
  # NOT replay the same code/state — otherwise OFCS interprets it as
  # "the response was also in the URL fragment" and FAPI 2.0's
  # RejectAuthCodeInUrlFragment fires. But it also cannot be empty:
  # FAPI 2.0 conditions read callback_params.code as a string and
  # throw on JsonNull. Send explicit empty values for code/state so
  # OFCS records "fragment present, no code, no state".
  if [[ "$redirect" == *"?code="* || "$redirect" == *"&code="* \
        || "$redirect" == *"?error="* || "$redirect" == *"&error="* ]]; then
    # Empty values for code/state without a leading "?" — OFCS parses
    # the body as a raw query string, so a leading "?" would corrupt
    # the first key (e.g. "?code"). FAPI 2.0 conditions require
    # callback_params.code to be a string (not JsonNull), so explicit
    # empty strings keep RejectAuthCodeInUrlFragment happy.
    query="code=&state="
  else
    query="$(printf '%s' "$redirect" | sed -E 's|^[^?]*\?||')"
  fi
  echo "[drive forward] POST ${alias_base}/${impl}"
  curl -sk -X POST "${alias_base}/${impl}" \
    -H 'Content-Type: text/plain' \
    --data-binary "$query" \
    -o /dev/null -w '[drive forward] implicit_post=%{http_code}\n'
}

OFCS_API="https://localhost:8443"

# json_field <stdin-json> <key>: dump a top-level key via python so
# parsing stays tolerant of OFCS's occasional whitespace/case quirks.
json_field() {
  python3 -c "import json,sys; print((json.load(sys.stdin) or {}).get('$1','') or '')"
}

# drive_all_urls <runner-id> [max_iters]: poll the runner for queued
# browser URLs and feed each unseen one through `drive`. Bails when
# /api/info/<id> reports a terminal state.
drive_all_urls() {
  local id="$1" max_iters="${2:-40}"
  local driven=" " urls url s found i
  # Forward the runner id so cmd_drive can call back into the OFCS
  # browser visit endpoint when a test (currently only the
  # PAR reused-request-uri-prior-to-auth-completion check) needs an
  # extra visit registered.
  OFCS_RUNNER_ID="$id"
  export OFCS_RUNNER_ID
  for ((i=0; i<max_iters; i++)); do
    urls="$(curl -sk "${OFCS_API}/api/runner/$id" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for u in (d.get("browser") or {}).get("urls") or []:
    print(u)
' 2>/dev/null || true)"
    found=0
    while IFS= read -r url; do
      [[ -z "$url" ]] && continue
      [[ "$driven" == *" $url "* ]] && continue
      echo "  -> driving step URL"
      cmd_drive "$url" || true
      driven+="$url "
      found=1
      sleep 1
    done <<< "$urls"
    if [[ "$found" -eq 0 ]]; then
      # No new URLs since last poll. RUNNING and WAITING are both
      # "still working"; only FINISHED / INTERRUPTED are terminal.
      s="$(curl -sk "${OFCS_API}/api/info/$id" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))' \
        2>/dev/null || true)"
      [[ "$s" == "FINISHED" || "$s" == "INTERRUPTED" ]] && return 0
      sleep 1
    fi
  done
}

# _select_variant <module> echoes the urlencoded JSON variant string to
# launch the module under. Centralised here so both cmd_batch and
# cmd_baseline pick consistent variants. BATCH_VARIANT overrides the
# auto-selected value (kept for ad-hoc cmd_batch invocations).
_select_variant() {
  local m="$1"
  local default_variant client_secret_post_variant fapi2_baseline_variant
  default_variant='%7B%22client_auth_type%22%3A%22client_secret_basic%22%2C%22response_type%22%3A%22code%22%2C%22response_mode%22%3A%22default%22%7D'
  client_secret_post_variant='%7B%22client_auth_type%22%3A%22client_secret_post%22%2C%22response_type%22%3A%22code%22%2C%22response_mode%22%3A%22default%22%7D'
  fapi2_baseline_variant='%7B%22client_auth_type%22%3A%22private_key_jwt%22%2C%22sender_constrain%22%3A%22dpop%22%2C%22fapi_profile%22%3A%22plain_fapi%22%2C%22openid%22%3A%22openid_connect%22%2C%22fapi_request_method%22%3A%22unsigned%22%2C%22fapi_response_mode%22%3A%22plain_response%22%7D'
  if [[ -n "${BATCH_VARIANT:-}" ]]; then
    printf '%s' "${BATCH_VARIANT}"
  elif [[ "$m" == fapi2-security-profile-id2-* || "$m" == fapi2-message-signing-id1-* ]]; then
    printf '%s' "${fapi2_baseline_variant}"
  elif [[ "$m" == "oidcc-server-client-secret-post" ]]; then
    printf '%s' "${client_secret_post_variant}"
  else
    printf '%s' "${default_variant}"
  fi
}

# _run_one_module <plan-id> <module> drives one OFCS module to a terminal
# state and writes the outcome to the output globals MODULE_STATUS,
# MODULE_RESULT, MODULE_RUNNER_ID, MODULE_ELAPSED_MS. Returns 0 on a
# successful end-to-end run regardless of pass/fail; returns 1 only when
# OFCS rejected the module-create call (the runner ID never came back).
# The function reuses cmd_drive's per-module flags (OFCS_DRIVE_REJECT /
# OFCS_DRIVE_DOUBLE_VISIT) by inspecting the module name.
_run_one_module() {
  local plan="$1" m="$2"
  MODULE_STATUS=""; MODULE_RESULT=""; MODULE_RUNNER_ID=""; MODULE_ELAPSED_MS="0"
  local v jar resp id info status result start_ms end_ms
  jar="$(mktemp /tmp/ofcs-batch-cookies.XXXXXX)"
  OFCS_DRIVE_COOKIES="$jar"
  export OFCS_DRIVE_COOKIES
  case "$m" in
    *user-rejects-authentication*) OFCS_DRIVE_REJECT=1 ;;
    *)                             OFCS_DRIVE_REJECT=0 ;;
  esac
  export OFCS_DRIVE_REJECT
  case "$m" in
    *reused-request-uri-prior-to-auth-completion*) OFCS_DRIVE_DOUBLE_VISIT=1 ;;
    *)                                             OFCS_DRIVE_DOUBLE_VISIT=0 ;;
  esac
  export OFCS_DRIVE_DOUBLE_VISIT
  v="$(_select_variant "$m")"
  start_ms="$(python3 -c 'import time; print(int(time.time()*1000))')"
  resp="$(curl -sk -X POST "${OFCS_API}/api/runner?test=${m}&plan=${plan}&variant=${v}" \
    -H 'Content-Type: application/json')"
  id="$(printf '%s' "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))' 2>/dev/null || true)"
  if [[ -z "$id" ]]; then
    rm -f "$jar"
    unset OFCS_DRIVE_COOKIES OFCS_DRIVE_REJECT OFCS_DRIVE_DOUBLE_VISIT
    MODULE_STATUS="ERROR"
    MODULE_RESULT="${resp:0:200}"
    return 1
  fi
  MODULE_RUNNER_ID="$id"
  sleep 1
  drive_all_urls "$id" 40
  info=""
  local stable=0
  for _ in $(seq 1 30); do
    info="$(curl -sk "${OFCS_API}/api/info/$id")"
    status="$(printf '%s' "$info" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))' 2>/dev/null || true)"
    [[ "$status" == "FINISHED" || "$status" == "INTERRUPTED" ]] && break
    if [[ "$status" == "WAITING" ]]; then
      stable=$((stable+1))
      if (( stable >= 5 )); then break; fi
    else
      stable=0
    fi
    sleep 1
  done
  result="$(printf '%s' "$info" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("result","") or "")' 2>/dev/null || true)"
  end_ms="$(python3 -c 'import time; print(int(time.time()*1000))')"
  MODULE_STATUS="$status"
  MODULE_RESULT="$result"
  MODULE_ELAPSED_MS="$((end_ms - start_ms))"
  rm -f "$jar"
  unset OFCS_DRIVE_COOKIES OFCS_DRIVE_REJECT OFCS_DRIVE_DOUBLE_VISIT
  return 0
}

cmd_batch() {
  local plan="${1:-}"
  if [[ -z "$plan" || $# -lt 2 ]]; then
    echo "[batch] usage: $0 batch <plan-id> <module> [module...]" >&2
    exit 1
  fi
  shift
  local pass=0 fail=0 skip=0 err=0 m
  for m in "$@"; do
    echo
    echo "==== $m ===="
    if ! _run_one_module "$plan" "$m"; then
      echo "[batch] could not start ${m}: ${MODULE_RESULT}"
      err=$((err+1))
      continue
    fi
    echo "id=${MODULE_RUNNER_ID}"
    echo "result=${MODULE_STATUS}/${MODULE_RESULT}"
    case "${MODULE_STATUS}/${MODULE_RESULT}" in
      */PASSED)            pass=$((pass+1));;
      */SKIPPED)           skip=$((skip+1));;
      */REVIEW|WAITING/)   skip=$((skip+1));;
      */WARNING)           skip=$((skip+1));;
      *)                   fail=$((fail+1));;
    esac
  done
  echo
  echo "==== summary: pass=${pass} skip=${skip} fail=${fail} err=${err} ===="
}

# cmd_baseline runs every module in every seeded plan and writes a
# deterministic JSON snapshot. The plan-id mapping comes from
# conformance/.plan-ids.json (written by cmd_seed_plans). The module
# list per plan is queried from OFCS at runtime so catalog drift
# between OFCS releases is captured automatically. Output lands in
# conformance/baselines/<UTC-date>-<label>.json with sorted keys so a
# git diff between two snapshots is meaningful.
cmd_baseline() {
  local label="${1:-snapshot}"
  local plan_ids_file="${CONF}/.plan-ids.json"
  if [[ ! -f "${plan_ids_file}" ]]; then
    echo "[baseline] ${plan_ids_file} not found — run \`scripts/conformance.sh seed-plans\` first" >&2
    exit 1
  fi
  local out_dir="${CONF}/baselines"
  mkdir -p "${out_dir}"
  local stamp out_file
  stamp="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
  out_file="${out_dir}/${stamp}-${label}.json"
  local sha branch
  sha="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  branch="$(git -C "${ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  local tmp
  tmp="$(mktemp /tmp/ofcs-baseline.XXXXXX.json)"
  BASELINE_LABEL="${label}" BASELINE_STAMP="${stamp}" BASELINE_SHA="${sha}" \
  BASELINE_BRANCH="${branch}" BASELINE_OUT="${tmp}" \
    python3 - <<'PY'
import json, os, pathlib
p = pathlib.Path(os.environ["BASELINE_OUT"])
p.write_text(json.dumps({
    "schema":     "go-oidc-provider/baseline/v1",
    "label":      os.environ["BASELINE_LABEL"],
    "captured_at": os.environ["BASELINE_STAMP"],
    "git": {
        "sha":    os.environ["BASELINE_SHA"],
        "branch": os.environ["BASELINE_BRANCH"],
    },
    "plans": {},
}, indent=2, sort_keys=True) + "\n")
PY
  local plan_name plan_id modules m
  while IFS= read -r plan_name; do
    if [[ -n "${BASELINE_PLAN_FILTER:-}" ]] && ! [[ "${plan_name}" =~ ${BASELINE_PLAN_FILTER} ]]; then
      continue
    fi
    plan_id="$(PLAN_IDS_FILE="${plan_ids_file}" PLAN_NAME="${plan_name}" \
      python3 -c 'import json,os,pathlib; print(json.loads(pathlib.Path(os.environ["PLAN_IDS_FILE"]).read_text())[os.environ["PLAN_NAME"]]["id"])')"
    echo
    echo "==== plan ${plan_name} (id=${plan_id}) ===="
    local plan_info
    plan_info="$(curl -sk "${OFCS_API}/api/plan/${plan_id}")"
    modules="$(printf '%s' "${plan_info}" | python3 -c '
import json, os, re, sys
data = json.load(sys.stdin)
mods = []
for entry in data.get("modules", []):
    name = entry.get("testModule") or entry.get("name") or ""
    if not name:
        continue
    if not re.search(os.environ.get("BASELINE_FILTER", ""), name):
        continue
    mods.append(name)
print("\n".join(mods))
')"
    [[ -z "${modules}" ]] && {
      echo "[baseline] no modules returned for plan ${plan_name}; skipping"
      continue
    }
    while IFS= read -r m; do
      [[ -z "$m" ]] && continue
      echo "---- ${m} ----"
      _run_one_module "${plan_id}" "${m}" || true
      echo "result=${MODULE_STATUS}/${MODULE_RESULT} (${MODULE_ELAPSED_MS}ms)"
      BASELINE_OUT="${tmp}" PLAN_NAME="${plan_name}" PLAN_ID="${plan_id}" \
      MODULE_NAME="${m}" MODULE_STATUS="${MODULE_STATUS}" MODULE_RESULT="${MODULE_RESULT}" \
      MODULE_RUNNER_ID="${MODULE_RUNNER_ID}" MODULE_ELAPSED_MS="${MODULE_ELAPSED_MS}" \
        python3 - <<'PY'
import json, os, pathlib
p = pathlib.Path(os.environ["BASELINE_OUT"])
data = json.loads(p.read_text())
plan = data["plans"].setdefault(os.environ["PLAN_NAME"], {
    "plan_id": os.environ["PLAN_ID"],
    "modules": {},
})
plan["modules"][os.environ["MODULE_NAME"]] = {
    "status":     os.environ.get("MODULE_STATUS", ""),
    "result":     os.environ.get("MODULE_RESULT", ""),
    "runner_id":  os.environ.get("MODULE_RUNNER_ID", ""),
    "elapsed_ms": int(os.environ.get("MODULE_ELAPSED_MS") or 0),
}
p.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
PY
    done <<< "${modules}"
  done < <(python3 -c 'import json,pathlib,sys; print("\n".join(sorted(json.loads(pathlib.Path(sys.argv[1]).read_text()).keys())))' "${plan_ids_file}")
  mv "${tmp}" "${out_file}"
  echo
  echo "[baseline] snapshot written to ${out_file}"
  BASELINE_OUT="${out_file}" python3 - <<'PY'
import json, os, pathlib
p = pathlib.Path(os.environ["BASELINE_OUT"])
data = json.loads(p.read_text())
totals = {"PASSED": 0, "OTHER": 0, "FAILED": 0}
for plan in data["plans"].values():
    for mod in plan["modules"].values():
        r = mod.get("result") or ""
        if r == "PASSED":
            totals["PASSED"] += 1
        elif r in ("FAILED", "WARNING") and mod.get("status") == "FINISHED":
            totals["FAILED"] += 1
        else:
            totals["OTHER"] += 1
print(f"[baseline] totals: pass={totals['PASSED']} fail={totals['FAILED']} other={totals['OTHER']}")
PY
}

# cmd_baseline_diff compares two baseline JSON snapshots and prints
# regressions (modules that lost PASSED) and fixes (modules that
# gained PASSED). Pure JSON comparison — does NOT touch OFCS, so it
# can run in any environment that has python3.
cmd_baseline_diff() {
  local old_file="${1:-}" new_file="${2:-}"
  if [[ -z "${old_file}" || -z "${new_file}" ]]; then
    echo "[baseline-diff] usage: $0 baseline-diff <old.json> <new.json>" >&2
    exit 1
  fi
  if [[ ! -f "${old_file}" || ! -f "${new_file}" ]]; then
    echo "[baseline-diff] file not found (old=${old_file} new=${new_file})" >&2
    exit 1
  fi
  OLD_FILE="${old_file}" NEW_FILE="${new_file}" python3 - <<'PY'
import json, os, pathlib, sys
old = json.loads(pathlib.Path(os.environ["OLD_FILE"]).read_text())
new = json.loads(pathlib.Path(os.environ["NEW_FILE"]).read_text())

def index(snap):
    out = {}
    for plan, body in snap.get("plans", {}).items():
        for m, info in body.get("modules", {}).items():
            out[(plan, m)] = info.get("result") or ""
    return out

old_idx = index(old)
new_idx = index(new)
keys = sorted(set(old_idx) | set(new_idx))
regressions = []
fixes = []
new_only_passes = []
dropped_passes = []
churn = []
for k in keys:
    o = old_idx.get(k)
    n = new_idx.get(k)
    if o == n:
        continue
    if o == "PASSED" and n != "PASSED":
        regressions.append((k, o, n))
    elif o != "PASSED" and n == "PASSED":
        fixes.append((k, o, n))
    elif o is None:
        new_only_passes.append((k, n))
    elif n is None:
        dropped_passes.append((k, o))
    else:
        churn.append((k, o, n))

def fmt(k, *vals):
    plan, m = k
    return f"  [{plan}] {m}: " + " -> ".join(v or "(absent)" for v in vals)

print(f"old: {os.environ['OLD_FILE']}  ({old.get('captured_at','?')})")
print(f"new: {os.environ['NEW_FILE']}  ({new.get('captured_at','?')})")
print()
print(f"regressions: {len(regressions)}")
for k, o, n in regressions:
    print(fmt(k, o, n))
print(f"fixes: {len(fixes)}")
for k, o, n in fixes:
    print(fmt(k, o, n))
if churn:
    print(f"non-pass churn: {len(churn)}")
    for k, o, n in churn:
        print(fmt(k, o, n))
if new_only_passes or dropped_passes:
    print(f"catalog drift: added={len(new_only_passes)} removed={len(dropped_passes)}")
sys.exit(1 if regressions else 0)
PY
}

case "${1:-help}" in
  certs)        cmd_certs ;;
  seed-plans)   cmd_seed_plans ;;
  ofcs-up)      cmd_ofcs_up ;;
  ofcs-down)    cmd_ofcs_down ;;
  ofcs-status)  cmd_ofcs_status ;;
  up)           cmd_up ;;
  down)         cmd_down ;;
  op-up)        cmd_op_up ;;
  op-down)      cmd_op_down ;;
  op-status)    cmd_op_status ;;
  drive)        shift; cmd_drive "$@" ;;
  batch)        shift; cmd_batch "$@" ;;
  baseline)     shift; cmd_baseline "$@" ;;
  baseline-diff) shift; cmd_baseline_diff "$@" ;;
  help|-h|--help) usage ;;
  *)
    echo "unknown sub-command: $1" >&2
    usage >&2
    exit 1
    ;;
esac
