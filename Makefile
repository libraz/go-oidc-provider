SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := verify

.PHONY: tools fmt lint vet test test-race cover fuzz fuzz-long govulncheck licenses verify clean \
        conformance-certs conformance-up conformance-down \
        conformance-ofcs-up conformance-ofcs-down conformance-ofcs-status \
        conformance-op-up conformance-op-down conformance-op-status \
        conformance-seed-plans conformance-baseline conformance-baseline-diff

tools:
	@scripts/install-tools.sh

fmt:
	@scripts/fmt.sh

lint:
	@scripts/lint.sh

vet:
	go vet ./...

test:
	@scripts/test.sh

test-race:
	@scripts/test.sh --race

cover:
	@scripts/test.sh --cover

fuzz:
	@scripts/fuzz.sh 30s

fuzz-long:
	@scripts/fuzz.sh 5m

govulncheck:
	@scripts/govulncheck.sh

licenses:
	@scripts/licenses.sh

verify:
	@scripts/verify.sh

clean:
	go clean -testcache
	rm -rf cover.out cover.html bin/ build/ dist/ testdata/fuzz

# Conformance harness (OpenID Foundation Conformance Suite). OFCS
# itself runs from conformance/docker-compose.yml at a pinned image
# tag, so `make conformance-up` is sufficient to bring the whole
# stack up from a clean clone — no separate OFCS checkout needed.
conformance-up:
	@scripts/conformance.sh up

conformance-down:
	@scripts/conformance.sh down

conformance-certs:
	@scripts/conformance.sh certs

conformance-seed-plans:
	@scripts/conformance.sh seed-plans

conformance-ofcs-up:
	@scripts/conformance.sh ofcs-up

conformance-ofcs-down:
	@scripts/conformance.sh ofcs-down

conformance-ofcs-status:
	@scripts/conformance.sh ofcs-status

conformance-op-up:
	@scripts/conformance.sh op-up

conformance-op-down:
	@scripts/conformance.sh op-down

conformance-op-status:
	@scripts/conformance.sh op-status

# Capture an OFCS baseline. LABEL is a short slug ("pre-loginflow",
# "release-v0.5", ...). Output lands in conformance/baselines/.
# Requires the OFCS stack and op-demo running (e.g. `make conformance-up`)
# plus a fresh `make conformance-seed-plans` so .plan-ids.json is current.
conformance-baseline:
	@scripts/conformance.sh baseline "$(LABEL)"

# Diff two baselines. Set BASELINE_OLD and BASELINE_NEW to file paths.
# Exits non-zero on regression so CI / pre-merge hooks can wire it up.
conformance-baseline-diff:
	@scripts/conformance.sh baseline-diff "$(BASELINE_OLD)" "$(BASELINE_NEW)"
