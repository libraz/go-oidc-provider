SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := verify

.PHONY: tools format lint vet test test-race cover fuzz fuzz-long govulncheck licenses verify verify-examples clean \
        scenario-validate scenario-validate-lenient scenario-coverage scenario-coverage-strict \
        scenario-coverage-yaml-only scenario-stats scenario-advisories scenario-advisories-strict \
        example-01 example-03 example-17 example-41 example-51 \
        conformance-certs conformance-up conformance-down \
        conformance-ofcs-up conformance-ofcs-down conformance-ofcs-status \
        conformance-op-up conformance-op-down conformance-op-status \
        conformance-seed-plans conformance-baseline conformance-baseline-diff \
        conformance-release-verify

tools:
	@scripts/install-tools.sh

format:
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

verify-examples:
	@scripts/verify_examples.sh

# Manual smoke targets for examples that pair an OP with an
# in-process Relying Party. These targets are operator-driven —
# they boot a long-running process the developer drives from a
# browser, and they are NOT wired into `make verify`. See the
# example godoc for the click path.
example-01:
	cd examples/01-minimal && go run -tags example .

example-03:
	cd examples/03-fapi2 && go run -tags example .

example-61:
	cd examples/61-claims-request && go run -tags example .

example-41:
	cd examples/41-dynamic-registration && go run -tags example .

example-51:
	cd examples/51-dpop-nonce && go run -tags example .

# Spec Scenario Suite — catalog validation and coverage.
# Catalog source of truth: test/scenarios/catalog/<feature>.yaml.
# See test/scenarios/catalog/README.md for the schema.
scenario-validate:
	@scripts/scenario.sh validate

scenario-validate-lenient:
	@scripts/scenario.sh validate --lenient

scenario-coverage:
	@scripts/scenario.sh coverage

scenario-coverage-strict:
	@scripts/scenario.sh coverage --strict

# Catalog-only coverage view — does not run `go test -list`, so it
# stays useful when the main module currently fails to build.
scenario-coverage-yaml-only:
	@scripts/scenario.sh coverage --yaml-only

# Severity x status dashboard for the catalog. Pass `feature=<slug>`
# to narrow to one file.
scenario-stats:
	@scripts/scenario.sh stats $(feature)

# CVE / GHSA advisory inventory ↔ `// Tracks: <id>` comment audit.
# Source of truth: test/scenarios/catalog/_advisories.yaml + the Go
# source itself. The strict variant fails the build on drift, orphan
# references, or stale `tracking` entries that have since been
# annotated.
scenario-advisories:
	@scripts/scenario.sh advisories

scenario-advisories-strict:
	@scripts/scenario.sh advisories --check

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

# Strict release gate. The candidate must have exactly the reference module
# catalog, with every result PASSED or exactly matched by the checked-in
# exclusion manifest.
conformance-release-verify:
	@scripts/conformance.sh release-verify \
		"$(BASELINE_REFERENCE)" "$(BASELINE_CANDIDATE)" \
		--exclusions "$(or $(CONFORMANCE_EXCLUSIONS),conformance/release-exclusions.json)"
