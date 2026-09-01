SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := verify

.PHONY: tools format lint vet test test-race cover fuzz fuzz-long govulncheck licenses verify clean \
        verify-examples verify-examples-api verify-examples-browser verify-examples-harness \
        stability stability-check stability-backfill reach \
        scenario-validate scenario-validate-lenient scenario-coverage scenario-coverage-strict \
        scenario-coverage-bindings \
        scenario-coverage-yaml-only scenario-stats scenario-advisories scenario-advisories-strict \
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

# Compile / vet the examples plus the static documentation checks. Fast
# enough to be part of `make verify`; it never calls op.New.
verify-examples:
	@scripts/verify_examples.sh

# Runtime verification of the examples: boot each one as a real process and
# assert it does what its header doc promises. These are the only gates that
# construct an example's configuration, so a library change that invalidates
# one surfaces here and nowhere earlier. They are minutes of work apiece (and
# the browser half needs Chrome), so they are NOT wired into `make verify` —
# the release pre-flight runs them.
verify-examples-api:
	@scripts/verify_example_harness.sh api

# Set BROWSERVERIFY_REQUIRED=1 to make a missing Chrome — or a run that
# executed zero browser cases — a failure instead of a skip.
verify-examples-browser:
	@scripts/verify_example_harness.sh browser

verify-examples-harness:
	@scripts/verify_example_harness.sh all

# Manual smoke targets for examples that pair an OP with an
# in-process Relying Party. These targets are operator-driven —
# they boot a long-running process the developer drives from a
# browser, and they are NOT wired into `make verify`. See the
# example godoc for the click path.
#
# EXAMPLE_SMOKE is the single source of truth: the target names and
# the .PHONY list are both derived from it, so adding an entry cannot
# leave the two out of step. Every example is its own module resolved
# through a development `replace`, so the run is GOWORK=off like the
# per-module commands in scripts/ — the repository workspace covers
# only the published modules.
EXAMPLE_SMOKE := 01-minimal 03-fapi2 41-dynamic-registration 51-dpop-nonce 61-claims-request
EXAMPLE_TARGETS := $(foreach e,$(EXAMPLE_SMOKE),example-$(word 1,$(subst -, ,$(e))))

.PHONY: $(EXAMPLE_TARGETS)

# One explicit rule per entry rather than a single `example-%` pattern:
# make excludes .PHONY targets from implicit-rule search, so a pattern
# rule would never fire for the names above.
define example_smoke_rule
example-$(word 1,$(subst -, ,$(1))):
	cd examples/$(1) && GOWORK=off go run -tags example .
endef
$(foreach e,$(EXAMPLE_SMOKE),$(eval $(call example_smoke_rule,$(e))))

# Spec Scenario Suite — catalog validation and coverage.
# api/experimental.txt records the public API exempt from the SemVer
# promise; api/stability.txt records, per symbol, the release its contract
# was frozen in. Both are generated from the godoc markers, so a marker
# added or removed shows up as a diff on a report rather than only in the
# source. The stable report is also a history check: it refuses a version
# that rewrites what an already-recorded row says.
stability:
	@scripts/stability.sh --write

stability-check:
	@scripts/stability.sh --check

# Regenerate while admitting a "Stable since" marker newly added to a symbol
# that shipped unmarked in that release. Marking one late is legitimate — the
# convention is sparse — but back-dating a symbol that did not exist is not,
# so this is a separate, deliberate target rather than a default.
stability-backfill:
	@scripts/stability.sh --write-backfill

# Declared-but-unreached gate: exported constants and Err-prefixed
# sentinels never named as a Go identifier anywhere in non-test library
# code, catalogued audit events whose godoc lets an operator read
# silence as evidence, seed message keys no screen renders, and
# DynamoDB indexes no read path queries. "Named" is a textual-reference
# test, not a control-flow one: a symbol that appears only in an
# enum's own String()/IsValid()-style plumbing counts as named, even
# when nothing ever branches on it. Whether a flag is actually
# consulted anywhere remains a manual review question this gate does
# not answer. Deliberate exceptions live in api/unreached.txt, one row
# each with the reason nothing reading the entry is correct; a row
# that stops applying fails too.
reach:
	@scripts/reach.sh

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

# The subset of the coverage gate that is a binding check rather than a
# progress report: a row with no test, a test with no row, or a test
# that runs under an out-of-scope row. `make verify` runs the --strict
# mode above, which is a superset of this one — this target is the
# tolerant local check for a tree mid-change, and passing it does not
# mean the pre-merge gate passes.
scenario-coverage-bindings:
	@scripts/scenario.sh coverage --check-bindings

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
# catalog, and every module must have PASSED, matched an exact per-module
# entry in the checked-in exclusion manifest, or fallen under one of that
# manifest's class-level accepted_outcomes rules (REVIEW / SKIPPED families
# only). A module with no verdict at all needs an entry in the manifest's
# separate unreachable_verdicts section, which requires evidence of what was
# tried; no ordinary exclusion can cover one.
conformance-release-verify:
	@scripts/conformance.sh release-verify \
		"$(BASELINE_REFERENCE)" "$(BASELINE_CANDIDATE)" \
		--exclusions "$(or $(CONFORMANCE_EXCLUSIONS),conformance/release-exclusions.json)"
