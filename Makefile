SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := verify

.PHONY: tools fmt lint vet test test-race cover fuzz fuzz-long govulncheck licenses verify clean \
        conformance-certs conformance-op-up conformance-op-down conformance-op-status

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

# Conformance harness (OpenID Foundation Conformance Suite). The OFCS
# itself is not started by these targets — see conformance/README.md
# for the (one-time) clone+build of openid/conformance-suite. These
# targets manage the cert and the cmd/op-demo side of the loop.
conformance-certs:
	@scripts/conformance.sh certs

conformance-op-up:
	@scripts/conformance.sh op-up

conformance-op-down:
	@scripts/conformance.sh op-down

conformance-op-status:
	@scripts/conformance.sh op-status
