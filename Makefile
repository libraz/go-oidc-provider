SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := verify

.PHONY: tools fmt lint vet test test-race cover fuzz fuzz-long govulncheck licenses verify clean

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
