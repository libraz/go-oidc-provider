#!/usr/bin/env bash
# Assert every code_challenge generator documented in examples/
# produces base64url(SHA256(verifier)) per RFC 7636 §4.2. Concretely:
# reject shell snippets that pipe `shasum` (hex output) or `cut` /
# `awk` extraction patterns that imply hex parsing. The approved
# generator is `openssl dgst -sha256 -binary | basenc --base64url
# -w0 | tr -d '='` (or a Go reference snippet that calls
# encoding/base64 RawURLEncoding on the SHA-256 of the verifier).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

bad=0

# Pattern 1: shasum invoked anywhere near a code_challenge expression.
# shasum's default output is hex; PKCE wants base64url. Even if a
# downstream pipeline transforms the hex, the snippet is misleading
# enough that we reject it outright.
if grep -RnE 'code_challenge.*shasum|shasum.*code_challenge' examples/ >/tmp/pkce_shasum.txt 2>/dev/null && [ -s /tmp/pkce_shasum.txt ]; then
  warn "examples derive code_challenge with shasum (produces hex; PKCE requires base64url):"
  cat /tmp/pkce_shasum.txt >&2
  bad=1
fi

# Pattern 2: any single-line bash expression that pipes a hash
# command directly through `cut -d' ' -f1`, the canonical hex
# extraction shape. This catches code_challenge=$(echo ... | sha256sum
# | cut -d' ' -f1) and similar.
if grep -RnE "code_challenge=.*\| *cut " examples/ >/tmp/pkce_cut.txt 2>/dev/null && [ -s /tmp/pkce_cut.txt ]; then
  warn "examples extract code_challenge via cut (implies hex parsing):"
  cat /tmp/pkce_cut.txt >&2
  bad=1
fi

# Pattern 3: an obviously short verifier literal. RFC 7636 §4.1
# mandates 43..128 chars; anything under 43 chars in a quoted shell
# variable named VERIFIER fails on the wire.
if grep -RnE "VERIFIER=['\"][^'\"]{1,42}['\"]" examples/ >/tmp/pkce_short.txt 2>/dev/null && [ -s /tmp/pkce_short.txt ]; then
  warn "examples declare a short PKCE verifier (RFC 7636 §4.1 requires 43..128 chars):"
  cat /tmp/pkce_short.txt >&2
  bad=1
fi

rm -f /tmp/pkce_shasum.txt /tmp/pkce_cut.txt /tmp/pkce_short.txt

if [ "$bad" -ne 0 ]; then
  die "fix the PKCE shell snippet — approved generators: openssl dgst -sha256 -binary | basenc --base64url -w0 | tr -d '='"
fi
log "example PKCE generators OK"
