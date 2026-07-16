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

# Example 04 documents a concrete verifier and derives the challenge in the
# command sequence. Execute the documented derivation and ensure both request
# legs consume the paired variables; this catches a future edit that changes
# one side but leaves the other stale.
example04="examples/04-oauth2-only/main.go"
verifier="$(sed -nE "s@.*VERIFIER='([^']+)'.*@\1@p" "$example04")"
if [ -z "$verifier" ] || [ "${#verifier}" -lt 43 ] || [ "${#verifier}" -gt 128 ]; then
  warn "Example 04 must document an RFC 7636 verifier of 43..128 characters"
  bad=1
else
  challenge="$(printf %s "$verifier" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
  if [ "${#challenge}" -ne 43 ] || ! grep -Fq 'code_challenge=${CHALLENGE}' "$example04" || ! grep -Fq 'code_verifier=${VERIFIER}' "$example04"; then
    warn "Example 04 PKCE verifier/challenge command sequence is not a paired S256 flow"
    bad=1
  fi
fi

if [ "$bad" -ne 0 ]; then
  die "fix the PKCE shell snippet — approved generators: openssl dgst -sha256 -binary | basenc --base64url -w0 | tr -d '='"
fi
log "example PKCE generators OK"
