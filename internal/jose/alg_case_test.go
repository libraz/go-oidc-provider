package jose_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

// TestParseAlgorithm_CaseVariantsRejected pins case-sensitive matching
// for the "none" / HMAC family. Many legacy JWT libraries normalised
// the alg header before checking against a deny-list, leaving case-
// variant bypasses (NONE, nOnE, " none ") wide open.
//
// Tracks: CVE-2026-22817 / CVE-2026-27804 / CVE-2026-23552 (Hono JWT
// middleware family, 2026 cluster) — reproduced the original 2015 alg=none
// pattern with case-variant alg headers. Tracks back to the root attack
// class first publicised in 2015 around CVE-2015-9235 (jsonwebtoken) and
// CVE-2015-2951-equivalent reports for jose4j / pyjwt / php-jwt.
//
// The library defends structurally: ParseAlgorithm uses a small
// constant allow-list with byte-exact comparison, so any variant not
// matching {RS256,PS256,ES256,EdDSA} fails. We pin the contract in a
// table so a future "tolerant" patch breaks the build instead of the OP.
func TestParseAlgorithm_CaseVariantsRejected(t *testing.T) {
	t.Parallel()

	rejected := []string{
		"none",
		"NONE",
		"None",
		"nOnE",
		" none",
		"none ",
		"none\t",
		"\nnone",
		"NoNe",
		"hs256",
		"HS256 ",
		" HS256",
		"hS256",
		"rs256",   // case-folded would equal RS256 — must be rejected.
		"Rs256",   // ditto.
		"rS256",   // ditto.
		"es256",   // case-folded would equal ES256 — must be rejected.
		"eddsa",   // case-folded would equal EdDSA — must be rejected.
		"EDDSA",   // ditto.
		"ed25519", // not registered as a JWS alg name; only "EdDSA" is.
		"",
	}
	for _, raw := range rejected {
		t.Run("rejected="+strings.ReplaceAll(raw, " ", "_SP_"), func(t *testing.T) {
			t.Parallel()
			if _, ok := jose.ParseAlgorithm(raw); ok {
				t.Fatalf("ParseAlgorithm(%q) returned ok=true; case-variant must be rejected", raw)
			}
		})
	}
}

// TestParseSigned_CaseVariantNoneRejected drives the case-variant
// rejection through [jose.ParseSigned] — i.e. an actual compact-
// serialised JWS whose header reads "alg":"NONE" / "None" / "nOnE".
//
// Tracks the same CVE family as [TestParseAlgorithm_CaseVariantsRejected]
// but exercises the wire path: a real attacker submits raw bytes, not
// already-parsed alg strings. The seed is built by hand so we can
// inject the unusual casing into the JSON header.
func TestParseSigned_CaseVariantNoneRejected(t *testing.T) {
	t.Parallel()

	cases := []string{
		`{"alg":"none","typ":"JWT"}`,
		`{"alg":"NONE","typ":"JWT"}`,
		`{"alg":"None","typ":"JWT"}`,
		`{"alg":"nOnE","typ":"JWT"}`,
		`{"alg":"NoNe","typ":"JWT"}`,
		`{"alg":"HS256","typ":"JWT"}`,
		`{"alg":"hs256","typ":"JWT"}`,
		`{"alg":"Hs256","typ":"JWT"}`,
	}
	const payload = `{"sub":"alice"}`

	for _, hdr := range cases {
		t.Run(hdr, func(t *testing.T) {
			t.Parallel()
			tok := base64.RawURLEncoding.EncodeToString([]byte(hdr)) +
				"." + base64.RawURLEncoding.EncodeToString([]byte(payload)) +
				"."
			_, _, err := jose.ParseSigned(tok)
			if err == nil {
				t.Fatalf("ParseSigned accepted token with header %s", hdr)
			}
			// Either ErrAlgorithmNotAllowed (allow-list) or ErrMalformed
			// (go-jose v4 rejects at parse time) is acceptable. What
			// matters is that no nil-error path leaks.
			if !errors.Is(err, jose.ErrAlgorithmNotAllowed) && !errors.Is(err, jose.ErrMalformed) {
				t.Fatalf("ParseSigned err=%v want ErrAlgorithmNotAllowed or ErrMalformed", err)
			}
		})
	}
}
