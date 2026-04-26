package authn_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
)

// FuzzParse exercises [authn.Parse] with arbitrary Authorization header,
// Content-Type, and body triples synthesised into a token-endpoint request.
// The harness checks four structural invariants:
//
//  1. Parse never panics, regardless of input.
//  2. Every error returned MUST wrap one of the documented Parse sentinels
//     (ErrNoCredentials, ErrAmbiguousCredentials, ErrUnsupportedMethod,
//     ErrClientMismatch, ErrAssertionMalformed). ErrCredentialsInvalid and
//     ErrAssertionReplayed belong to Verify and must not surface here.
//  3. On error the returned *Credentials MUST be nil.
//  4. On success the Method is one of the four enumerated values and the
//     populated-field set is consistent with the chosen Method, per the
//     RFC 6749 §2.3.1 / RFC 7521 §4.2 channel separation rules. Parse
//     itself does not require ClientID to be non-empty for the secret /
//     assertion methods (a Basic header with an empty username, or a
//     body with client_assertion but no client_id, is structurally
//     accepted here and rejected later by Verify); it only collapses
//     the MethodNone-with-empty-id case to ErrNoCredentials.
//
// Seed corpus rationale (each seed targets a distinct branch the parser
// must keep stable under fuzzing):
//
//   - All-empty: the no-auth path that yields ErrNoCredentials.
//   - Basic("client:secret") with an empty form body: the canonical
//     RFC 6749 §2.3.1 client_secret_basic shape.
//   - Form-only client_secret: the client_secret_post shape.
//   - Form-only client_assertion + correct assertion_type: the
//     private_key_jwt shape (RFC 7523 §2.2).
//   - Basic + body client_secret: the ambiguous combination that must
//     trip ErrAmbiguousCredentials.
//   - Form with a bogus assertion_type: must trip ErrUnsupportedMethod.
//   - Basic("alice:s") with body client_id=bob: must trip
//     ErrClientMismatch (RFC 6749 §2.3.1, single-id rule).
//   - Garbage Authorization header that is not "Basic <b64>": Go's
//     [http.Request.BasicAuth] returns hasBasic=false, so the request
//     must collapse to MethodNone (or ErrNoCredentials), never to an
//     ambiguous-credentials error.
//   - Body that violates application/x-www-form-urlencoded ("%%%"): must
//     hit the ParseForm error wrapped as ErrAssertionMalformed.
//   - Empty Content-Type with a body present: ParseForm should not
//     consult the body, so this is a MethodNone / ErrNoCredentials path.
func FuzzParse(f *testing.F) {
	basicClientSecret := base64.StdEncoding.EncodeToString([]byte("client:secret"))
	basicAliceSecret := base64.StdEncoding.EncodeToString([]byte("alice:s"))

	// All-empty: no Authorization, no body, no form Content-Type.
	f.Add("", "", "")
	// client_secret_basic: Basic auth + form Content-Type, empty body.
	f.Add(basicClientSecret, "application/x-www-form-urlencoded", "")
	// client_secret_post: form-encoded client_id + client_secret.
	f.Add("", "application/x-www-form-urlencoded", "client_id=c&client_secret=s")
	// private_key_jwt: form-encoded client_assertion with the IANA-registered type.
	f.Add("",
		"application/x-www-form-urlencoded",
		"client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=eyJhbGciOiJFUzI1NiJ9.e30.sig")
	// Ambiguous: Basic auth alongside a body client_secret.
	f.Add(basicClientSecret, "application/x-www-form-urlencoded", "client_secret=s2")
	// Unsupported assertion_type alongside a client_assertion.
	f.Add("", "application/x-www-form-urlencoded", "client_assertion_type=urn%3Abogus&client_assertion=eyJhbGciOiJFUzI1NiJ9.e30.sig")
	// Mismatched ids: Basic("alice:s") + body client_id=bob.
	f.Add(basicAliceSecret, "application/x-www-form-urlencoded", "client_id=bob")
	// Garbage Authorization header value: not "Basic <b64>" — but we feed
	// it as-is via the basicAuth fuzz field, prefixed with "Basic " by the
	// harness, so the inner payload is what we vary here. This particular
	// seed pushes a non-base64 payload at the BasicAuth decoder.
	f.Add("not::base64::at::all", "application/x-www-form-urlencoded", "")
	// Malformed urlencoded body: "%%%" cannot be percent-decoded.
	f.Add("", "application/x-www-form-urlencoded", "%%%")
	// Body present but Content-Type empty: ParseForm leaves PostForm empty.
	f.Add("", "", "client_id=c&client_secret=s")

	f.Fuzz(func(t *testing.T, basicAuth, contentType, body string) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://op.test/oidc/token", strings.NewReader(body))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if basicAuth != "" {
			req.Header.Set("Authorization", "Basic "+basicAuth)
		}

		creds, err := authn.Parse(req)
		if err != nil {
			// Invariant 2: the error MUST wrap a Parse-tier sentinel.
			switch {
			case errors.Is(err, authn.ErrNoCredentials),
				errors.Is(err, authn.ErrAmbiguousCredentials),
				errors.Is(err, authn.ErrUnsupportedMethod),
				errors.Is(err, authn.ErrClientMismatch),
				errors.Is(err, authn.ErrAssertionMalformed):
				// allowed
			default:
				t.Fatalf("Parse returned unrecognised error class: %v", err)
			}
			// Invariant 3: error path returns nil credentials.
			if creds != nil {
				t.Fatalf("Parse returned non-nil credentials alongside error %v: %+v", err, creds)
			}
			return
		}

		// Success path. Invariant 4: method enum + field consistency.
		if creds == nil {
			t.Fatalf("Parse returned nil credentials with nil error")
		}
		switch creds.Method {
		case authn.MethodNone:
			// MethodNone with empty ClientID would have been rerouted
			// through ErrNoCredentials, so ClientID must be non-empty
			// here. All secret/assertion fields must be empty.
			if creds.ClientID == "" {
				t.Fatalf("MethodNone with empty ClientID escaped Parse: %+v", creds)
			}
			if creds.SecretBasic != "" || creds.SecretPost != "" || creds.AssertionJWT != "" {
				t.Fatalf("MethodNone leaked secret/assertion material: %+v", creds)
			}
		case authn.MethodSecretBasic:
			// SecretBasic and ClientID may both be empty if the Basic
			// header carried empty user / pass; that is Verify's
			// problem to reject, not Parse's.
			if creds.SecretPost != "" || creds.AssertionJWT != "" {
				t.Fatalf("MethodSecretBasic leaked into other channels: %+v", creds)
			}
		case authn.MethodSecretPost:
			if creds.SecretPost == "" {
				t.Fatalf("MethodSecretPost without SecretPost: %+v", creds)
			}
			if creds.SecretBasic != "" || creds.AssertionJWT != "" {
				t.Fatalf("MethodSecretPost leaked into other channels: %+v", creds)
			}
		case authn.MethodPrivateKeyJWT:
			if creds.AssertionJWT == "" {
				t.Fatalf("MethodPrivateKeyJWT without AssertionJWT: %+v", creds)
			}
			if creds.SecretBasic != "" || creds.SecretPost != "" {
				t.Fatalf("MethodPrivateKeyJWT leaked into secret channels: %+v", creds)
			}
		default:
			t.Fatalf("Parse returned unknown Method %q", creds.Method)
		}
	})
}
