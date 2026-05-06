package clientauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
)

func newPostRequest(tb testing.TB, form url.Values, basicID, basicSecret string) *http.Request {
	tb.Helper()
	body := strings.NewReader(form.Encode())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://op.test/oidc/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" || basicSecret != "" {
		req.SetBasicAuth(basicID, basicSecret)
	}
	return req
}

func TestParse_BasicAuth(t *testing.T) {
	t.Parallel()

	req := newPostRequest(t, url.Values{}, "client-1", "secret-1")
	creds, err := clientauth.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if creds.Method != clientauth.MethodSecretBasic {
		t.Errorf("Method=%v want %v", creds.Method, clientauth.MethodSecretBasic)
	}
	if creds.ClientID != "client-1" || creds.SecretBasic != "secret-1" {
		t.Errorf("creds=%+v", creds)
	}
}

func TestParse_FormPost(t *testing.T) {
	t.Parallel()

	form := url.Values{}
	form.Set("client_id", "client-1")
	form.Set("client_secret", "secret-1")
	req := newPostRequest(t, form, "", "")
	creds, err := clientauth.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if creds.Method != clientauth.MethodSecretPost {
		t.Errorf("Method=%v want %v", creds.Method, clientauth.MethodSecretPost)
	}
}

func TestParse_AssertionJWT(t *testing.T) {
	t.Parallel()

	form := url.Values{}
	form.Set("client_id", "client-1")
	form.Set("client_assertion_type", clientauth.AssertionType)
	form.Set("client_assertion", "eyJhbGciOiJFUzI1NiJ9.payload.sig")
	req := newPostRequest(t, form, "", "")
	creds, err := clientauth.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if creds.Method != clientauth.MethodPrivateKeyJWT {
		t.Errorf("Method=%v", creds.Method)
	}
	if creds.AssertionJWT == "" {
		t.Error("AssertionJWT empty")
	}
}

func TestParse_NoneMethodWithBodyClientID(t *testing.T) {
	t.Parallel()

	form := url.Values{}
	form.Set("client_id", "client-public")
	req := newPostRequest(t, form, "", "")
	creds, err := clientauth.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if creds.Method != clientauth.MethodNone {
		t.Errorf("Method=%v want %v", creds.Method, clientauth.MethodNone)
	}
	if creds.ClientID != "client-public" {
		t.Errorf("ClientID=%q", creds.ClientID)
	}
}

func TestParse_NoCredentials(t *testing.T) {
	t.Parallel()

	req := newPostRequest(t, url.Values{}, "", "")
	_, err := clientauth.Parse(req)
	if !errors.Is(err, clientauth.ErrNoCredentials) {
		t.Errorf("err=%v want ErrNoCredentials", err)
	}
}

func TestParse_AmbiguousBasicAndForm(t *testing.T) {
	t.Parallel()

	form := url.Values{}
	form.Set("client_secret", "secret-2")
	req := newPostRequest(t, form, "client-1", "secret-1")
	_, err := clientauth.Parse(req)
	if !errors.Is(err, clientauth.ErrAmbiguousCredentials) {
		t.Errorf("err=%v want ErrAmbiguousCredentials", err)
	}
}

func TestParse_AmbiguousBasicAndAssertion(t *testing.T) {
	t.Parallel()

	form := url.Values{}
	form.Set("client_assertion_type", clientauth.AssertionType)
	form.Set("client_assertion", "abc")
	req := newPostRequest(t, form, "client-1", "secret-1")
	_, err := clientauth.Parse(req)
	if !errors.Is(err, clientauth.ErrAmbiguousCredentials) {
		t.Errorf("err=%v want ErrAmbiguousCredentials", err)
	}
}

func TestParse_UnsupportedAssertionType(t *testing.T) {
	t.Parallel()

	form := url.Values{}
	form.Set("client_id", "client-1")
	form.Set("client_assertion_type", "urn:my:bogus:type")
	form.Set("client_assertion", "abc")
	req := newPostRequest(t, form, "", "")
	_, err := clientauth.Parse(req)
	if !errors.Is(err, clientauth.ErrUnsupportedMethod) {
		t.Errorf("err=%v want ErrUnsupportedMethod", err)
	}
}

func TestParse_BasicAndBodyClientIDMismatch(t *testing.T) {
	t.Parallel()

	form := url.Values{}
	form.Set("client_id", "client-2")
	req := newPostRequest(t, form, "client-1", "secret-1")
	_, err := clientauth.Parse(req)
	if !errors.Is(err, clientauth.ErrClientMismatch) {
		t.Errorf("err=%v want ErrClientMismatch", err)
	}
}

// TestParse_AssertionWithoutClientID_OversizedAssertionRejected pins
// H-A5: when client_id is omitted from the form and the parser falls
// back to the unverified assertion lookup, an oversized assertion
// (typical signed JWTs are 1-4 KB; 32 KiB is far past the 8 KiB
// hard cap) MUST NOT be parsed for its unverified body. The cap
// fires before any base64 decode / json.Unmarshal so a malicious
// client cannot force the parser to allocate megabytes of buffer
// before the assertion verifier ever runs.
//
// The visible signal is that the fallback lookup leaves ClientID
// empty (the parser does not surface ErrAssertionMalformed up the
// stack — the assertion verifier rejects the request later with
// invalid_client). The contract this test pins is that the cap path
// MUST NOT panic / OOM and MUST NOT silently extract a client_id
// from the malformed payload.
func TestParse_AssertionWithoutClientID_OversizedAssertionRejected(t *testing.T) {
	t.Parallel()

	// 32 KiB body -> a base64-encoded JWT comfortably above the
	// 8 KiB hard cap. The shape (header.body.signature) is valid
	// per the JWT compact form so the early-exit is purely the
	// length check.
	bigPayload := strings.Repeat("a", 32*1024)
	form := url.Values{}
	form.Set("client_assertion_type", clientauth.AssertionType)
	form.Set("client_assertion", "eyJhbGciOiJFUzI1NiJ9."+bigPayload+".sig")
	req := newPostRequest(t, form, "", "")
	creds, err := clientauth.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if creds.ClientID != "" {
		t.Errorf("ClientID=%q want empty (oversized assertion must not yield a derived id)", creds.ClientID)
	}
}

// TestParse_DuplicateCredentialParameter pins the rule that the
// shared client-authentication parser MUST refuse a request that
// repeats a credential-bearing single-valued field (RFC 6749 §3.2).
// The defence is layered with the per-endpoint duplicate gates the
// token / PAR / introspection / revocation handlers also install:
// a future endpoint that wires [Parse] without its own gate still
// gets the credential ambiguity closed here, and the parser
// surfaces the canonical [ErrAmbiguousCredentials] sentinel so the
// wire response reads the same as the existing Basic+body /
// Basic+assertion ambiguity rows.
func TestParse_DuplicateCredentialParameter(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		param string
		valA  string
		valB  string
	}{
		{"client_id", "client_id", "client-1", "client-2"},
		{"client_secret", "client_secret", "good", "bad"},
		{"client_assertion_type", "client_assertion_type", clientauth.AssertionType, "urn:bogus"},
		{"client_assertion", "client_assertion", "header.body.sig", "other.body.sig"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			form := url.Values{}
			form.Add(tc.param, tc.valA)
			form.Add(tc.param, tc.valB)
			req := newPostRequest(t, form, "", "")
			_, err := clientauth.Parse(req)
			if !errors.Is(err, clientauth.ErrAmbiguousCredentials) {
				t.Fatalf("dup %s err=%v want ErrAmbiguousCredentials", tc.param, err)
			}
		})
	}
}

// TestParse_DuplicateByteEqualParameterStillRejected pins the
// posture: even when the repeated values are byte-equal, the parser
// MUST reject. The wire ambiguity exists regardless of value
// agreement (proxy / WAF / audit tooling that disagrees with the OP
// on duplicate handling is the threat we close), and the audit
// observer cannot reason about what the parser "really meant" if it
// silently accepts collisions.
func TestParse_DuplicateByteEqualParameterStillRejected(t *testing.T) {
	t.Parallel()

	form := url.Values{}
	form.Add("client_id", "client-1")
	form.Add("client_id", "client-1")
	req := newPostRequest(t, form, "", "")
	_, err := clientauth.Parse(req)
	if !errors.Is(err, clientauth.ErrAmbiguousCredentials) {
		t.Fatalf("byte-equal dup err=%v want ErrAmbiguousCredentials", err)
	}
}

// TestParse_AssertionWithoutClientID_NormalSizedAssertionParsed pins
// the legitimate companion behaviour: an assertion within the cap
// whose unverified body carries a recoverable "iss" claim still
// derives the client id so FAPI 2.0 / OAuth 2.1 deployments that
// drop the redundant client_id parameter continue to work.
func TestParse_AssertionWithoutClientID_NormalSizedAssertionParsed(t *testing.T) {
	t.Parallel()

	// Construct a tiny assertion whose body decodes to {"iss":"client-1"}.
	// "eyJpc3MiOiJjbGllbnQtMSJ9" is base64url-no-pad of {"iss":"client-1"}.
	form := url.Values{}
	form.Set("client_assertion_type", clientauth.AssertionType)
	form.Set("client_assertion", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJjbGllbnQtMSJ9.sig")
	req := newPostRequest(t, form, "", "")
	creds, err := clientauth.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if creds.ClientID != "client-1" {
		t.Errorf("ClientID=%q want %q (assertion-derived id was lost)", creds.ClientID, "client-1")
	}
}
