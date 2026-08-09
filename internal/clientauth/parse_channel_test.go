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

// bodylessAssertionQuery is the credential set a private_key_jwt client
// appends to a GET / DELETE URL: the assertion plus its type, and the
// (optional) client_id.
func bodylessAssertionQuery() url.Values {
	q := url.Values{}
	q.Set("client_id", "client-1")
	q.Set("client_assertion_type", clientauth.AssertionType)
	q.Set("client_assertion", "eyJhbGciOiJFUzI1NiJ9.payload.sig")
	return q
}

func newBodylessRequest(tb testing.TB, method string, query url.Values) *http.Request {
	tb.Helper()
	target := "https://op.test/oidc/grant_management/g-1"
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	return httptest.NewRequestWithContext(context.Background(), method, target, http.NoBody)
}

// TestParse_BodylessMethodsReadQueryAssertion pins the only channel a
// GET / DELETE has. Go's [http.Request.ParseForm] populates PostForm
// for POST / PUT / PATCH only, so a bodyless request that authenticates
// with private_key_jwt has nowhere but the query string to carry its
// assertion. Reading it there is what makes the grant management
// endpoint's query / revoke operations usable by clients whose profile
// mandates private_key_jwt.
func TestParse_BodylessMethodsReadQueryAssertion(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			req := newBodylessRequest(t, method, bodylessAssertionQuery())
			creds, err := clientauth.Parse(req)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if creds.Method != clientauth.MethodPrivateKeyJWT {
				t.Errorf("Method=%v want %v", creds.Method, clientauth.MethodPrivateKeyJWT)
			}
			if creds.ClientID != "client-1" {
				t.Errorf("ClientID=%q want client-1", creds.ClientID)
			}
			if creds.AssertionJWT == "" {
				t.Error("AssertionJWT empty")
			}
		})
	}
}

// TestParse_BodylessMethodRejectsQuerySecret pins the one credential
// the query channel refuses to carry. A shared secret in a URL lands in
// proxy logs, access logs, and browser history; a confidential client
// on a bodyless surface authenticates with HTTP Basic or
// private_key_jwt instead.
func TestParse_BodylessMethodRejectsQuerySecret(t *testing.T) {
	t.Parallel()

	query := url.Values{}
	query.Set("client_id", "client-1")
	query.Set("client_secret", "secret-1")
	req := newBodylessRequest(t, http.MethodGet, query)
	if _, err := clientauth.Parse(req); !errors.Is(err, clientauth.ErrCredentialsInvalid) {
		t.Errorf("err=%v want ErrCredentialsInvalid", err)
	}
}

// TestParse_BodylessMethodStillAcceptsBasic confirms the header channel
// is untouched: HTTP Basic works on a bodyless request exactly as it
// does on a POST.
func TestParse_BodylessMethodStillAcceptsBasic(t *testing.T) {
	t.Parallel()

	req := newBodylessRequest(t, http.MethodDelete, nil)
	req.SetBasicAuth("client-1", "secret-1")
	creds, err := clientauth.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if creds.Method != clientauth.MethodSecretBasic || creds.ClientID != "client-1" {
		t.Errorf("creds=%+v want secret_basic/client-1", creds)
	}
}

// TestParse_BodyCarryingMethodsIgnoreQueryCredentials is the security
// half of the split. Every POST-only surface (token, PAR,
// introspection, revocation) takes credentials from the form body
// alone; a client_assertion appended to the URL must stay invisible so
// no credential is ever accepted from a channel that leaks into logs
// (RFC 6750 §2.3, RFC 9700 §2.4). With nothing in the body the parser
// therefore reports "no credentials at all".
func TestParse_BodyCarryingMethodsIgnoreQueryCredentials(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			target := "https://op.test/oidc/token?" + bodylessAssertionQuery().Encode()
			req := httptest.NewRequestWithContext(
				context.Background(),
				method,
				target,
				strings.NewReader(""),
			)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if _, err := clientauth.Parse(req); !errors.Is(err, clientauth.ErrNoCredentials) {
				t.Errorf("err=%v want ErrNoCredentials", err)
			}
		})
	}
}

// TestParse_BodyCredentialsWinOverQueryOnPost pins that the query
// channel cannot even influence a POST that authenticates properly: the
// body's client_id is the one that surfaces, and a query-borne
// assertion for a different client is not mistaken for an ambiguous
// credential set — it simply is not read.
func TestParse_BodyCredentialsWinOverQueryOnPost(t *testing.T) {
	t.Parallel()

	form := url.Values{}
	form.Set("client_id", "client-body")
	form.Set("client_secret", "secret-body")
	target := "https://op.test/oidc/token?" + bodylessAssertionQuery().Encode()
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		target,
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	creds, err := clientauth.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if creds.Method != clientauth.MethodSecretPost {
		t.Errorf("Method=%v want %v", creds.Method, clientauth.MethodSecretPost)
	}
	if creds.ClientID != "client-body" {
		t.Errorf("ClientID=%q want client-body", creds.ClientID)
	}
	if creds.AssertionJWT != "" {
		t.Errorf("AssertionJWT=%q must stay empty: the query channel is closed on POST", creds.AssertionJWT)
	}
}
