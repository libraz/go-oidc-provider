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
