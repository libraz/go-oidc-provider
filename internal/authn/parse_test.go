package authn_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
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
	creds, err := authn.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if creds.Method != authn.MethodSecretBasic {
		t.Errorf("Method=%v want %v", creds.Method, authn.MethodSecretBasic)
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
	creds, err := authn.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if creds.Method != authn.MethodSecretPost {
		t.Errorf("Method=%v want %v", creds.Method, authn.MethodSecretPost)
	}
}

func TestParse_AssertionJWT(t *testing.T) {
	t.Parallel()

	form := url.Values{}
	form.Set("client_id", "client-1")
	form.Set("client_assertion_type", authn.AssertionType)
	form.Set("client_assertion", "eyJhbGciOiJFUzI1NiJ9.payload.sig")
	req := newPostRequest(t, form, "", "")
	creds, err := authn.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if creds.Method != authn.MethodPrivateKeyJWT {
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
	creds, err := authn.Parse(req)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if creds.Method != authn.MethodNone {
		t.Errorf("Method=%v want %v", creds.Method, authn.MethodNone)
	}
	if creds.ClientID != "client-public" {
		t.Errorf("ClientID=%q", creds.ClientID)
	}
}

func TestParse_NoCredentials(t *testing.T) {
	t.Parallel()

	req := newPostRequest(t, url.Values{}, "", "")
	_, err := authn.Parse(req)
	if !errors.Is(err, authn.ErrNoCredentials) {
		t.Errorf("err=%v want ErrNoCredentials", err)
	}
}

func TestParse_AmbiguousBasicAndForm(t *testing.T) {
	t.Parallel()

	form := url.Values{}
	form.Set("client_secret", "secret-2")
	req := newPostRequest(t, form, "client-1", "secret-1")
	_, err := authn.Parse(req)
	if !errors.Is(err, authn.ErrAmbiguousCredentials) {
		t.Errorf("err=%v want ErrAmbiguousCredentials", err)
	}
}

func TestParse_AmbiguousBasicAndAssertion(t *testing.T) {
	t.Parallel()

	form := url.Values{}
	form.Set("client_assertion_type", authn.AssertionType)
	form.Set("client_assertion", "abc")
	req := newPostRequest(t, form, "client-1", "secret-1")
	_, err := authn.Parse(req)
	if !errors.Is(err, authn.ErrAmbiguousCredentials) {
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
	_, err := authn.Parse(req)
	if !errors.Is(err, authn.ErrUnsupportedMethod) {
		t.Errorf("err=%v want ErrUnsupportedMethod", err)
	}
}

func TestParse_BasicAndBodyClientIDMismatch(t *testing.T) {
	t.Parallel()

	form := url.Values{}
	form.Set("client_id", "client-2")
	req := newPostRequest(t, form, "client-1", "secret-1")
	_, err := authn.Parse(req)
	if !errors.Is(err, authn.ErrClientMismatch) {
		t.Errorf("err=%v want ErrClientMismatch", err)
	}
}
