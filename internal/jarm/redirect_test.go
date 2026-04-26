package jarm_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jarm"
)

func TestBuildRedirect_QueryJWT(t *testing.T) {
	t.Parallel()

	got, err := jarm.BuildRedirect(jarm.ResponseModeQueryJWT, "https://rp.example.com/cb", "compact-jwt")
	if err != nil {
		t.Fatalf("BuildRedirect: %v", err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("Parse(%q): %v", got, err)
	}
	if u.Query().Get("response") != "compact-jwt" {
		t.Errorf("response=%q", u.Query().Get("response"))
	}
	if u.Fragment != "" {
		t.Errorf("fragment=%q want empty", u.Fragment)
	}
}

func TestBuildRedirect_QueryJWT_PreservesExistingQuery(t *testing.T) {
	t.Parallel()

	got, err := jarm.BuildRedirect(jarm.ResponseModeQueryJWT,
		"https://rp.example.com/cb?source=ad", "j")
	if err != nil {
		t.Fatalf("BuildRedirect: %v", err)
	}
	u, _ := url.Parse(got)
	if u.Query().Get("source") != "ad" {
		t.Errorf("source dropped: %s", got)
	}
	if u.Query().Get("response") != "j" {
		t.Errorf("response missing: %s", got)
	}
}

func TestBuildRedirect_FragmentJWT(t *testing.T) {
	t.Parallel()

	got, err := jarm.BuildRedirect(jarm.ResponseModeFragmentJWT, "https://rp.example.com/cb", "compact-jwt")
	if err != nil {
		t.Fatalf("BuildRedirect: %v", err)
	}
	if !strings.Contains(got, "#response=compact-jwt") {
		t.Errorf("fragment missing in %q", got)
	}
	if strings.Contains(got, "?response=") {
		t.Errorf("query unexpectedly contains response: %q", got)
	}
}

func TestBuildRedirect_FragmentJWT_PreservesFormEncodedFragment(t *testing.T) {
	t.Parallel()

	got, err := jarm.BuildRedirect(jarm.ResponseModeFragmentJWT,
		"https://rp.example.com/cb#tracker=abc", "j")
	if err != nil {
		t.Fatalf("BuildRedirect: %v", err)
	}
	if !strings.Contains(got, "tracker=abc") {
		t.Errorf("existing fragment dropped: %q", got)
	}
	if !strings.Contains(got, "response=j") {
		t.Errorf("response missing: %q", got)
	}
}

func TestBuildRedirect_FormPostJWT_ReturnsSentinel(t *testing.T) {
	t.Parallel()

	_, err := jarm.BuildRedirect(jarm.ResponseModeFormPostJWT, "https://rp.example.com/cb", "j")
	if !errors.Is(err, jarm.ErrUseFormPost) {
		t.Errorf("err=%v want ErrUseFormPost", err)
	}
}

func TestBuildRedirect_BareJWT_RequiresResolution(t *testing.T) {
	t.Parallel()

	_, err := jarm.BuildRedirect(jarm.ResponseModeJWT, "https://rp.example.com/cb", "j")
	if !errors.Is(err, jarm.ErrUnsupportedResponseMode) {
		t.Errorf("err=%v want ErrUnsupportedResponseMode", err)
	}
}

func TestBuildRedirect_RejectsUnknownMode(t *testing.T) {
	t.Parallel()

	_, err := jarm.BuildRedirect(jarm.ResponseMode("query"), "https://rp.example.com/cb", "j")
	if !errors.Is(err, jarm.ErrUnsupportedResponseMode) {
		t.Errorf("err=%v want ErrUnsupportedResponseMode", err)
	}
}

func TestBuildRedirect_InvalidRedirectURI(t *testing.T) {
	t.Parallel()

	_, err := jarm.BuildRedirect(jarm.ResponseModeQueryJWT, "://malformed", "j")
	if !errors.Is(err, jarm.ErrInvalidRedirect) {
		t.Errorf("err=%v want ErrInvalidRedirect", err)
	}
}
