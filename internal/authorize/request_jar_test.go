package authorize_test

import (
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorize"
)

func TestParseValues_RequestObject(t *testing.T) {
	t.Parallel()

	v := url.Values{
		"client_id": {"abc"},
		"request":   {"eyJhbGciOiJFUzI1NiJ9.body.sig"},
	}
	req, err := authorize.ParseValues(v)
	if err != nil {
		t.Fatalf("ParseValues: %v", err)
	}
	if req.RequestObject != "eyJhbGciOiJFUzI1NiJ9.body.sig" {
		t.Errorf("RequestObject=%q", req.RequestObject)
	}
}

func TestParseValues_RequestURI(t *testing.T) {
	t.Parallel()

	v := url.Values{
		"client_id":   {"abc"},
		"request_uri": {"https://rp.example.com/req/1"},
	}
	req, err := authorize.ParseValues(v)
	if err != nil {
		t.Fatalf("ParseValues: %v", err)
	}
	if req.RequestURI != "https://rp.example.com/req/1" {
		t.Errorf("RequestURI=%q", req.RequestURI)
	}
}

func TestParseValues_RequestAndRequestURIBothPresent(t *testing.T) {
	t.Parallel()

	// The validator does not surface ErrRequestAndRequestURI on its
	// own — the HTTP layer enforces that rule before the validator
	// runs. The parser merely captures both values; this test
	// documents that contract.
	v := url.Values{
		"client_id":   {"abc"},
		"request":     {"eyJ..."},
		"request_uri": {"https://rp.example.com/req/1"},
	}
	req, err := authorize.ParseValues(v)
	if err != nil {
		t.Fatalf("ParseValues: %v", err)
	}
	if req.RequestObject == "" || req.RequestURI == "" {
		t.Errorf("expected both fields populated; got %+v", req)
	}
}
