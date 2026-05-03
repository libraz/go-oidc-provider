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

	// Only the PAR URN form is accepted. Bare https URLs (RFC 9101
	// §5.2.2 JAR-by-URI) are rejected at the parser; see
	// TestParseValues_RequestURIShape.
	const parURN = "urn:ietf:params:oauth:request_uri:abc123"
	v := url.Values{
		"client_id":   {"abc"},
		"request_uri": {parURN},
	}
	req, err := authorize.ParseValues(v)
	if err != nil {
		t.Fatalf("ParseValues: %v", err)
	}
	if req.RequestURI != parURN {
		t.Errorf("RequestURI=%q", req.RequestURI)
	}
}

func TestParseValues_RequestAndRequestURIBothPresent(t *testing.T) {
	t.Parallel()

	// The validator does not surface ErrRequestAndRequestURI on its
	// own — the HTTP layer enforces that rule before the validator
	// runs. The parser merely captures both values; this test
	// documents that contract. The request_uri value uses the PAR
	// URN form because non-PAR request_uri is rejected at the parser.
	const parURN = "urn:ietf:params:oauth:request_uri:abc123"
	v := url.Values{
		"client_id":   {"abc"},
		"request":     {"eyJ..."},
		"request_uri": {parURN},
	}
	req, err := authorize.ParseValues(v)
	if err != nil {
		t.Fatalf("ParseValues: %v", err)
	}
	if req.RequestObject == "" || req.RequestURI == "" {
		t.Errorf("expected both fields populated; got %+v", req)
	}
}
