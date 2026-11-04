package authorizeendpoint

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/op/store"
)

// refusePKCE drives the /authorize validation-error writer with a missing
// code_challenge refusal for client.
func refusePKCE(deps resolved, client *store.Client) {
	req := &authorize.Request{ClientID: client.ID, RedirectURI: "https://rp.example/cb"}
	writeAuthorizeValidationError(httptest.NewRecorder(), jarFetchRequest(), req, client, deps, authorize.ErrPKCERequired)
}

func pkceLogRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

func TestAuthorize_PKCERequiredLogConfidentialClientWarnsOncePerClient(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	deps := resolveDeps(Deps{Logger: slog.New(slog.NewJSONHandler(&buf, nil))})
	client := &store.Client{ID: "confidential-1", RedirectURIs: []string{"https://rp.example/cb"}}

	refusePKCE(deps, client)
	recs := pkceLogRecords(t, &buf)
	if len(recs) != 1 {
		t.Fatalf("records=%d want 1: %s", len(recs), buf.String())
	}
	got := recs[0]
	if got["level"] != "WARN" || got["msg"] != "authorization request refused: code_challenge is required" {
		t.Errorf("level=%v msg=%v", got["level"], got["msg"])
	}
	if got["client_id"] != "confidential-1" {
		t.Errorf("client_id=%v", got["client_id"])
	}
	if s, _ := got["hint"].(string); !strings.Contains(s, "profile.OIDCCore") {
		t.Errorf("hint=%v want it to name profile.OIDCCore", got["hint"])
	}

	refusePKCE(deps, client)
	if n := len(pkceLogRecords(t, &buf)); n != 1 {
		t.Fatalf("records after repeat=%d want 1", n)
	}

	refusePKCE(deps, &store.Client{ID: "confidential-2", RedirectURIs: client.RedirectURIs})
	if n := len(pkceLogRecords(t, &buf)); n != 2 {
		t.Fatalf("records after a second client=%d want 2", n)
	}
}

func TestAuthorize_PKCERequiredLogClientTypeMandatingPKCEDoesNotLog(t *testing.T) {
	t.Parallel()
	cases := map[string]*store.Client{
		"public":            {ID: "pub", PublicClient: true},
		"native":            {ID: "nat", ApplicationType: "native"},
		"metadata-document": {ID: "cimd", Source: store.ClientSourceMetadataDocument},
	}
	for name, client := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			deps := resolveDeps(Deps{Logger: slog.New(slog.NewJSONHandler(&buf, nil))})
			refusePKCE(deps, client)
			if buf.Len() != 0 {
				t.Fatalf("unexpected log output: %s", buf.String())
			}
		})
	}
}

func TestAuthorize_PKCERequiredLogNativeConfidentialClientDoesNotLog(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	deps := resolveDeps(Deps{Logger: slog.New(slog.NewJSONHandler(&buf, nil))})
	refusePKCE(deps, &store.Client{ID: "native-confidential", ApplicationType: "native", PublicClient: false})
	if buf.Len() != 0 {
		t.Fatalf("unexpected log output: %s", buf.String())
	}
}

func TestAuthorize_PKCERequiredLogOtherRefusalDoesNotLog(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	deps := resolveDeps(Deps{Logger: slog.New(slog.NewJSONHandler(&buf, nil))})
	client := &store.Client{ID: "confidential-1"}
	req := &authorize.Request{ClientID: client.ID, RedirectURI: "https://rp.example/cb"}
	writeAuthorizeValidationError(httptest.NewRecorder(), jarFetchRequest(), req, client, deps, authorize.ErrPKCEFormat)
	if buf.Len() != 0 {
		t.Fatalf("unexpected log output: %s", buf.String())
	}
}

func TestAuthorize_PKCERequiredLogNilLoggerDoesNotPanic(t *testing.T) {
	t.Parallel()
	refusePKCE(resolveDeps(Deps{}), &store.Client{ID: "confidential-1"})
}
