package authorizeendpoint_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// auditSink is the concurrency-safe io.Writer the audit slog handler
// writes its JSON records into. Audit events are emitted from whichever
// goroutine served the request, so the buffer needs its own lock.
type auditSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *auditSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *auditSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// auditRecords decodes the JSON audit stream one line at a time. Each
// record keeps its canonical fields, so callers can select on "event"
// before reaching into "extras".
func auditRecords(t *testing.T, stream string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stream), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode audit record %q: %v", line, err)
		}
		out = append(out, record)
	}
	return out
}

// auditExtrasFor returns the "extras" object of every record emitted
// under the named event, in emission order.
func auditExtrasFor(t *testing.T, stream, event string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, record := range auditRecords(t, stream) {
		if name, _ := record["event"].(string); name != event {
			continue
		}
		extras, ok := record["extras"].(map[string]any)
		if !ok {
			t.Fatalf("audit record %q carries no extras: %v", event, record)
		}
		out = append(out, extras)
	}
	return out
}

// auditExtras decodes the JSON audit stream and returns the "extras"
// object of every record that carries one, keyed by nothing in
// particular — callers scan the slice for the key they care about.
func auditExtras(t *testing.T, stream string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, record := range auditRecords(t, stream) {
		if extras, ok := record["extras"].(map[string]any); ok {
			out = append(out, extras)
		}
	}
	return out
}

// collectAuditExtra returns every value recorded under key across the
// supplied extras objects, in emission order.
func collectAuditExtra(extras []map[string]any, key string) []string {
	var out []string
	for _, e := range extras {
		if v, ok := e[key].(string); ok {
			out = append(out, v)
		}
	}
	return out
}

// findAuditExtra returns the first value recorded under key across every
// audit record, or "" when no record carries it.
func findAuditExtra(extras []map[string]any, key string) string {
	if got := collectAuditExtra(extras, key); len(got) > 0 {
		return got[0]
	}
	return ""
}

// TestEndToEnd_AuditNeverCarriesRawAuthorizationCode pins that an
// authorization code never reaches the audit stream in a form that could
// be redeemed. Both issuance branches are driven through a real
// op.WithAuditLogger sink: the interaction completion that records the
// consent grant, and the silent mint the following pass takes once the
// grant covers the request.
//
// The code is a bearer credential for its whole TTL, so anyone with read
// access to the log — aggregation pipeline, SIEM, on-call — would
// otherwise be able to redeem it. The recorded value must be the
// irreversible digest instead, matching what the token endpoint stamps
// on the consumption record so the two still correlate.
func TestEndToEnd_AuditNeverCarriesRawAuthorizationCode(t *testing.T) {
	t.Parallel()

	sink := &auditSink{}
	f := newE2EFlow(t, "rp-audit-digest",
		testkit.WithOptions(op.WithAuditLogger(slog.New(slog.NewJSONHandler(sink, nil)))))

	// The interaction branch: with no grant on file the first pass runs
	// the consent ceremony and completes through /interaction.
	interactiveCode := f.completeLogin(t, f.authorize(t, f.values()), "user-audit-digest")

	// The silent branch: the grant the ceremony recorded covers the same
	// request, so the second pass mints straight from /authorize.
	silentLoc := f.authorize(t, f.values())
	silentCode := silentLoc.Query().Get("code")
	if silentCode == "" {
		t.Fatalf("second pass did not silent-mint a code: %s", silentLoc)
	}
	if silentCode == interactiveCode {
		t.Fatalf("both passes returned the same code %q; the branches are not distinct", silentCode)
	}

	stream := sink.String()
	if stream == "" {
		t.Fatal("audit sink captured nothing; the logger was not wired")
	}
	for name, code := range map[string]string{
		"interaction completion": interactiveCode,
		"silent mint":            silentCode,
	} {
		if strings.Contains(stream, code) {
			t.Errorf("audit stream contains the raw %s code %q", name, code)
		}
	}

	extras := auditExtras(t, stream)
	if got, want := findAuditExtra(extras, "completion_id"), audit.Fingerprint(interactiveCode); got != want {
		t.Errorf("extras.completion_id=%q want %q (the digest of the completed code)", got, want)
	}
	// Both branches issue a code and therefore both stamp a code_id; the
	// digests appear in issuance order.
	want := []string{audit.Fingerprint(interactiveCode), audit.Fingerprint(silentCode)}
	if got := collectAuditExtra(auditExtrasFor(t, stream, "code.issued"), "code_id"); !slices.Equal(got, want) {
		t.Errorf("code.issued code_id digests=%v want %v (interactive then silent)", got, want)
	}
}
