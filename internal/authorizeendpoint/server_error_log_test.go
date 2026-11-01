package authorizeendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/op/store"
)

// findFaultInteractions fails every Find with err.
type findFaultInteractions struct {
	store.InteractionStore
	err error
}

func (f findFaultInteractions) Find(context.Context, string) (*store.Interaction, error) {
	return nil, f.err
}

// TestInteraction_StoreFaultIsLoggedAndWireUnchanged pins that a store
// fault on the login path reaches the embedder's logger with its cause
// while the wire response carries the fixed description only.
func TestInteraction_StoreFaultIsLoggedAndWireUnchanged(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	h := newHarness(t, func(d *authorizeendpoint.Deps) { d.Logger = logger })
	start := startInteractionFlow(t, h)

	h.deps.Interactions = findFaultInteractions{
		InteractionStore: h.store.Interactions(),
		err:              errors.New("no such column: login_state"),
	}
	h.handler = authorizeendpoint.Handler(h.deps)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.interactionPth+"/"+start.uid, http.NoBody)
	r.AddCookie(start.interactionCk)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "server_error" || body["error_description"] != "interaction store unavailable" {
		t.Errorf("wire body = %v", body)
	}
	if strings.Contains(w.Body.String(), "login_state") {
		t.Errorf("wire body leaks the cause: %s", w.Body.String())
	}

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("decode log record %q: %v", buf.String(), err)
	}
	if rec["level"] != "ERROR" {
		t.Errorf("level=%v want ERROR", rec["level"])
	}
	if got, _ := rec["error"].(string); got != "no such column: login_state" {
		t.Errorf("err=%q", got)
	}
	if rec["description"] != "interaction store unavailable" {
		t.Errorf("description=%v", rec["description"])
	}
}

// TestAuthorize_RedirectURIMismatchEmitsAudit pins the audit event and
// the unchanged 400 for an unregistered redirect_uri.
func TestAuthorize_RedirectURIMismatchEmitsAudit(t *testing.T) {
	t.Parallel()

	emitter := &recordingEmitter{}
	h := newHarness(t, func(d *authorizeendpoint.Deps) { d.Audit = emitter })
	values := goodAuthorizeValues()
	const presented = "https://evil.example.com/cb"
	values.Set("redirect_uri", presented)

	resp := doAuthorizeGET(t, h, values)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", body["error"])
	}

	var got []audit.Event
	for _, ev := range emitter.snapshot() {
		if ev.Name == string(auditevent.AuditRedirectURIMismatch) {
			got = append(got, ev)
		}
	}
	if len(got) != 1 {
		t.Fatalf("redirect_uri.mismatch events = %d want 1", len(got))
	}
	ev := got[0]
	if ev.Level != audit.LevelWarn || ev.ClientID != "client-1" {
		t.Errorf("level=%v client=%q", ev.Level, ev.ClientID)
	}
	if ev.Extras["endpoint"] != "authorize" || ev.Extras["redirect_uri"] != presented {
		t.Errorf("extras=%v", ev.Extras)
	}
}
