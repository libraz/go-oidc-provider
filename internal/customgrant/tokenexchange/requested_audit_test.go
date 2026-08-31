//nolint:testpackage // drives Handle against the unexported handler fields
package tokenexchange

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/customgrant"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// requestedAuditFixture builds a handler whose policy must never run,
// signs an id_token for audienceClientID, and returns the emitter that
// captured the exchange.
type requestedAuditFixture struct {
	handler *Handler
	emitter *recordingEmitter
	idToken string
}

func newRequestedAuditFixture(t *testing.T, audienceClientID string) requestedAuditFixture {
	t.Helper()

	entry, err := keys.GenerateES256("tx-requested-audit-kid")
	if err != nil {
		t.Fatalf("GenerateES256: %v", err)
	}
	keySet, err := keys.NewSet([]keys.Entry{entry})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	emitter := &recordingEmitter{}
	h := &Handler{
		policy: func(_ context.Context, _ RequestView) (*Decision, error) {
			t.Helper()
			t.Fatal("policy unexpectedly invoked: the parse-stage gate should have rejected first")
			return nil, errors.New("unreachable")
		},
		issuer: "https://op.example",
		keys:   keySet,
		audit:  emitter,
		clock:  fixedClock{now: now},
		grants: staticGrantStore{grant: &store.Grant{
			ID:       "grant-requested-audit",
			Subject:  "user-1",
			ClientID: audienceClientID,
			Scope:    []string{"openid"},
		}},
		maxAccessTTL: time.Hour,
	}
	idToken, err := tokens.SignIDToken(tokens.FromInternalEntry(entry), tokens.IDTokenClaims{
		Issuer:    "https://op.example",
		Subject:   "user-1",
		Audience:  []string{audienceClientID},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}
	return requestedAuditFixture{handler: h, emitter: emitter, idToken: idToken}
}

// TestHandle_ParseStageRejectionStillRecordsTheAttempt pins the
// attempt-counting contract of the token-exchange audit stream: every
// request that reaches the handler is recorded as requested, before any
// gate can reject it.
//
// The gate driven here is the id_token audience binding, which rejects
// after the token verified — a security check whose silence an operator
// cannot explain. With the requested event raised only after the parse
// stage, an "exchange rejection rate" panel divided failures by a
// denominator that excluded this whole class of rejection, so the
// failure count could exceed the requested count and a request refused
// here was indistinguishable from one that was never made.
func TestHandle_ParseStageRejectionStillRecordsTheAttempt(t *testing.T) {
	t.Parallel()

	f := newRequestedAuditFixture(t, "another-client")
	req := customgrant.Request{
		Client: &store.Client{ID: "caller", Resources: []string{"https://api.target.example"}},
		Form: url.Values{
			"subject_token":      []string{f.idToken},
			"subject_token_type": []string{TokenTypeIDToken},
			"audience":           []string{"https://api.target.example"},
		},
	}

	_, err := f.handler.Handle(context.Background(), req)
	if err == nil {
		t.Fatal("Handle returned nil error; the id_token names another client as its audience")
	}
	var coded oauthCoded
	if !errors.As(err, &coded) {
		t.Fatalf("err %v does not satisfy oauthCoded", err)
	}
	if got := coded.OAuthCode(); got != "invalid_grant" {
		t.Errorf("OAuthCode=%q want invalid_grant", got)
	}

	events := f.emitter.events
	if len(events) == 0 {
		t.Fatal("no audit events; the attempt left no trace at all")
	}
	if events[0].Name != auditRequested {
		t.Fatalf("first event=%q want %q; the attempt must be recorded before the gate that rejected it",
			events[0].Name, auditRequested)
	}
	if events[0].Level != audit.LevelInfo {
		t.Errorf("requested level=%v want %v", events[0].Level, audit.LevelInfo)
	}
	if events[0].ClientID != "caller" {
		t.Errorf("requested client_id=%q want %q", events[0].ClientID, "caller")
	}
	aud, _ := events[0].Extras["requested_audience"].([]string)
	if len(aud) != 1 || aud[0] != "https://api.target.example" {
		t.Errorf("requested_audience=%v want [https://api.target.example]", events[0].Extras["requested_audience"])
	}
	for _, ev := range events[1:] {
		if ev.Name == auditRequested {
			t.Errorf("requested emitted twice: %v", eventNames(events))
		}
	}
}

// TestHandle_MalformedRequestStillRecordsTheAttempt covers the earliest
// gate of all: a request whose form never resolves a token. It is the
// same invariant one step further out — the count of attempts must not
// depend on how far into the state machine a request got.
func TestHandle_MalformedRequestStillRecordsTheAttempt(t *testing.T) {
	t.Parallel()

	f := newRequestedAuditFixture(t, "caller")
	req := customgrant.Request{
		Client: &store.Client{ID: "caller"},
		Form: url.Values{
			"subject_token":      []string{f.idToken},
			"subject_token_type": []string{"urn:example:not-a-token-type"},
		},
	}

	if _, err := f.handler.Handle(context.Background(), req); err == nil {
		t.Fatal("Handle returned nil error; subject_token_type is not recognised")
	}
	if len(f.emitter.events) != 1 || f.emitter.events[0].Name != auditRequested {
		t.Fatalf("audit events=%v want exactly one %q", eventNames(f.emitter.events), auditRequested)
	}
}
