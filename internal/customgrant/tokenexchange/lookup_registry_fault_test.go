// Test file pins the M10 invariant: a non-NotFound fault from the
// access-token registry during subject_token / actor_token lookup
// MUST surface on a dedicated audit event so SOC tooling can
// distinguish a transient outage (registry timeout, secondary
// failover) from an actual revocation. The wire response stays
// invalid_grant either way — the wire shape MUST stay collapsed —
// but the audit channel MUST split.
//
//nolint:testpackage // exercises unexported helpers
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

// errInjectedRegistryFault is the sentinel the failing-registry stub
// returns from [store.AccessTokenRegistry.Find]. The handler stringifies
// the wrapped cause into the audit Extras["error"] field; the test
// asserts on the wrapped sentinel rather than the formatted string so
// rephrasing the wrapper does not break the assertion.
var errInjectedRegistryFault = errors.New("injected: registry Find fault")

// faultyRegistry implements [store.AccessTokenRegistry] and forces every
// Find call to fail with [errInjectedRegistryFault]. Register / Revoke /
// GC are not exercised by the lookup path; they panic so a future code
// change that quietly invokes them through the lookup surface fails
// loudly rather than reading a zero value.
type faultyRegistry struct{}

func (faultyRegistry) Register(_ context.Context, _ store.AccessTokenRecord) error {
	panic("faultyRegistry.Register should not be reached on the lookup path")
}

func (faultyRegistry) Find(_ context.Context, _ string) (*store.AccessTokenRecord, error) {
	return nil, errInjectedRegistryFault
}

func (faultyRegistry) RevokeByJTI(_ context.Context, _ string) error {
	panic("faultyRegistry.RevokeByJTI should not be reached on the lookup path")
}

func (faultyRegistry) RevokeByGrant(_ context.Context, _ string) (int, error) {
	panic("faultyRegistry.RevokeByGrant should not be reached on the lookup path")
}

func (faultyRegistry) GC(_ context.Context, _ time.Time) (int, error) {
	panic("faultyRegistry.GC should not be reached on the lookup path")
}

// recordingEmitter captures every emitted audit.Event in order so the
// test can scan for the M10 audit name. The struct is intentionally not
// goroutine-safe — a single test goroutine drives one Handle call.
type recordingEmitter struct {
	events []audit.Event
}

func (e *recordingEmitter) Emit(_ context.Context, ev audit.Event) {
	e.events = append(e.events, ev)
}

// TestHandle_RegistryFault_EmitsRegistryErrorAudit pins the M10
// invariant end-to-end through the handler:
//
//   - the wire response is invalid_grant (the existing wire shape
//     MUST stay collapsed regardless of the audit split);
//   - the audit stream carries token_exchange.subject_token_registry_error
//     and NOT token_exchange.subject_token_invalid;
//   - the dedicated event is emitted at warn level (a healthy
//     deployment should never see it);
//   - extras["reason"] == "registry_error" and extras["is_subject"]
//     == true so SOC tooling can pivot.
func TestHandle_RegistryFault_EmitsRegistryErrorAudit(t *testing.T) {
	t.Parallel()

	// Build a real signing keyset so the JWS verifies cleanly; the
	// fault is injected on the registry layer, not the signature
	// layer.
	entry, err := keys.GenerateES256("tx-m10-kid")
	if err != nil {
		t.Fatalf("GenerateES256: %v", err)
	}
	keySet, err := keys.NewSet([]keys.Entry{entry})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	clock := fixedClock{now: now}
	emitter := &recordingEmitter{}

	h := &Handler{
		policy: func(_ context.Context, _ RequestView) (*Decision, error) {
			// The registry-fault path returns invalid_grant before
			// the policy runs; reaching this stub means the gate
			// regressed and the test should fail loudly rather than
			// silently emit (nil, nil).
			t.Helper()
			t.Fatal("policy unexpectedly invoked: registry-fault path should short-circuit before policy runs")
			return nil, errors.New("unreachable")
		},
		issuer:       "https://op.example",
		keys:         keySet,
		accessTokens: faultyRegistry{},
		audit:        emitter,
		clock:        clock,
		maxAccessTTL: time.Hour,
	}

	// Mint a JWT-shaped subject_token signed by the OP keyset so the
	// JWS verification step passes; the registry fault fires on the
	// defence-in-depth Find call after verification succeeds.
	signer := tokens.FromInternalEntry(entry)
	subjectJWS, err := tokens.SignAccessToken(signer, tokens.AccessTokenClaims{
		Issuer:    "https://op.example",
		Subject:   "user-m10",
		Audience:  []string{"https://api.target.example"},
		ClientID:  "subject-client",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       "tx-m10-jti",
		Scope:     []string{"read"},
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}

	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{TokenTypeAccessToken},
	}
	req := customgrant.Request{
		Client: &store.Client{ID: "caller", Resources: []string{"https://api.target.example"}},
		Form:   form,
	}

	_, herr := h.Handle(context.Background(), req)
	if herr == nil {
		t.Fatalf("Handle returned nil error; expected invalid_grant")
	}
	// (a) wire shape: invalid_grant. The handler's invalidGrant helper
	// returns an oauthCoded error; pull the code out via the same
	// interface.
	var coded oauthCoded
	if !errors.As(herr, &coded) {
		t.Fatalf("err %v does not satisfy oauthCoded", herr)
	}
	if got := coded.OAuthCode(); got != "invalid_grant" {
		t.Errorf("OAuthCode=%q, want invalid_grant", got)
	}

	// (b) audit channel: a single token_exchange.subject_token_registry_error
	// event was emitted; token_exchange.subject_token_invalid was NOT.
	var found *audit.Event
	for i := range emitter.events {
		ev := emitter.events[i]
		if ev.Name == auditSubjectTokenInvalid {
			t.Errorf("emitted %q for a registry fault; M10 splits this onto a dedicated event", ev.Name)
		}
		if ev.Name == auditSubjectTokenRegistryError {
			ev := ev
			found = &ev
		}
	}
	if found == nil {
		t.Fatalf("expected audit event %q; got %v", auditSubjectTokenRegistryError, eventNames(emitter.events))
	}
	if found.Level != audit.LevelWarn {
		t.Errorf("event level=%v, want LevelWarn", found.Level)
	}
	if got, _ := found.Extras["reason"].(string); got != "registry_error" {
		t.Errorf("extras.reason=%q, want %q", got, "registry_error")
	}
	if got, _ := found.Extras["is_subject"].(bool); !got {
		t.Errorf("extras.is_subject=%v, want true", got)
	}
	if found.ClientID != "caller" {
		t.Errorf("client_id=%q, want %q", found.ClientID, "caller")
	}
}

// eventNames flattens an audit.Event slice to its Name fields so a
// failing assertion prints a compact list of what WAS emitted instead
// of dumping the full audit struct.
func eventNames(events []audit.Event) []string {
	out := make([]string, 0, len(events))
	for _, ev := range events {
		out = append(out, ev.Name)
	}
	return out
}
