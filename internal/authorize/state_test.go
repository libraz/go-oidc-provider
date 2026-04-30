package authorize_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
)

// fixedNow is the canonical wall-clock reading the snapshot tests use. A
// constant time keeps "CreatedUnix" comparisons readable.
var fixedNow = time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

func TestSnapshotFrom_NilRequest(t *testing.T) {
	t.Parallel()

	got := authorize.SnapshotFrom(nil, fixedNow)
	if got.ClientID != "" {
		t.Errorf("ClientID=%q want empty", got.ClientID)
	}
	if got.CreatedUnix != fixedNow.UTC().Unix() {
		t.Errorf("CreatedUnix=%d want %d", got.CreatedUnix, fixedNow.UTC().Unix())
	}
}

func TestSnapshotFrom_FullRoundTrip(t *testing.T) {
	t.Parallel()

	maxAge := int64(60)
	req := &authorize.Request{
		ClientID:            "client-1",
		ResponseType:        "code",
		RedirectURI:         "https://rp.example.com/cb",
		State:               "abc",
		Nonce:               "nnn",
		CodeChallenge:       "ccc",
		CodeChallengeMethod: "S256",
		Scope:               []string{"openid", "profile"},
		Resource:            "https://api.example.com",
		Prompt:              []string{"consent"},
		ACRValues:           []string{"urn:1"},
		UILocales:           []string{"en-US"},
		MaxAge:              &maxAge,
		LoginHint:           "user@example.com",
	}
	snap := authorize.SnapshotFrom(req, fixedNow)
	if snap.CreatedUnix != fixedNow.UTC().Unix() {
		t.Errorf("CreatedUnix=%d", snap.CreatedUnix)
	}

	got := snap.ToRequest()
	if got == nil {
		t.Fatal("ToRequest returned nil")
	}
	if got.ClientID != req.ClientID || got.ResponseType != req.ResponseType {
		t.Errorf("identity mismatch: %+v vs %+v", got, req)
	}
	if got.MaxAge == nil || *got.MaxAge != maxAge {
		t.Errorf("MaxAge=%v want %d", got.MaxAge, maxAge)
	}
	if got.Resource != req.Resource {
		t.Errorf("Resource=%q want %q", got.Resource, req.Resource)
	}
	// Mutating the recovered request must not affect the snapshot.
	got.Scope[0] = "mutated"
	if snap.Scope[0] != "openid" {
		t.Errorf("snapshot scope leaked: %v", snap.Scope)
	}
}

func TestSnapshotFrom_AbsentMaxAgeStaysAbsent(t *testing.T) {
	t.Parallel()

	req := &authorize.Request{ClientID: "x", RedirectURI: "y"}
	snap := authorize.SnapshotFrom(req, fixedNow)
	if snap.MaxAge != nil {
		t.Errorf("MaxAge=%v want nil", snap.MaxAge)
	}
	if got := snap.ToRequest(); got.MaxAge != nil {
		t.Errorf("ToRequest MaxAge=%v want nil", got.MaxAge)
	}
}

func TestRequestState_RoundTripWithAuthnBlob(t *testing.T) {
	t.Parallel()

	state := authorize.RequestState{
		Library: authorize.SnapshotFrom(&authorize.Request{
			ClientID:    "client-1",
			RedirectURI: "https://rp.example.com/cb",
			Scope:       []string{"openid"},
		}, fixedNow),
		Authn: json.RawMessage(`{"phase":1,"step_counter":2}`),
	}
	raw, err := authorize.MarshalState(state)
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}
	got, err := authorize.UnmarshalState(raw)
	if err != nil {
		t.Fatalf("UnmarshalState: %v", err)
	}
	if got.Library.ClientID != "client-1" {
		t.Errorf("ClientID=%q", got.Library.ClientID)
	}
	if string(got.Authn) != `{"phase":1,"step_counter":2}` {
		t.Errorf("Authn=%s", string(got.Authn))
	}
}

func TestUnmarshalState_RejectsGarbage(t *testing.T) {
	t.Parallel()

	if _, err := authorize.UnmarshalState([]byte("not-json")); err == nil {
		t.Error("UnmarshalState accepted invalid JSON")
	}
}
