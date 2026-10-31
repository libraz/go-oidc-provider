package ssf

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestSET_BuildClaimsShape(t *testing.T) {
	t.Parallel()
	b, err := BuildClaims(Claims{
		Issuer:    testIssuer,
		Audience:  "rp-1",
		IssuedAt:  testNow,
		JTI:       "jti-1",
		TxN:       "txn-1",
		SubjectID: IssSubSubject(testIssuer, "alice"),
		Event:     EventSessionRevoked,
		Payload:   map[string]any{"event_timestamp": testNow.Unix()},
	})
	if err != nil {
		t.Fatalf("BuildClaims: %v", err)
	}
	c := decodeClaims(t, b)
	want := map[string]any{"iss": testIssuer, "aud": "rp-1", "jti": "jti-1", "txn": "txn-1", "iat": float64(testNow.Unix())}
	for k, v := range want {
		if c[k] != v {
			t.Errorf("%s = %#v, want %#v", k, c[k], v)
		}
	}
	for _, k := range []string{"sub", "exp"} {
		if _, ok := c[k]; ok {
			t.Errorf("claims carry %q; a SET must not", k)
		}
	}
	subID, _ := c["sub_id"].(map[string]any)
	if subID["format"] != "iss_sub" || subID["iss"] != testIssuer || subID["sub"] != "alice" {
		t.Errorf("sub_id = %#v", c["sub_id"])
	}
	if key, _ := eventMember(t, c); key != string(EventSessionRevoked) {
		t.Errorf("event key = %q", key)
	}
}

func TestSET_BuildClaimsOmitsEmptyTxnAndEncodesNilPayload(t *testing.T) {
	t.Parallel()
	b, err := BuildClaims(Claims{
		Issuer: testIssuer, Audience: "rp-1", IssuedAt: testNow, JTI: "j",
		SubjectID: StreamSubject("s-1"), Event: EventVerification,
	})
	if err != nil {
		t.Fatalf("BuildClaims: %v", err)
	}
	c := decodeClaims(t, b)
	if _, ok := c["txn"]; ok {
		t.Error("empty txn was emitted")
	}
	if subID, _ := c["sub_id"].(map[string]any); subID["format"] != "opaque" || subID["id"] != "s-1" {
		t.Errorf("sub_id = %#v", c["sub_id"])
	}
	if _, payload := eventMember(t, c); len(payload) != 0 {
		t.Errorf("payload = %#v, want {}", payload)
	}
}

func TestSET_BuildClaimsRejectsMissingMembers(t *testing.T) {
	t.Parallel()
	base := Claims{
		Issuer: testIssuer, Audience: "rp-1", IssuedAt: testNow, JTI: "j",
		SubjectID: IssSubSubject(testIssuer, "alice"), Event: EventSessionRevoked,
	}
	cases := map[string]func(*Claims){
		"issuer":   func(c *Claims) { c.Issuer = "" },
		"audience": func(c *Claims) { c.Audience = "" },
		"jti":      func(c *Claims) { c.JTI = "" },
		"event":    func(c *Claims) { c.Event = "" },
		"iat":      func(c *Claims) { c.IssuedAt = time.Time{} },
		"sub_id":   func(c *Claims) { c.SubjectID = nil },
		"format":   func(c *Claims) { c.SubjectID = map[string]string{"sub": "alice"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := base
			mutate(&c)
			if _, err := BuildClaims(c); !errors.Is(err, ErrInvalidClaims) {
				t.Fatalf("err = %v, want ErrInvalidClaims", err)
			}
		})
	}
}

func TestSET_SignProducesTypedVerifiableJWS(t *testing.T) {
	t.Parallel()
	key, pub := testKey(t, "sig-1")
	claims, err := BuildClaims(Claims{
		Issuer: testIssuer, Audience: "rp-1", IssuedAt: testNow, JTI: "j",
		SubjectID: IssSubSubject(testIssuer, "alice"), Event: EventSessionRevoked,
	})
	if err != nil {
		t.Fatalf("BuildClaims: %v", err)
	}
	compact, err := Sign(claims, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	hdr, payload := verifySET(t, compact, pub)
	if typ, _ := hdr.ExtraHeaders["typ"].(string); typ != TokenType {
		t.Errorf("typ = %q, want %q", typ, TokenType)
	}
	if hdr.KeyID != "sig-1" || hdr.Algorithm != "ES256" {
		t.Errorf("kid/alg = %q/%q", hdr.KeyID, hdr.Algorithm)
	}
	if !bytes.Equal(payload, claims) {
		t.Errorf("payload is not the stored claims verbatim:\n got %s\nwant %s", payload, claims)
	}
}

func TestSET_SignRejectsMalformedClaims(t *testing.T) {
	t.Parallel()
	key, _ := testKey(t, "sig-1")
	cases := map[string]string{
		"not json":     `{`,
		"missing aud":  `{"iss":"i","jti":"j","events":{"e":{}}}`,
		"carries sub":  `{"iss":"i","jti":"j","aud":"a","sub":"x","events":{"e":{}}}`,
		"carries exp":  `{"iss":"i","jti":"j","aud":"a","exp":1,"events":{"e":{}}}`,
		"two events":   `{"iss":"i","jti":"j","aud":"a","events":{"e":{},"f":{}}}`,
		"no events":    `{"iss":"i","jti":"j","aud":"a"}`,
		"array claims": `[]`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Sign([]byte(raw), key); !errors.Is(err, ErrInvalidClaims) {
				t.Fatalf("err = %v, want ErrInvalidClaims", err)
			}
		})
	}
	if _, err := Sign([]byte(`{}`), SigningKey{}); err == nil {
		t.Error("nil signer accepted")
	}
}

func TestSET_EventPayloads(t *testing.T) {
	t.Parallel()
	custom := map[string]string{"en": "admin action", "ja": "管理操作"}
	cases := []struct {
		name    string
		et      EventType
		f       Fields
		want    map[string]any
		absent  []string
		wantErr bool
	}{
		{
			name:   "session-revoked default reason",
			et:     EventSessionRevoked,
			want:   map[string]any{"event_timestamp": testNow.Unix(), "reason_admin": map[string]string{"en": defaultSessionRevokedReason}},
			absent: []string{"initiating_entity"},
		},
		{
			name: "session-revoked logout initiated",
			et:   EventSessionRevoked,
			f:    Fields{InitiatingEntity: InitiatingEntityUser, ReasonAdmin: custom},
			want: map[string]any{"initiating_entity": "user", "reason_admin": custom},
		},
		{
			name:   "credential-change",
			et:     EventCredentialChange,
			f:      Fields{CredentialType: "password", ChangeType: "update"},
			want:   map[string]any{"credential_type": "password", "change_type": "update", "reason_admin": map[string]string{"en": defaultCredentialChangeReason}},
			absent: []string{"friendly_name", "initiating_entity"},
		},
		{
			name: "credential-change friendly name",
			et:   EventCredentialChange,
			f:    Fields{CredentialType: "fido2-platform", ChangeType: "create", FriendlyName: "laptop"},
			want: map[string]any{"friendly_name": "laptop"},
		},
		{name: "credential-change without change_type", et: EventCredentialChange, f: Fields{CredentialType: "password"}, wantErr: true},
		{name: "credential-change without credential_type", et: EventCredentialChange, f: Fields{ChangeType: "create"}, wantErr: true},
		{name: "account-disabled reason", et: EventAccountDisabled, f: Fields{Reason: "hijacking"}, want: map[string]any{"reason": "hijacking"}, absent: []string{"reason_admin", "event_timestamp"}},
		{name: "account-disabled no reason", et: EventAccountDisabled, absent: []string{"reason"}},
		{name: "account-enabled", et: EventAccountEnabled, absent: []string{"reason_admin"}},
		{name: "account-purged", et: EventAccountPurged, absent: []string{"reason_admin"}},
		{name: "credential-compromise", et: EventCredentialCompromise, f: Fields{CredentialType: "password"}, want: map[string]any{"credential_type": "password"}},
		{name: "credential-compromise without credential_type", et: EventCredentialCompromise, wantErr: true},
		{name: "control type", et: EventVerification, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := eventPayload(tc.et, tc.f, testNow)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidEvent) {
					t.Fatalf("err = %v, want ErrInvalidEvent", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("eventPayload: %v", err)
			}
			for k, v := range tc.want {
				if !equalJSONish(p[k], v) {
					t.Errorf("%s = %#v, want %#v", k, p[k], v)
				}
			}
			for _, k := range tc.absent {
				if _, ok := p[k]; ok {
					t.Errorf("%s present; want absent", k)
				}
			}
		})
	}
}

func TestSET_ReasonAdminIsCopied(t *testing.T) {
	t.Parallel()
	in := map[string]string{"en": "x"}
	p, err := eventPayload(EventSessionRevoked, Fields{ReasonAdmin: in}, testNow)
	if err != nil {
		t.Fatalf("eventPayload: %v", err)
	}
	in["en"] = "mutated"
	if got := p["reason_admin"].(map[string]string)["en"]; got != "x" {
		t.Errorf("reason_admin aliases the caller's map: %q", got)
	}
}

func TestSET_ControlPayloads(t *testing.T) {
	t.Parallel()
	p, err := controlPayload(EventStreamUpdated, ControlFields{Status: "paused", Reason: "maintenance"})
	if err != nil || p["status"] != "paused" || p["reason"] != "maintenance" {
		t.Errorf("stream-updated = %#v, %v", p, err)
	}
	if _, err := controlPayload(EventStreamUpdated, ControlFields{}); !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("stream-updated without status: err = %v", err)
	}
	p, err = controlPayload(EventVerification, ControlFields{State: "abc"})
	if err != nil || p["state"] != "abc" {
		t.Errorf("verification = %#v, %v", p, err)
	}
	p, err = controlPayload(EventVerification, ControlFields{})
	if _, ok := p["state"]; err != nil || ok {
		t.Errorf("stateless verification = %#v, %v", p, err)
	}
	if _, err := controlPayload(EventSessionRevoked, ControlFields{}); !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("ordinary type accepted as control: %v", err)
	}
}

func TestSET_SupportedEventsExcludeControl(t *testing.T) {
	t.Parallel()
	got := SupportedEvents()
	if len(got) != 6 {
		t.Fatalf("SupportedEvents = %v", got)
	}
	for _, c := range []EventType{EventStreamUpdated, EventVerification} {
		if slices.Contains(got, string(c)) {
			t.Errorf("SupportedEvents lists control event %q", c)
		}
	}
}

func TestSET_NewIDIsUnique(t *testing.T) {
	t.Parallel()
	a, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	b, _ := NewID()
	if a == b || len(a) < 20 {
		t.Errorf("NewID = %q, %q", a, b)
	}
}

func equalJSONish(got, want any) bool {
	switch w := want.(type) {
	case map[string]string:
		g, ok := got.(map[string]string)
		if !ok || len(g) != len(w) {
			return false
		}
		for k, v := range w {
			if g[k] != v {
				return false
			}
		}
		return true
	default:
		return got == want
	}
}
