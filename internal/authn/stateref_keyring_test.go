package authn_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
)

func TestStateRefSigner_KeyRotationAcceptsPreviousAndIssuesCurrent(t *testing.T) {
	t.Parallel()

	current := bytes.Repeat([]byte{0x11}, 32)
	previous := bytes.Repeat([]byte{0x22}, 32)
	old, err := authn.NewStateRefSigner(previous)
	if err != nil {
		t.Fatalf("old NewStateRefSigner: %v", err)
	}
	ring, err := authn.NewStateRefSigner(current, previous)
	if err != nil {
		t.Fatalf("ring NewStateRefSigner: %v", err)
	}
	now := fakeNow()
	oldToken, err := old.Issue("uid", "auth:password", 2, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("old Issue: %v", err)
	}
	if _, err := ring.Verify(oldToken, "uid", 2, now); err != nil {
		t.Fatalf("ring rejected previous-key token: %v", err)
	}
	newToken, err := ring.Issue("uid", "auth:password", 2, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("ring Issue: %v", err)
	}
	if _, err := old.Verify(newToken, "uid", 2, now); !errors.Is(err, authn.ErrStateRefSignature) {
		t.Fatalf("old signer accepted current-key token: %v", err)
	}
}

func TestStateRefSigner_IssueRejectsInvalidSemanticPayload(t *testing.T) {
	t.Parallel()

	s := newSigner(t)
	now := fakeNow()
	for _, tc := range []struct {
		name string
		uid  string
		tag  string
		step int
		exp  time.Time
	}{
		{name: "empty-uid", uid: "", tag: "auth:password", step: 0, exp: now.Add(time.Hour)},
		{name: "empty-tag", uid: "uid", tag: "", step: 0, exp: now.Add(time.Hour)},
		{name: "negative-step", uid: "uid", tag: "auth:password", step: -1, exp: now.Add(time.Hour)},
		{name: "empty-expiry", uid: "uid", tag: "auth:password", step: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := s.Issue(tc.uid, tc.tag, tc.step, tc.exp); !errors.Is(err, authn.ErrStateRefMalformed) {
				t.Errorf("Issue err=%v want ErrStateRefMalformed", err)
			}
		})
	}
}
