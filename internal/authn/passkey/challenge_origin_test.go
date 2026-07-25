package passkey_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// TestAuthenticator_ChallengeComesOnlyFromServerHeldState pins where the
// challenge a WebAuthn assertion is checked against comes from: the
// ceremony state the OP minted and kept, never anything the client sends
// back. The client does receive the challenge — it has to, that is how
// the ceremony works — but the value it returns is only ever the signed
// material under scrutiny, never the yardstick.
//
// The three assertions correspond to the three ways a client could try to
// supply one. It cannot smuggle a challenge through the submission,
// because the prompt declares exactly one input and the adapter reads
// exactly that one. It cannot proceed without server state, because an
// absent ceremony is a hard error rather than a fall back to whatever the
// submission carried. And it cannot pin the OP to a challenge it has seen
// before, because each ceremony mints a fresh one.
//
// Tracks: CVE-2026-28787 (OneUptime) — the ceremony challenge was
// returned to the client and accepted back at verification time, so an
// assertion captured once replayed indefinitely (W3C WebAuthn Level 2
// §13.4.3 requires the challenge be stored server-side and consumed
// single-use).
func TestAuthenticator_ChallengeComesOnlyFromServerHeldState(t *testing.T) {
	t.Parallel()

	t.Run("submission cannot carry a challenge", func(t *testing.T) {
		t.Parallel()
		f := newAdapterFixture(t)

		step, err := f.adapter.Begin(context.Background(), op.BeginInput{
			Subject:  adapterTestSubject,
			AuthTime: f.now,
		})
		if err != nil {
			t.Fatalf("Begin: %v", err)
		}
		// The prompt is the client's entire write surface for this
		// factor. One field, and it is the assertion response.
		if len(step.Prompt.Inputs) != 1 {
			t.Fatalf("prompt declares %d inputs, want 1: %+v", len(step.Prompt.Inputs), step.Prompt.Inputs)
		}
		if step.Prompt.Inputs[0].Name != passkey.ResponseFieldName {
			t.Fatalf("prompt input = %q, want %q", step.Prompt.Inputs[0].Name, passkey.ResponseFieldName)
		}

		// Present an expired ceremony alongside a submission that also
		// carries a plausible-looking challenge under several names. The
		// expiry verdict must be unchanged: the adapter decided from the
		// server-held session and never consulted the extra fields.
		expired := passkey.Session{
			Challenge: "server-held-challenge",
			UserID:    []byte(adapterTestSubject),
			Expires:   f.now.Add(-time.Minute),
		}
		scratch, err := json.Marshal(expired)
		if err != nil {
			t.Fatalf("marshal session: %v", err)
		}
		_, err = f.adapter.Continue(context.Background(), op.ContinueInput{
			Subject:  adapterTestSubject,
			AuthTime: f.now,
			Submission: interaction.FormSubmission{
				Values: map[string]string{
					passkey.ResponseFieldName: "{}",
					"challenge":               "client-supplied-challenge",
					"session":                 `{"challenge":"client-supplied-challenge","expires":"2126-01-01T00:00:00Z"}`,
					"expires":                 "2126-01-01T00:00:00Z",
				},
			},
			Scratch: scratch,
		})
		if !errors.Is(err, passkey.ErrChallengeExpired) {
			t.Fatalf("err = %v, want ErrChallengeExpired; a client-supplied field displaced the server-held ceremony", err)
		}
	})

	t.Run("absent server state is a hard failure", func(t *testing.T) {
		t.Parallel()
		f := newAdapterFixture(t)

		// A client that sends a complete-looking ceremony but no
		// server-side state must be refused outright. Accepting this
		// shape is precisely the upstream defect: verification would
		// then run against material the caller chose.
		_, err := f.adapter.Continue(context.Background(), op.ContinueInput{
			Subject:  adapterTestSubject,
			AuthTime: f.now,
			Submission: interaction.FormSubmission{
				Values: map[string]string{
					passkey.ResponseFieldName: "{}",
					"challenge":               "client-supplied-challenge",
				},
			},
		})
		if !errors.Is(err, passkey.ErrSessionMissing) {
			t.Fatalf("err = %v, want ErrSessionMissing", err)
		}
	})

	t.Run("each ceremony mints a fresh challenge", func(t *testing.T) {
		t.Parallel()
		f := newAdapterFixture(t)

		seen := make(map[string]struct{}, 8)
		for i := range 8 {
			step, err := f.adapter.Begin(context.Background(), op.BeginInput{
				Subject:  adapterTestSubject,
				AuthTime: f.now,
			})
			if err != nil {
				t.Fatalf("Begin %d: %v", i, err)
			}
			var session passkey.Session
			if err := json.Unmarshal(step.Scratch, &session); err != nil {
				t.Fatalf("Begin %d: decode scratch: %v", i, err)
			}
			if session.Challenge == "" {
				t.Fatalf("Begin %d minted an empty challenge", i)
			}
			if _, dup := seen[session.Challenge]; dup {
				t.Fatalf("Begin %d reissued challenge %q; a repeated challenge makes a captured assertion replayable",
					i, session.Challenge)
			}
			seen[session.Challenge] = struct{}{}
		}
	})
}
