package totp_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestAuthenticator_PromptReportsTheBudgetThatLocksFirst pins the
// AttemptsRemaining the TOTP prompt shows: the lower of the record's own
// budget, read with the verifier's rolling window, and the cross-factor
// counter's. A count taken from the raw record alone overstates the
// budget when a sibling factor has spent the shared one, and understates
// it once the record's failures have aged out of the window.
func TestAuthenticator_PromptReportsTheBudgetThatLocksFirst(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name           string
		recordFailures int
		firstFailure   time.Duration
		sharedFailures int
		wireCounter    bool
		want           int
	}{
		{name: "record failures past the window", recordFailures: 25, firstFailure: -25 * time.Hour, want: 30},
		{name: "record failures inside the window", recordFailures: 25, firstFailure: -time.Hour, want: 5},
		{name: "shared counter spent by a sibling factor", sharedFailures: 20, wireCounter: true, want: 10},
		{
			name:           "record budget lower than the shared one",
			recordFailures: 5, firstFailure: -time.Hour,
			sharedFailures: 2, wireCounter: true,
			want: 25,
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			const subject = "alice"
			clock := &fakeClock{t: time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)}
			st := inmem.New()
			codec, err := totp.NewCodec(newKey(t))
			if err != nil {
				t.Fatalf("NewCodec: %v", err)
			}
			secret, err := totp.GenerateSecret()
			if err != nil {
				t.Fatalf("GenerateSecret: %v", err)
			}
			rec := newRecord(t, codec, subject, secret, clock.t.Add(-48*time.Hour))
			rec.FailedCount = row.recordFailures
			if row.recordFailures > 0 {
				rec.FirstFailureAt = clock.t.Add(row.firstFailure)
			}
			if err := st.TOTPs().Put(ctx, rec); err != nil {
				t.Fatalf("TOTPs.Put: %v", err)
			}
			auth, err := totp.NewAuthenticator(&totp.Verifier{Codec: codec, Clock: clock}, st.TOTPs())
			if err != nil {
				t.Fatalf("NewAuthenticator: %v", err)
			}
			if row.wireCounter {
				counter, err := lockout.New(st.AuthnLockouts(), clock)
				if err != nil {
					t.Fatalf("lockout.New: %v", err)
				}
				for i := range row.sharedFailures {
					if _, err := counter.RecordFailure(ctx, subject); err != nil {
						t.Fatalf("RecordFailure %d: %v", i+1, err)
					}
				}
				auth = auth.WithLockout(counter)
			}

			step, err := auth.Begin(ctx, authn.BeginInput{Subject: subject, AuthTime: clock.t})
			if err != nil {
				t.Fatalf("Begin: %v", err)
			}
			data, ok := step.Prompt.Data.(interaction.TOTPPromptData)
			if !ok {
				t.Fatalf("Prompt.Data type = %T, want interaction.TOTPPromptData", step.Prompt.Data)
			}
			if data.AttemptsRemaining != row.want {
				t.Errorf("AttemptsRemaining = %d, want %d", data.AttemptsRemaining, row.want)
			}
		})
	}
}
