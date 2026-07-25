package emailotp_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// TestContinueVerify_ConcurrentSubmissionsOfOneCodeYieldOneSuccess pins
// that a delivered code is single-use under interleaving, not merely
// under sequence.
//
// "Read the record, see it is unconsumed, mark it consumed" is three
// steps, and a second request that arrives between the first and the
// third sees exactly what the first saw. Both then proceed, and the
// code that was mailed once authenticates twice. This is the same
// property as the ordinary replay check but a different implementation
// question: replay is answered by the guard existing, interleaving is
// answered by the guard and the write being one operation the store
// arbitrates.
//
// It matters for a mailed code specifically because the delivery
// channel is shared and lossy in ways the user compensates for. People
// double-click, mail clients prefetch links, and a code that reaches an
// inbox reaches whatever else can read that inbox. A second acceptance
// is a second session.
//
// Tracks: CVE-2026-22751 (Spring Security) — JdbcOneTimeTokenService
// read the token, decided it was unused, and deleted it in separate
// statements, so a one-time token could authenticate multiple times
// when the requests raced.
func TestContinueVerify_ConcurrentSubmissionsOfOneCodeYieldOneSuccess(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	a, mailer, recStore := newFixture(t, now)
	code := driveSendStep(t, a, mailer, "sub-1")

	const concurrent = 8
	var (
		wg      sync.WaitGroup
		ready   = make(chan struct{})
		results = make(chan error, concurrent)
	)
	for range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Pile in together so the submissions genuinely interleave
			// rather than queueing behind each other.
			<-ready
			step, err := a.Continue(context.Background(), authn.ContinueInput{
				Subject:  "sub-1",
				AuthTime: now.Add(time.Second),
				Scratch:  emailotp.ScratchVerify,
				Submission: interaction.FormSubmission{
					Values: map[string]string{emailotp.CodeFieldName: code},
				},
			})
			if err == nil && step.Result == nil {
				// A nil error with no Result would be neither a
				// success nor a refusal; count it as neither by
				// reporting a distinguishable error.
				results <- errNoResult
				return
			}
			results <- err
		}()
	}
	close(ready)
	wg.Wait()
	close(results)

	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d of %d concurrent submissions of one code authenticated, want exactly 1; "+
			"the consume is not atomic with the check", succeeded, concurrent)
	}

	// And the record reflects a single consumption, so the winner's
	// write is the one that survived rather than the last writer's.
	rec, err := recStore.Get(context.Background(), "sub-1")
	if err != nil {
		t.Fatalf("Get record: %v", err)
	}
	if rec.ConsumedAt.IsZero() {
		t.Error("ConsumedAt not stamped after a successful verify")
	}
}

// errNoResult marks a Continue that returned neither an error nor a
// Result, which would otherwise be counted as a success by the nil-error
// test above.
var errNoResult = &noResultError{}

type noResultError struct{}

func (*noResultError) Error() string { return "emailotp: Continue returned no error and no Result" }
