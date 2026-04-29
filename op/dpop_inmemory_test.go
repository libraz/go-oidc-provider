package op_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
)

func TestNewInMemoryDPoPNonceSource_RejectsNonPositiveRotation(t *testing.T) {
	t.Parallel()

	for _, d := range []time.Duration{0, -time.Second} {
		if _, err := op.NewInMemoryDPoPNonceSource(context.Background(), d); err == nil {
			t.Errorf("rotate=%v: expected error, got nil", d)
		}
	}
}

func TestNewInMemoryDPoPNonceSource_IssuesNonEmptyValue(t *testing.T) {
	t.Parallel()

	src, err := op.NewInMemoryDPoPNonceSource(context.Background(), time.Hour)
	if err != nil {
		t.Fatalf("NewInMemoryDPoPNonceSource: %v", err)
	}
	if got := src.IssueNonce(); got == "" {
		t.Errorf("IssueNonce returned empty string before rotation")
	}
}

func TestNewInMemoryDPoPNonceSource_ValidatesCurrent(t *testing.T) {
	t.Parallel()

	src, err := op.NewInMemoryDPoPNonceSource(context.Background(), time.Hour)
	if err != nil {
		t.Fatalf("NewInMemoryDPoPNonceSource: %v", err)
	}
	current := src.IssueNonce()
	if !src.Validate(current) {
		t.Errorf("Validate(current=%q) = false, want true", current)
	}
	if src.Validate("") {
		t.Errorf("Validate(empty) = true, want false")
	}
	if src.Validate("never-issued") {
		t.Errorf("Validate(never-issued) = true, want false")
	}
}

func TestNewInMemoryDPoPNonceSource_AcceptsPreviousAcrossRotation(t *testing.T) {
	t.Parallel()

	src, err := op.NewInMemoryDPoPNonceSource(context.Background(), 20*time.Millisecond)
	if err != nil {
		t.Fatalf("NewInMemoryDPoPNonceSource: %v", err)
	}
	first := src.IssueNonce()

	// Wait for at least one rotation to occur.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if next := src.IssueNonce(); next != first {
			// Rotation happened. The previous value MUST still
			// validate so an in-flight client retry that straddles
			// the boundary does not get rejected.
			if !src.Validate(first) {
				t.Errorf("Validate(previous=%q) = false after rotation, want true", first)
			}
			if !src.Validate(next) {
				t.Errorf("Validate(current=%q) = false, want true", next)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("nonce did not rotate within deadline (first=%q)", first)
}

func TestNewInMemoryDPoPNonceSource_StopsRotatingOnCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	src, err := op.NewInMemoryDPoPNonceSource(ctx, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewInMemoryDPoPNonceSource: %v", err)
	}
	cancel()

	// Give the rotation goroutine time to observe the cancellation.
	time.Sleep(50 * time.Millisecond)
	frozen := src.IssueNonce()
	time.Sleep(40 * time.Millisecond)
	if got := src.IssueNonce(); got != frozen {
		t.Errorf("IssueNonce kept rotating after ctx.Cancel: frozen=%q later=%q", frozen, got)
	}
	// Validation MUST keep working after cancellation; embedders rely
	// on in-flight RP retries succeeding even when the OP is shutting
	// down.
	if !src.Validate(frozen) {
		t.Errorf("Validate(%q) = false after cancel; helper must keep accepting the last issued nonce", frozen)
	}
}

func TestNewInMemoryDPoPNonceSource_ProducesUniqueValues(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, 64)
	for i := range 64 {
		src, err := op.NewInMemoryDPoPNonceSource(context.Background(), time.Hour)
		if err != nil {
			t.Fatalf("NewInMemoryDPoPNonceSource: %v", err)
		}
		v := src.IssueNonce()
		if v == "" || strings.ContainsAny(v, "+/=") {
			t.Errorf("nonce=%q is not non-empty base64url", v)
		}
		if _, dup := seen[v]; dup {
			t.Errorf("nonce %q collided after %d samples", v, i)
		}
		seen[v] = struct{}{}
	}
}
