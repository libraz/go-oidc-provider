//go:build testcontainers

package oidcredis_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	redismod "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/libraz/go-oidc-provider/op"
	oidcredis "github.com/libraz/go-oidc-provider/op/storeadapter/redis"
)

var _ op.DPoPNonceSource = (*oidcredis.DPoPNonceSource)(nil)

// nonceRig is one Redis container with a movable clock; stores built from
// it share a key prefix, standing in for replicas of one OP.
type nonceRig struct {
	dsn    string
	pw     string
	prefix string
	clock  *fixedClock
}

func newNonceRig(t *testing.T) *nonceRig {
	t.Helper()
	const pw = "nonce-test-pw" //nolint:gosec // ephemeral test container.
	ctr, err := redismod.Run(context.Background(), redisImage,
		testcontainers.WithCmdArgs("--requirepass", pw),
		testcontainers.WithWaitStrategy(wait.ForLog("Ready to accept connections").WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		t.Skipf("redis container unavailable (Docker not running?): %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })
	endpoint, err := ctr.Endpoint(context.Background(), "")
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	return &nonceRig{
		dsn:    fmt.Sprintf("redis://:%s@%s/0", pw, endpoint),
		pw:     pw,
		prefix: "oidc-nonce-1:",
		clock:  &fixedClock{now: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)},
	}
}

// source builds a replica; a distinct prefix gives it an independent state.
func (r *nonceRig) source(t *testing.T, prefix string, rotate time.Duration) *oidcredis.DPoPNonceSource {
	t.Helper()
	store, err := oidcredis.New(t.Context(),
		oidcredis.WithDSN(r.dsn),
		oidcredis.WithRedisAuth("", r.pw),
		oidcredis.WithDevModeAllowPlaintext(func(string) {}),
		oidcredis.WithKeyPrefix(prefix),
		oidcredis.WithClock(r.clock),
	)
	if err != nil {
		t.Fatalf("oidcredis.New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	src, err := store.DPoPNonceSource(rotate)
	if err != nil {
		t.Fatalf("DPoPNonceSource: %v", err)
	}
	return src
}

func TestRedis_DPoPNonceSource(t *testing.T) {
	rig := newNonceRig(t)
	const rotate = time.Minute

	t.Run("replicas share and rotate", func(t *testing.T) {
		a := rig.source(t, "oidc-share:", rotate)
		b := rig.source(t, "oidc-share:", rotate)

		n1 := a.IssueNonce()
		if n1 == "" {
			t.Fatal("empty nonce")
		}
		if got := b.IssueNonce(); got != n1 {
			t.Fatalf("replica B issued %q, want A's %q", got, n1)
		}
		if !b.Validate(n1) || !a.Validate(n1) {
			t.Fatal("shared nonce rejected")
		}
		if a.Validate("") || a.Validate("forged") {
			t.Fatal("empty or forged nonce accepted")
		}

		rig.clock.now = rig.clock.now.Add(rotate)
		n2 := b.IssueNonce()
		if n2 == n1 {
			t.Fatal("nonce did not rotate")
		}
		if got := a.IssueNonce(); got != n2 {
			t.Fatalf("replica A issued %q after rotation, want %q", got, n2)
		}
		if !a.Validate(n1) || !a.Validate(n2) {
			t.Fatal("current and previous nonce must both validate")
		}

		rig.clock.now = rig.clock.now.Add(rotate)
		n3 := a.IssueNonce()
		if a.Validate(n1) {
			t.Fatal("nonce two rotations old still accepted")
		}
		if !b.Validate(n2) || !b.Validate(n3) {
			t.Fatal("previous and current nonce rejected")
		}
	})

	t.Run("long idle drops the previous value", func(t *testing.T) {
		a := rig.source(t, "oidc-idle:", rotate)
		n1 := a.IssueNonce()
		rig.clock.now = rig.clock.now.Add(3 * rotate)
		n2 := a.IssueNonce()
		if n2 == n1 || a.Validate(n1) {
			t.Fatal("a value older than two intervals must not survive")
		}
	})

	t.Run("concurrent callers agree on one rotation", func(t *testing.T) {
		a := rig.source(t, "oidc-race:", rotate)
		b := rig.source(t, "oidc-race:", rotate)
		a.IssueNonce()
		rig.clock.now = rig.clock.now.Add(rotate)
		var wg sync.WaitGroup
		got := make([]string, 8)
		for i := range got {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if i%2 == 0 {
					got[i] = a.IssueNonce()
				} else {
					got[i] = b.IssueNonce()
				}
			}()
		}
		wg.Wait()
		for _, g := range got {
			if g == "" || g != got[0] {
				t.Fatalf("callers saw different nonces: %v", got)
			}
		}
	})

	t.Run("independent prefixes do not share", func(t *testing.T) {
		a := rig.source(t, "oidc-iso-a:", rotate)
		b := rig.source(t, "oidc-iso-b:", rotate)
		if a.Validate(b.IssueNonce()) {
			t.Fatal("nonce crossed key prefixes")
		}
	})

	t.Run("unreachable Redis fails closed", func(t *testing.T) {
		store, err := oidcredis.New(t.Context(),
			oidcredis.WithDSN(rig.dsn),
			oidcredis.WithRedisAuth("", rig.pw),
			oidcredis.WithDevModeAllowPlaintext(func(string) {}),
			oidcredis.WithKeyPrefix("oidc-down:"),
			oidcredis.WithClock(rig.clock),
		)
		if err != nil {
			t.Fatalf("oidcredis.New: %v", err)
		}
		src, err := store.DPoPNonceSource(rotate)
		if err != nil {
			t.Fatal(err)
		}
		n := src.IssueNonce()
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if got := src.IssueNonce(); got != "" {
			t.Errorf("IssueNonce after close = %q, want empty", got)
		}
		if src.Validate(n) {
			t.Error("Validate accepted a nonce while the state was unreachable")
		}
		if src.Failures() == 0 {
			t.Error("failures not counted")
		}
	})
}
