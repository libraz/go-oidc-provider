package inmem

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
)

type parTestClock struct{ now time.Time }

func (c *parTestClock) Now() time.Time { return c.now }

func TestPARSaveAmortizesFullSweep(t *testing.T) {
	t.Parallel()

	clk := &parTestClock{now: contract.Reference}
	s := New(WithClock(clk))
	ps := s.pars
	ctx := context.Background()

	if err := ps.Save(ctx, &store.PushedAuthRequest{
		URI:       "urn:ietf:params:oauth:request_uri:expired-1",
		ClientID:  "client-1",
		RawParams: []byte("response_type=code"),
		ExpiresAt: clk.now.Add(-time.Second),
		CreatedAt: clk.now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("Save expired: %v", err)
	}
	if len(ps.m) != 1 {
		t.Fatalf("after first save len=%d want 1 (expired record retained until amortized sweep)", len(ps.m))
	}

	for i := uint32(1); i < parFullGCSaveInterval; i++ {
		if err := ps.Save(ctx, &store.PushedAuthRequest{
			URI:       "urn:ietf:params:oauth:request_uri:fresh-" + strconv.Itoa(int(i)),
			ClientID:  "client-1",
			RawParams: []byte("response_type=code"),
			ExpiresAt: clk.now.Add(time.Minute),
			CreatedAt: clk.now,
		}); err != nil {
			t.Fatalf("Save fresh #%d: %v", i, err)
		}
	}
	if _, exists := ps.m[hashKey("urn:ietf:params:oauth:request_uri:expired-1")]; exists {
		t.Fatal("expired PAR survived the amortized full sweep")
	}
	if ps.savesSinceGC != 0 {
		t.Fatalf("savesSinceGC=%d want 0 after sweep", ps.savesSinceGC)
	}
}
