package authorizeendpoint_test

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/op/store"
)

// countingInteractions counts the interaction records the endpoint
// persists through the wrapped store.
type countingInteractions struct {
	store.InteractionStore
	saves atomic.Int64
}

func (c *countingInteractions) Save(ctx context.Context, i *store.Interaction) error {
	c.saves.Add(1)
	return c.InteractionStore.Save(ctx, i)
}

// TestAuthorize_GETQueryCappedLikePOSTBody pins the GET half of the
// request-size ceiling. The query is persisted into the interaction
// record, so a GET is held to the same bound as a POST body: past it the
// request is refused with 414 and nothing is stored; at it the request
// proceeds to an interaction as usual.
func TestAuthorize_GETQueryCappedLikePOSTBody(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name       string
		oversize   bool
		wantStatus int
		wantSaves  int64
	}{
		{name: "query past the ceiling", oversize: true, wantStatus: http.StatusRequestURITooLong},
		{name: "query at the ceiling", wantStatus: http.StatusFound, wantSaves: 1},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			var counter *countingInteractions
			h := newHarness(t, func(d *authorizeendpoint.Deps) {
				counter = &countingInteractions{InteractionStore: d.Interactions}
				d.Interactions = counter
			})
			v := goodAuthorizeValues()
			base := len(v.Encode()) + len("&x_pad=")
			pad := endpointsupport.MaxFormBytes - base
			if row.oversize {
				pad++
			}
			v.Set("x_pad", strings.Repeat("a", pad))
			if got := len(v.Encode()); got != base+pad {
				t.Fatalf("encoded query is %d bytes, want %d", got, base+pad)
			}

			resp := doAuthorizeGET(t, h, v)
			defer resp.Body.Close()
			if resp.StatusCode != row.wantStatus {
				t.Fatalf("status=%d want %d", resp.StatusCode, row.wantStatus)
			}
			if got := counter.saves.Load(); got != row.wantSaves {
				t.Errorf("interaction saves=%d want %d", got, row.wantSaves)
			}
		})
	}
}
