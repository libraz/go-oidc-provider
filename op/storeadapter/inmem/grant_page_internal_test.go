package inmem

import (
	"fmt"
	"testing"
)

func TestGrantClientPageBuilder_HighCardinalityMemoryIsBounded(t *testing.T) {
	t.Parallel()

	const (
		distinctClients = 100_000
		limit           = 8
	)
	builder := newGrantClientPageBuilder("", limit)
	for i := distinctClients - 1; i >= 0; i-- {
		clientID := fmt.Sprintf("client-%06d", i)
		builder.add(clientID)
		builder.add(clientID)
	}
	page := builder.page()
	if builder.peak > limit || len(builder.clientIDs) > limit {
		t.Fatalf(
			"candidate storage peak=%d current=%d, want <=%d",
			builder.peak,
			len(builder.clientIDs),
			limit,
		)
	}
	if len(page.ClientIDs) != limit ||
		page.ClientIDs[0] != "client-000000" ||
		page.ClientIDs[limit-1] != "client-000007" {
		t.Fatalf("page = %+v", page)
	}
	if page.NextCursor != "client-000007" {
		t.Fatalf("next cursor = %q, want client-000007", page.NextCursor)
	}
}
