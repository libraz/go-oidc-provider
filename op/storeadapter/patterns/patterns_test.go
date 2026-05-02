package patterns_test

import (
	databasesql "database/sql"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// fixedNow is the wall-clock instant the table-driven cases pivot
// around. It is intentionally not tied to contract.Reference so the
// patterns package can be tested independently of the contract
// harness.
var fixedNow = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

func TestIsExpiredStrict(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		t    time.Time
		want bool
	}{
		{"zero is live", time.Time{}, false},
		{"strictly before now is expired", fixedNow.Add(-time.Second), true},
		{"exactly now is live", fixedNow, false},
		{"strictly after now is live", fixedNow.Add(time.Second), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := patterns.IsExpiredStrict(tc.t, fixedNow); got != tc.want {
				t.Fatalf("IsExpiredStrict(%v, now)=%v want %v", tc.t, got, tc.want)
			}
		})
	}
}

func TestIsExpiredInclusive(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		t    time.Time
		want bool
	}{
		{"zero is live", time.Time{}, false},
		{"strictly before now is expired", fixedNow.Add(-time.Second), true},
		{"exactly now is expired", fixedNow, true},
		{"strictly after now is live", fixedNow.Add(time.Second), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := patterns.IsExpiredInclusive(tc.t, fixedNow); got != tc.want {
				t.Fatalf("IsExpiredInclusive(%v, now)=%v want %v", tc.t, got, tc.want)
			}
		})
	}
}

func TestMapSQLNotFound(t *testing.T) {
	t.Parallel()
	other := errors.New("driver: connection refused")
	cases := []struct {
		name string
		in   error
		want error
	}{
		{"nil pass-through", nil, nil},
		{"ErrNoRows mapped", databasesql.ErrNoRows, store.ErrNotFound},
		{"other error preserved", other, other},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := patterns.MapSQLNotFound(tc.in, databasesql.ErrNoRows)
			if !errors.Is(got, tc.want) {
				t.Fatalf("MapSQLNotFound(%v)=%v want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestMapRedisNotFound(t *testing.T) {
	t.Parallel()
	// Synthesise a sentinel value that mirrors redis.Nil's role
	// without importing the redis client package: the helper compares
	// via errors.Is, so any sentinel behaves the same.
	redisNil := errors.New("redis: nil")
	other := errors.New("redis: connection refused")
	cases := []struct {
		name string
		in   error
		want error
	}{
		{"nil pass-through", nil, nil},
		{"redis.Nil mapped", redisNil, store.ErrNotFound},
		{"other error preserved", other, other},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := patterns.MapRedisNotFound(tc.in, redisNil)
			if !errors.Is(got, tc.want) {
				t.Fatalf("MapRedisNotFound(%v)=%v want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestDedupBatch(t *testing.T) {
	t.Parallel()
	t.Run("nil input", func(t *testing.T) {
		t.Parallel()
		got := patterns.DedupBatch[string](nil)
		if got != nil {
			t.Fatalf("DedupBatch(nil)=%v want nil", got)
		}
	})
	t.Run("empty input", func(t *testing.T) {
		t.Parallel()
		got := patterns.DedupBatch([]string{})
		if got == nil {
			t.Fatal("DedupBatch([]string{}) must return a non-nil empty slice")
		}
		if len(got) != 0 {
			t.Fatalf("DedupBatch([]string{})=%v want []", got)
		}
	})
	t.Run("preserves first occurrence", func(t *testing.T) {
		t.Parallel()
		in := []string{"a", "b", "a", "c", "b", "d"}
		got := patterns.DedupBatch(in)
		want := []string{"a", "b", "c", "d"}
		if len(got) != len(want) {
			t.Fatalf("DedupBatch len=%d want %d (got=%v)", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("DedupBatch[%d]=%q want %q (full=%v)", i, got[i], want[i], got)
			}
		}
	})
	t.Run("works with int", func(t *testing.T) {
		t.Parallel()
		got := patterns.DedupBatch([]int{1, 2, 2, 3, 1})
		want := []int{1, 2, 3}
		if len(got) != len(want) {
			t.Fatalf("DedupBatch len=%d want %d (got=%v)", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("DedupBatch[%d]=%d want %d", i, got[i], want[i])
			}
		}
	})
}

func TestPaginate(t *testing.T) {
	t.Parallel()
	in := []string{"a", "b", "c", "d", "e"}
	cases := []struct {
		name           string
		offset         int
		pageSize       int
		wantPage       []string
		wantNextOffset int
		wantHasMore    bool
	}{
		{"first page", 0, 2, []string{"a", "b"}, 2, true},
		{"middle page", 2, 2, []string{"c", "d"}, 4, true},
		{"last page", 4, 2, []string{"e"}, 5, false},
		{"page size larger than remaining", 3, 10, []string{"d", "e"}, 5, false},
		{"page size zero returns all", 0, 0, in, 5, false},
		{"negative offset clamps to zero", -3, 2, []string{"a", "b"}, 2, true},
		{"offset past end", 99, 2, nil, 5, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			page, next, hasMore := patterns.Paginate(in, tc.offset, tc.pageSize)
			if len(page) != len(tc.wantPage) {
				t.Fatalf("Paginate page len=%d want %d (got=%v)", len(page), len(tc.wantPage), page)
			}
			for i := range tc.wantPage {
				if page[i] != tc.wantPage[i] {
					t.Fatalf("Paginate page[%d]=%q want %q", i, page[i], tc.wantPage[i])
				}
			}
			if next != tc.wantNextOffset {
				t.Fatalf("Paginate next=%d want %d", next, tc.wantNextOffset)
			}
			if hasMore != tc.wantHasMore {
				t.Fatalf("Paginate hasMore=%v want %v", hasMore, tc.wantHasMore)
			}
		})
	}
}
