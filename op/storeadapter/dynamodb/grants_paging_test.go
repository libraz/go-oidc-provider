//go:build testcontainers

package oidcdynamo_test

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
)

// queryRecord is what one Query asked the service for and what it got
// back. Both halves matter: a page bound the service applies is the only
// thing that limits the work, and the rows returned are what the caller
// actually paid for.
type queryRecord struct {
	table string
	index string
	limit int32
	rows  int
}

// countingAPI records every Query the adapter issues, so a test can
// assert on the work asked of the backend rather than on the answer that
// came back. The two differ exactly where a bound is missing: an
// unbounded query returns the same page after reading the whole
// partition.
type countingAPI struct {
	oidcdynamo.API

	mu      sync.Mutex
	queries []queryRecord
}

func (a *countingAPI) Query(
	ctx context.Context,
	in *awsdynamodb.QueryInput,
	opts ...func(*awsdynamodb.Options),
) (*awsdynamodb.QueryOutput, error) {
	out, err := a.API.Query(ctx, in, opts...)
	if err != nil {
		return out, err
	}
	rec := queryRecord{
		table: aws.ToString(in.TableName),
		index: aws.ToString(in.IndexName),
		rows:  len(out.Items),
	}
	if in.Limit != nil {
		rec.limit = *in.Limit
	}
	a.mu.Lock()
	a.queries = append(a.queries, rec)
	a.mu.Unlock()
	return out, nil
}

func (a *countingAPI) reset() {
	a.mu.Lock()
	a.queries = nil
	a.mu.Unlock()
}

// on returns the recorded queries against one table.
func (a *countingAPI) on(table string) []queryRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.DeleteFunc(slices.Clone(a.queries), func(q queryRecord) bool {
		return q.table != table
	})
}

// TestGrants_ListClientIDsBySubjectBoundsBackendReads pins the resource
// bound [store.GrantClientLister] exists for. Back-channel logout calls
// the method once per session termination, so a subject that has
// authorized clients for years would otherwise pay to read its entire
// grant history on every logout — the cost the bound is there to cap.
//
// The assertion is on the queries issued, not on the page returned: an
// implementation that reads every grant and slices the result in memory
// returns exactly the same page.
func TestGrants_ListClientIDsBySubjectBoundsBackendReads(t *testing.T) {
	t.Parallel()

	api := &countingAPI{}
	s, _ := newWrappedStore(t, "grantpage_", func(inner oidcdynamo.API) oidcdynamo.API {
		api.API = inner
		return api
	})
	ctx := t.Context()

	const (
		subject = "sub-many-clients"
		total   = 40
		limit   = 5
	)
	for i := range total {
		g := &store.Grant{
			ID:        fmt.Sprintf("g-%02d", i),
			Subject:   subject,
			ClientID:  fmt.Sprintf("client-%02d", i),
			Scope:     []string{"openid"},
			CreatedAt: contract.Reference,
			UpdatedAt: contract.Reference,
		}
		if err := s.Grants().Save(ctx, g); err != nil {
			t.Fatalf("Save %s: %v", g.ID, err)
		}
	}
	lister, ok := s.Grants().(store.GrantClientLister)
	if !ok {
		t.Fatalf("%T does not implement store.GrantClientLister", s.Grants())
	}
	grantsTable := "grantpage_grants"

	assertBounded := func(t *testing.T, label string) {
		t.Helper()
		issued := api.on(grantsTable)
		if len(issued) == 0 {
			t.Fatalf("%s: no query reached the grants table", label)
		}
		read := 0
		for _, q := range issued {
			if q.index == "" {
				t.Errorf("%s: query ran against the base table rather than an index", label)
			}
			if q.limit != limit+1 {
				t.Errorf("%s: query carried Limit %d, want %d so the service stops at one page past the caller's limit",
					label, q.limit, limit+1)
			}
			read += q.rows
		}
		if read > limit+1 {
			t.Errorf("%s: the backend returned %d rows for a limit of %d; "+
				"a page must cost at most limit+1 rows however many grants the subject holds",
				label, read, limit)
		}
	}

	api.reset()
	first, err := lister.ListClientIDsBySubject(ctx, subject, "", limit)
	if err != nil {
		t.Fatalf("ListClientIDsBySubject first page: %v", err)
	}
	want := []string{"client-00", "client-01", "client-02", "client-03", "client-04"}
	if !slices.Equal(first.ClientIDs, want) {
		t.Fatalf("first page client IDs = %v, want %v", first.ClientIDs, want)
	}
	if first.NextCursor != "client-04" {
		t.Fatalf("first page next cursor = %q, want client-04", first.NextCursor)
	}
	assertBounded(t, "first page")

	// The cursor page has to be bounded too: an implementation that
	// materialises the subject and skips forward in memory reads more the
	// deeper the caller pages.
	api.reset()
	second, err := lister.ListClientIDsBySubject(ctx, subject, first.NextCursor, limit)
	if err != nil {
		t.Fatalf("ListClientIDsBySubject second page: %v", err)
	}
	want = []string{"client-05", "client-06", "client-07", "client-08", "client-09"}
	if !slices.Equal(second.ClientIDs, want) {
		t.Fatalf("second page client IDs = %v, want %v", second.ClientIDs, want)
	}
	assertBounded(t, "cursor page")
}
