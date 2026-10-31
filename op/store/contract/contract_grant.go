package contract

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// --- GrantStore --------------------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var grantCases = []subtest{
	{"SaveFind", grantSaveFind},
	{"FindMissing", grantFindMissing},
	{"FindBySubjectClient", grantFindBySubjectClient},
	{"FindBySubjectClientMissing", grantFindBySubjectClientMissing},
	{"ListBySubject", grantListBySubject},
	{"ListBySubjectEmpty", grantListBySubjectEmpty},
	{"ListClientIDsBySubject", grantListClientIDsBySubject},
	{"ListClientIDsBySubjectEmpty", grantListClientIDsBySubjectEmpty},
	{"ListClientIDsBySubjectRejectsInvalidLimit", grantListClientIDsRejectsInvalidLimit},
	{"ListSubjectsByClient", grantListSubjectsByClient},
	{"ListSubjectsByClientEmpty", grantListSubjectsByClientEmpty},
	{"ListSubjectsByClientRejectsInvalidLimit", grantListSubjectsByClientRejectsInvalidLimit},
	{"Delete", grantDelete},
}

func grantSaveFind(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	g := newGrant(b.Now(), "g-1", "sub-1", "client-1")
	if err := b.Store.Grants().Save(ctx, g); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := b.Store.Grants().Find(ctx, "g-1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.Subject != "sub-1" || got.ClientID != "client-1" {
		t.Fatalf("unexpected grant: %+v", got)
	}
}

func grantFindMissing(t *testing.T, f Factory) {
	b := f(t)
	_, err := b.Store.Grants().Find(context.Background(), "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find missing: want ErrNotFound, got %v", err)
	}
}

// grantFindBySubjectClient pins the rule declared on
// [store.GrantStore.FindBySubjectClient]: a backend that retains
// superseded grants for the pair returns the most recent one.
//
// The fixture ids run against recency on purpose — the older grant
// sorts first — because a backend that answers from an unordered index
// scan hands back whichever row its pages yielded first, and an id
// scheme where the newest also happens to sort first lets that pass.
// What it costs when it is wrong is the consent gate: a repeat
// authorization matched against a superseded grant skips the prompt on
// the narrower scope the earlier grant recorded, and the amendment
// lands on a record nothing else reads.
func grantFindBySubjectClient(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	// Several superseded rows rather than one, with ids that sort both
	// before and after the newest: a backend answering from an unordered
	// scan has to be wrong about most of them, so the case does not turn
	// on which row a particular index happened to yield first.
	superseded := []string{"g-aaa", "g-mmm", "g-yyy", "g-zzy"}
	for i, id := range superseded {
		g := newGrant(b.Now().Add(-time.Duration(i+2)*time.Hour), id, "sub", "client")
		g.UpdatedAt = b.Now().Add(-time.Duration(i+2) * time.Hour)
		if err := b.Store.Grants().Save(ctx, g); err != nil {
			t.Fatalf("Save %s: %v", g.ID, err)
		}
	}
	newest := newGrant(b.Now(), "g-zzz", "sub", "client")
	newest.UpdatedAt = b.Now()
	if err := b.Store.Grants().Save(ctx, newest); err != nil {
		t.Fatalf("Save %s: %v", newest.ID, err)
	}
	got, err := b.Store.Grants().FindBySubjectClient(ctx, "sub", "client")
	if err != nil {
		t.Fatalf("FindBySubjectClient: %v", err)
	}
	if got.ID != newest.ID {
		t.Fatalf("FindBySubjectClient returned %q, want the most recent grant %q", got.ID, newest.ID)
	}
}

func grantFindBySubjectClientMissing(t *testing.T, f Factory) {
	b := f(t)
	_, err := b.Store.Grants().FindBySubjectClient(context.Background(), "absent", "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindBySubjectClient missing: want ErrNotFound, got %v", err)
	}
}

func grantListBySubject(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	rows := []*store.Grant{
		newGrant(b.Now(), "g-a", "sub", "client-a"),
		newGrant(b.Now(), "g-b", "sub", "client-b"),
		newGrant(b.Now(), "g-other", "other-sub", "client-a"),
	}
	for _, g := range rows {
		if err := b.Store.Grants().Save(ctx, g); err != nil {
			t.Fatalf("Save %s: %v", g.ID, err)
		}
	}
	got, err := b.Store.Grants().ListBySubject(ctx, "sub")
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	clients := make(map[string]struct{}, len(got))
	for _, g := range got {
		if g.Subject != "sub" {
			t.Fatalf("ListBySubject returned wrong subject: %+v", g)
		}
		clients[g.ClientID] = struct{}{}
	}
	if len(clients) != 2 {
		t.Fatalf("ListBySubject got %d distinct clients, want 2: %+v", len(clients), got)
	}
	if _, ok := clients["client-a"]; !ok {
		t.Fatalf("ListBySubject missing client-a")
	}
	if _, ok := clients["client-b"]; !ok {
		t.Fatalf("ListBySubject missing client-b")
	}
}

func grantListBySubjectEmpty(t *testing.T, f Factory) {
	b := f(t)
	got, err := b.Store.Grants().ListBySubject(context.Background(), "absent")
	if err != nil {
		t.Fatalf("ListBySubject empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListBySubject empty: want 0 entries, got %d", len(got))
	}
}

// requireGrantClientLister skips the current test when the backend's GrantStore
// does not implement the optional [store.GrantClientLister] extension.
func requireGrantClientLister(t *testing.T, s store.Store) store.GrantClientLister {
	t.Helper()
	lister, ok := s.Grants().(store.GrantClientLister)
	if !ok {
		t.Skipf("backend %T does not implement store.GrantClientLister", s.Grants())
	}
	return lister
}

func grantListClientIDsBySubject(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	lister := requireGrantClientLister(t, b.Store)
	rows := []*store.Grant{
		newGrant(b.Now(), "g-c-1", "sub", "client-c"),
		newGrant(b.Now(), "g-a-1", "sub", "client-a"),
		newGrant(b.Now(), "g-a-2", "sub", "client-a"),
		newGrant(b.Now(), "g-b-1", "sub", "client-b"),
		newGrant(b.Now(), "g-other", "other-sub", "client-z"),
	}
	for _, g := range rows {
		if err := b.Store.Grants().Save(ctx, g); err != nil {
			t.Fatalf("Save %s: %v", g.ID, err)
		}
	}
	first, err := lister.ListClientIDsBySubject(ctx, "sub", "", 2)
	if err != nil {
		t.Fatalf("ListClientIDsBySubject first page: %v", err)
	}
	if !slices.Equal(first.ClientIDs, []string{"client-a", "client-b"}) {
		t.Fatalf("first page client IDs = %v", first.ClientIDs)
	}
	if first.NextCursor != "client-b" {
		t.Fatalf("first page next cursor = %q, want client-b", first.NextCursor)
	}
	second, err := lister.ListClientIDsBySubject(ctx, "sub", first.NextCursor, 2)
	if err != nil {
		t.Fatalf("ListClientIDsBySubject second page: %v", err)
	}
	if !slices.Equal(second.ClientIDs, []string{"client-c"}) {
		t.Fatalf("second page client IDs = %v", second.ClientIDs)
	}
	if second.NextCursor != "" {
		t.Fatalf("second page next cursor = %q, want empty", second.NextCursor)
	}
}

func grantListClientIDsBySubjectEmpty(t *testing.T, f Factory) {
	b := f(t)
	lister := requireGrantClientLister(t, b.Store)
	got, err := lister.ListClientIDsBySubject(context.Background(), "absent", "", 2)
	if err != nil {
		t.Fatalf("ListClientIDsBySubject empty: %v", err)
	}
	if len(got.ClientIDs) != 0 || got.NextCursor != "" {
		t.Fatalf("ListClientIDsBySubject empty: got %+v", got)
	}
}

func grantListClientIDsRejectsInvalidLimit(t *testing.T, f Factory) {
	b := f(t)
	lister := requireGrantClientLister(t, b.Store)
	if _, err := lister.ListClientIDsBySubject(
		context.Background(),
		"sub",
		"",
		0,
	); err == nil {
		t.Fatal("ListClientIDsBySubject limit=0: want error")
	}
}

func requireGrantSubjectLister(t *testing.T, s store.Store) store.GrantSubjectLister {
	t.Helper()
	lister, ok := s.Grants().(store.GrantSubjectLister)
	if !ok {
		t.Skipf("backend %T does not implement store.GrantSubjectLister", s.Grants())
	}
	return lister
}

func grantListSubjectsByClient(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	lister := requireGrantSubjectLister(t, b.Store)
	rows := []*store.Grant{
		newGrant(b.Now(), "g-s-c", "subject-c", "client"),
		newGrant(b.Now(), "g-s-a-1", "subject-a", "client"),
		newGrant(b.Now(), "g-s-a-2", "subject-a", "client"),
		newGrant(b.Now(), "g-s-b", "subject-b", "client"),
		newGrant(b.Now(), "g-s-other", "subject-z", "other-client"),
	}
	for _, g := range rows {
		if err := b.Store.Grants().Save(ctx, g); err != nil {
			t.Fatalf("Save %s: %v", g.ID, err)
		}
	}
	revoked := newGrant(b.Now(), "g-s-revoked", "subject-revoked", "client")
	if err := b.Store.Grants().Save(ctx, revoked); err != nil {
		t.Fatalf("Save revoked grant: %v", err)
	}
	if err := b.Store.Grants().Delete(ctx, revoked.ID); err != nil {
		t.Fatalf("Delete revoked grant: %v", err)
	}
	first, err := lister.ListSubjectsByClient(ctx, "client", "", 2)
	if err != nil {
		t.Fatalf("ListSubjectsByClient first page: %v", err)
	}
	if !slices.Equal(first.Subjects, []string{"subject-a", "subject-b"}) {
		t.Fatalf("first page subjects = %v", first.Subjects)
	}
	if first.NextCursor != "subject-b" {
		t.Fatalf("first page next cursor = %q, want subject-b", first.NextCursor)
	}
	second, err := lister.ListSubjectsByClient(ctx, "client", first.NextCursor, 2)
	if err != nil {
		t.Fatalf("ListSubjectsByClient second page: %v", err)
	}
	if !slices.Equal(second.Subjects, []string{"subject-c"}) {
		t.Fatalf("second page subjects = %v", second.Subjects)
	}
	if second.NextCursor != "" {
		t.Fatalf("second page next cursor = %q, want empty", second.NextCursor)
	}
}

func grantListSubjectsByClientEmpty(t *testing.T, f Factory) {
	b := f(t)
	lister := requireGrantSubjectLister(t, b.Store)
	got, err := lister.ListSubjectsByClient(context.Background(), "absent", "", 2)
	if err != nil {
		t.Fatalf("ListSubjectsByClient empty: %v", err)
	}
	if len(got.Subjects) != 0 || got.NextCursor != "" {
		t.Fatalf("ListSubjectsByClient empty: got %+v", got)
	}
}

func grantListSubjectsByClientRejectsInvalidLimit(t *testing.T, f Factory) {
	b := f(t)
	lister := requireGrantSubjectLister(t, b.Store)
	if _, err := lister.ListSubjectsByClient(context.Background(), "client", "", 0); err == nil {
		t.Fatal("ListSubjectsByClient limit=0: want error")
	}
}

func grantDelete(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	g := newGrant(b.Now(), "g-del", "sub", "client")
	if err := b.Store.Grants().Save(ctx, g); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := b.Store.Grants().Delete(ctx, "g-del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	err := b.Store.Grants().Delete(ctx, "g-del")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("repeat Delete: want ErrNotFound, got %v", err)
	}
}
