//go:build testcontainers

package oidcdynamo_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
)

// hookAPI runs a one-shot hook before the next UpdateItem or DeleteItem,
// which is how a test places a competing writer — or DynamoDB's own TTL
// reclaim — between the adapter's read and its conditional write. It
// also records the call sequence and the items every Scan returned, and
// can cap every Scan page.
type hookAPI struct {
	oidcdynamo.API

	mu           sync.Mutex
	beforeUpdate func(context.Context)
	beforeDelete func(context.Context)
	scanLimit    int32
	scans        []*awsdynamodb.ScanInput
	scanned      []map[string]types.AttributeValue
	calls        []string
}

func (a *hookAPI) take(hook *func(context.Context), call string) func(context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, call)
	h := *hook
	*hook = nil
	return h
}

func (a *hookAPI) UpdateItem(
	ctx context.Context,
	in *awsdynamodb.UpdateItemInput,
	opts ...func(*awsdynamodb.Options),
) (*awsdynamodb.UpdateItemOutput, error) {
	if h := a.take(&a.beforeUpdate, "UpdateItem"); h != nil {
		h(ctx)
	}
	return a.API.UpdateItem(ctx, in, opts...)
}

func (a *hookAPI) DeleteItem(
	ctx context.Context,
	in *awsdynamodb.DeleteItemInput,
	opts ...func(*awsdynamodb.Options),
) (*awsdynamodb.DeleteItemOutput, error) {
	if h := a.take(&a.beforeDelete, "DeleteItem"); h != nil {
		h(ctx)
	}
	return a.API.DeleteItem(ctx, in, opts...)
}

func (a *hookAPI) Scan(
	ctx context.Context,
	in *awsdynamodb.ScanInput,
	opts ...func(*awsdynamodb.Options),
) (*awsdynamodb.ScanOutput, error) {
	a.mu.Lock()
	a.calls = append(a.calls, "Scan")
	a.scans = append(a.scans, in)
	if a.scanLimit > 0 {
		capped := *in
		capped.Limit = aws.Int32(a.scanLimit)
		in = &capped
	}
	a.mu.Unlock()
	out, err := a.API.Scan(ctx, in, opts...)
	if err == nil {
		a.mu.Lock()
		a.scanned = append(a.scanned, out.Items...)
		a.mu.Unlock()
	}
	return out, err
}

func newHookedStore(t *testing.T, client *awsdynamodb.Client, prefix string) (*oidcdynamo.Store, *hookAPI) {
	t.Helper()
	api := &hookAPI{API: client}
	s, err := oidcdynamo.New(api,
		oidcdynamo.WithTablePrefix(prefix),
		oidcdynamo.WithClock(&fixedClock{now: contract.Reference}),
	)
	if err != nil {
		t.Fatalf("oidcdynamo.New: %v", err)
	}
	if err := s.CreateTables(t.Context()); err != nil {
		t.Fatalf("CreateTables: %v", err)
	}
	disableEmulatorTTL(t, client, s)
	return s, api
}

// tableNamed returns the physical name of a logical table of s, built
// with prefix.
func tableNamed(t *testing.T, s *oidcdynamo.Store, prefix, logical string) string {
	t.Helper()
	for _, def := range s.TableDefinitions() {
		if def.Name == prefix+logical {
			return def.Name
		}
	}
	t.Fatalf("no table %s%s", prefix, logical)
	return ""
}

// reclaimAll deletes every item of table through the raw client, as
// DynamoDB's TTL janitor would.
func reclaimAll(ctx context.Context, t *testing.T, client *awsdynamodb.Client, table string) {
	t.Helper()
	out, err := client.Scan(ctx, &awsdynamodb.ScanInput{TableName: aws.String(table)})
	if err != nil {
		t.Errorf("scan %s: %v", table, err)
		return
	}
	for _, it := range out.Items {
		if _, err := client.DeleteItem(ctx, &awsdynamodb.DeleteItemInput{
			TableName: aws.String(table),
			Key:       map[string]types.AttributeValue{"pk": it["pk"]},
		}); err != nil {
			t.Errorf("delete from %s: %v", table, err)
		}
	}
}

// consumeCase drives one single-use substore through the reclaim and
// lost-race windows.
type consumeCase struct {
	name  string
	table string
	save  func(ctx context.Context, s *oidcdynamo.Store) error
	// consume reports whether a record came back alongside the error.
	consume func(ctx context.Context, s *oidcdynamo.Store) (bool, error)
	// replayRecord is whether a lost race hands the record back.
	replayRecord bool
}

func consumeCases() []consumeCase {
	expires := contract.Reference.Add(time.Hour)
	return []consumeCase{
		{
			name:  "PushedAuthRequests",
			table: "par_records",
			save: func(ctx context.Context, s *oidcdynamo.Store) error {
				return s.PushedAuthRequests().Save(ctx, &store.PushedAuthRequest{
					URI: "urn:par:reclaim", ClientID: "client-1", ExpiresAt: expires, CreatedAt: contract.Reference,
				})
			},
			consume: func(ctx context.Context, s *oidcdynamo.Store) (bool, error) {
				rec, err := s.PushedAuthRequests().Consume(ctx, "urn:par:reclaim")
				return rec != nil, err
			},
		},
		{
			name:  "RefreshTokens",
			table: "refresh_tokens",
			save: func(ctx context.Context, s *oidcdynamo.Store) error {
				rt := newRotationToken("rt-reclaim", nil)
				rt.GrantID = ""
				return s.RefreshTokens().Save(ctx, rt)
			},
			consume: func(ctx context.Context, s *oidcdynamo.Store) (bool, error) {
				rec, err := s.RefreshTokens().Consume(ctx, "rt-reclaim")
				return rec != nil, err
			},
			replayRecord: true,
		},
		{
			name:  "AuthorizationCodes",
			table: "authorization_codes",
			save: func(ctx context.Context, s *oidcdynamo.Store) error {
				return s.AuthorizationCodes().Save(ctx, &store.AuthorizationCode{
					ID: "code-reclaim", ClientID: "client-1", Subject: "sub-1", GrantID: "grant-1",
					ExpiresAt: expires, CreatedAt: contract.Reference,
				})
			},
			consume: func(ctx context.Context, s *oidcdynamo.Store) (bool, error) {
				rec, err := s.AuthorizationCodes().Consume(ctx, "code-reclaim")
				return rec != nil, err
			},
			replayRecord: true,
		},
	}
}

// TestConsume_ReclaimedBeforeTheWriteReadsAsNotFound pins the absent-record
// answer of every single-use Consume: a record that DynamoDB removed
// between Consume's read and its conditional write is absent, and reports
// [store.ErrNotFound] — not [store.ErrAlreadyConsumed], which the token
// endpoint treats as replay evidence and answers with a revocation cascade.
func TestConsume_ReclaimedBeforeTheWriteReadsAsNotFound(t *testing.T) {
	t.Parallel()
	client := newEmulatorClient(t)
	for i, tc := range consumeCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			prefix := "reclaim" + strconv.Itoa(i) + "_"
			s, api := newHookedStore(t, client, prefix)
			ctx := t.Context()
			if err := tc.save(ctx, s); err != nil {
				t.Fatalf("Save: %v", err)
			}
			table := tableNamed(t, s, prefix, tc.table)
			api.beforeUpdate = func(ctx context.Context) { reclaimAll(ctx, t, client, table) }

			got, err := tc.consume(ctx, s)
			if !errors.Is(err, store.ErrNotFound) || got {
				t.Fatalf("Consume of a reclaimed record: want (nil, ErrNotFound), got record=%v err=%v", got, err)
			}
		})
	}
}

// TestConsume_LostRaceReadsAsAlreadyConsumed is the other half: when a
// concurrent Consume stamps the record between the read and the write,
// the loser reports [store.ErrAlreadyConsumed], with the record where its
// interface owes one on replay and without it for a request_uri.
func TestConsume_LostRaceReadsAsAlreadyConsumed(t *testing.T) {
	t.Parallel()
	client := newEmulatorClient(t)
	for i, tc := range consumeCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			prefix := "race" + strconv.Itoa(i) + "_"
			s, api := newHookedStore(t, client, prefix)
			ctx := t.Context()
			if err := tc.save(ctx, s); err != nil {
				t.Fatalf("Save: %v", err)
			}
			api.beforeUpdate = func(ctx context.Context) {
				if _, err := tc.consume(ctx, s); err != nil {
					t.Errorf("winning Consume: %v", err)
				}
			}

			got, err := tc.consume(ctx, s)
			if !errors.Is(err, store.ErrAlreadyConsumed) {
				t.Fatalf("losing Consume: want ErrAlreadyConsumed, got %v", err)
			}
			if got != tc.replayRecord {
				t.Fatalf("losing Consume returned a record=%v, want %v", got, tc.replayRecord)
			}
		})
	}
}

// TestRefreshConsume_ConcurrentTransactionsLeaveOneWinner pins what the
// token endpoint relies on to turn a concurrent refresh presentation into
// a replay: two transactions that both consumed the token cannot both
// commit, the loser's Commit reports [store.ErrConflict] having written
// nothing, and a Consume issued after it sees the winner's stamp as
// [store.ErrAlreadyConsumed] with the record the cascade starts from.
func TestRefreshConsume_ConcurrentTransactionsLeaveOneWinner(t *testing.T) {
	t.Parallel()
	client := newEmulatorClient(t)
	s, _ := newHookedStore(t, client, "txrace_")
	ctx := t.Context()
	if err := s.RefreshTokens().Save(ctx, newRotationToken("rt-txrace", nil)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	txs := make([]store.Tx, 2)
	for i := range txs {
		tx, err := s.BeginTx(ctx)
		if err != nil {
			t.Fatalf("BeginTx: %v", err)
		}
		if _, err := tx.RefreshTokens().Consume(ctx, "rt-txrace"); err != nil {
			t.Fatalf("tx %d Consume: %v", i, err)
		}
		txs[i] = tx
	}
	if err := txs[0].Commit(); err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	if err := txs[1].Commit(); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second Commit: want ErrConflict, got %v", err)
	}

	rec, err := s.RefreshTokens().Consume(ctx, "rt-txrace")
	if !errors.Is(err, store.ErrAlreadyConsumed) || rec == nil || rec.GrantID != "grant-rotation" {
		t.Fatalf("Consume after the race: want the record with ErrAlreadyConsumed, got %+v, %v", rec, err)
	}
}

// TestGC_SparesTombstoneWidenedAfterTheScan pins that GC's delete, not its
// scan, decides: a tombstone a concurrent cascade widens past the cutoff
// after the scan nominated it stays in place, is not counted, and still
// revokes the grant's tokens.
func TestGC_SparesTombstoneWidenedAfterTheScan(t *testing.T) {
	t.Parallel()
	client := newEmulatorClient(t)
	s, api := newHookedStore(t, client, "gcwiden_")
	ctx := t.Context()
	revocations := s.GrantRevocations()
	cutoff := contract.Reference

	stale := store.GrantTombstone{GrantID: "grant-widened", RevokedAt: cutoff.Add(-2 * time.Hour), ExpiresAt: cutoff.Add(-time.Hour)}
	if err := revocations.RevokeGrant(ctx, stale); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	api.beforeDelete = func(ctx context.Context) {
		widened := stale
		widened.ExpiresAt = cutoff.Add(time.Hour)
		if err := revocations.RevokeGrant(ctx, widened); err != nil {
			t.Errorf("widening RevokeGrant: %v", err)
		}
	}

	n, err := revocations.GC(ctx, cutoff)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n != 0 {
		t.Fatalf("GC counted %d deletions, want 0", n)
	}
	revoked, err := revocations.IsRevoked(ctx, "grant-widened", "", cutoff.Add(-3*time.Hour))
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("GC removed a tombstone that had been widened past the cutoff")
	}
}

// TestGC_DeletesPageByPageFromKeyOnlyScans pins GC's working set: every
// scan page asks the service for the keys of expired items only — live
// items never reach the process — and the page is deleted before the
// next one is fetched, so the sweep never holds more than one page
// however large the table is.
func TestGC_DeletesPageByPageFromKeyOnlyScans(t *testing.T) {
	t.Parallel()
	client := newEmulatorClient(t)
	s, api := newHookedStore(t, client, "gcpage_")
	ctx := t.Context()
	revocations := s.GrantRevocations()
	cutoff := contract.Reference

	expired := []string{"grant-a", "grant-b", "grant-c"}
	for _, id := range expired {
		if err := revocations.RevokeGrant(ctx, store.GrantTombstone{
			GrantID: id, RevokedAt: cutoff.Add(-2 * time.Hour), ExpiresAt: cutoff.Add(-time.Hour),
		}); err != nil {
			t.Fatalf("RevokeGrant %s: %v", id, err)
		}
	}
	live := make([]store.GrantTombstone, 0, 22)
	live = append(live,
		store.GrantTombstone{GrantID: "grant-at-cutoff", RevokedAt: cutoff.Add(-time.Hour), ExpiresAt: cutoff},
		store.GrantTombstone{GrantID: "grant-never", RevokedAt: cutoff.Add(-time.Hour)},
	)
	for i := range 20 {
		live = append(live, store.GrantTombstone{
			GrantID: "grant-live-" + strconv.Itoa(i), RevokedAt: cutoff.Add(-time.Hour), ExpiresAt: cutoff.Add(time.Hour),
		})
	}
	for _, tomb := range live {
		if err := revocations.RevokeGrant(ctx, tomb); err != nil {
			t.Fatalf("RevokeGrant %s: %v", tomb.GrantID, err)
		}
	}
	api.mu.Lock()
	api.scanLimit = 1
	api.calls = nil
	api.scanned = nil
	api.mu.Unlock()

	n, err := revocations.GC(ctx, cutoff)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n != len(expired) {
		t.Fatalf("GC deleted %d, want %d", n, len(expired))
	}
	for _, in := range api.scans {
		if aws.ToString(in.ProjectionExpression) == "" || aws.ToString(in.FilterExpression) == "" {
			t.Fatalf("GC scanned without a key projection and expiry filter: %+v", in)
		}
	}
	t.Logf("table %d items; GC received %d", len(expired)+len(live), len(api.scanned))
	if len(api.scanned) != len(expired) {
		t.Fatalf("GC received %d items from its scans, want only the %d expired", len(api.scanned), len(expired))
	}
	for _, it := range api.scanned {
		if _, ok := it["pk"]; !ok || len(it) != 1 {
			t.Fatalf("GC received attributes beyond the key: %v", it)
		}
	}
	firstDelete, lastScan := -1, -1
	for i, call := range api.calls {
		switch {
		case call == "DeleteItem" && firstDelete < 0:
			firstDelete = i
		case call == "Scan":
			lastScan = i
		}
	}
	if firstDelete < 0 || firstDelete > lastScan {
		t.Fatalf("GC fetched every page before deleting: calls %v", api.calls)
	}
	for _, id := range []string{"grant-at-cutoff", "grant-never"} {
		revoked, err := revocations.IsRevoked(ctx, id, "", cutoff.Add(-2*time.Hour))
		if err != nil || !revoked {
			t.Fatalf("GC removed live tombstone %s: revoked=%v err=%v", id, revoked, err)
		}
	}
}

// TestRefreshGrantRoots_CarryTheLatestRootExpiryAsTTL pins that a grant's
// root list is reclaimable: it carries a TTL no earlier than the latest
// expiry among the roots it lists, through the plain and the
// transactional Save alike, and none while a listed root never expires.
func TestRefreshGrantRoots_CarryTheLatestRootExpiryAsTTL(t *testing.T) {
	t.Parallel()
	client := newEmulatorClient(t)
	s, _ := newHookedStore(t, client, "roots_")
	ctx := t.Context()
	table := tableNamed(t, s, "roots_", "refresh_tokens")

	ttlOf := func(grantID string) (int64, bool) {
		t.Helper()
		out, err := client.GetItem(ctx, &awsdynamodb.GetItemInput{
			TableName:      aws.String(table),
			Key:            map[string]types.AttributeValue{"pk": &types.AttributeValueMemberS{Value: "grant-roots#" + grantID}},
			ConsistentRead: aws.Bool(true),
		})
		if err != nil || out.Item == nil {
			t.Fatalf("read root list of %s: item=%v err=%v", grantID, out.Item != nil, err)
		}
		n, ok := out.Item["ttl"].(*types.AttributeValueMemberN)
		if !ok {
			return 0, false
		}
		v, err := strconv.ParseInt(n.Value, 10, 64)
		if err != nil {
			t.Fatalf("ttl %q: %v", n.Value, err)
		}
		return v, true
	}
	root := func(id string, expiresAt time.Time) *store.RefreshToken {
		rt := newRotationToken(id, nil)
		rt.GrantID = "grant-" + id[:1]
		rt.ExpiresAt = expiresAt
		return rt
	}
	later := contract.Reference.Add(3 * time.Hour)
	earlier := contract.Reference.Add(time.Hour)

	if err := s.RefreshTokens().Save(ctx, root("a-late", later)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.RefreshTokens().Save(ctx, root("a-early", earlier)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if ttl, ok := ttlOf("grant-a"); !ok || ttl < later.Unix() {
		t.Fatalf("plain Save: root list ttl=%d present=%v, want >= %d", ttl, ok, later.Unix())
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.RefreshTokens().Save(ctx, root("b-tx", later)); err != nil {
		t.Fatalf("tx Save: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if ttl, ok := ttlOf("grant-b"); !ok || ttl < later.Unix() {
		t.Fatalf("tx Save: root list ttl=%d present=%v, want >= %d", ttl, ok, later.Unix())
	}

	if err := s.RefreshTokens().Save(ctx, root("c-bounded", later)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.RefreshTokens().Save(ctx, root("c-forever", time.Time{})); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if ttl, ok := ttlOf("grant-c"); ok {
		t.Fatalf("root list with a never-expiring root carries ttl=%d", ttl)
	}
}
