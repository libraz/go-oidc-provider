//go:build testcontainers

package oidcdynamo_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// laggingIndexAPI stands in for a Global Secondary Index that has not yet
// caught up with the base table: every index Query leaves out the items
// hidden through it. Base-table reads, scans and writes pass through
// untouched, so the only thing it removes is what replication lag would.
type laggingIndexAPI struct {
	oidcdynamo.API

	mu     sync.Mutex
	hidden map[string]bool
}

// hide keeps the tokens with the given ids out of every index query.
func (a *laggingIndexAPI) hide(ids ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, id := range ids {
		a.hidden[patterns.Digest(id)] = true
	}
}

func (a *laggingIndexAPI) Query(
	ctx context.Context,
	in *awsdynamodb.QueryInput,
	opts ...func(*awsdynamodb.Options),
) (*awsdynamodb.QueryOutput, error) {
	out, err := a.API.Query(ctx, in, opts...)
	if err != nil || in.IndexName == nil {
		return out, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	visible := out.Items[:0]
	for _, it := range out.Items {
		if pk, ok := it["pk"].(*types.AttributeValueMemberS); ok && a.hidden[pk.Value] {
			continue
		}
		visible = append(visible, it)
	}
	out.Items = visible
	return out, nil
}

// newLaggingStore builds an isolated store on client whose index reads
// go through a [laggingIndexAPI].
func newLaggingStore(t *testing.T, client *awsdynamodb.Client, prefix string) (*oidcdynamo.Store, *laggingIndexAPI) {
	t.Helper()
	api := &laggingIndexAPI{API: client, hidden: map[string]bool{}}
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

// saveChain stores root → child → grandchild through the plain Save path
// and returns their ids in that order.
func saveChain(t *testing.T, s *oidcdynamo.Store, prefix string) []string {
	t.Helper()
	root := newRotationToken(prefix+"-root", nil)
	child := newRotationToken(prefix+"-child", &root.ID)
	grandchild := newRotationToken(prefix+"-grandchild", &child.ID)
	for _, rt := range []*store.RefreshToken{root, child, grandchild} {
		if err := s.RefreshTokens().Save(t.Context(), rt); err != nil {
			t.Fatalf("Save %s: %v", rt.ID, err)
		}
	}
	return []string{root.ID, child.ID, grandchild.ID}
}

// saveBystander stores a live token under another grant and client, so a
// cascade that reached past its own scope is caught.
func saveBystander(t *testing.T, s *oidcdynamo.Store, id string) {
	t.Helper()
	rt := newRotationToken(id, nil)
	rt.GrantID = "grant-bystander"
	rt.ClientID = "client-bystander"
	if err := s.RefreshTokens().Save(t.Context(), rt); err != nil {
		t.Fatalf("Save %s: %v", id, err)
	}
}

// requireRevoked asserts a token reads back retired by a cascade: gone,
// or consumed with the revoked flag set.
func requireRevoked(t *testing.T, s *oidcdynamo.Store, id string) {
	t.Helper()
	got, err := s.RefreshTokens().Find(t.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return
	}
	if err != nil {
		t.Fatalf("Find %s: %v", id, err)
	}
	if got.ConsumedAt == nil || !got.Revoked {
		t.Fatalf("token %s escaped the cascade: ConsumedAt=%v Revoked=%v", id, got.ConsumedAt, got.Revoked)
	}
}

func requireLive(t *testing.T, s *oidcdynamo.Store, id string) {
	t.Helper()
	got, err := s.RefreshTokens().Find(t.Context(), id)
	if err != nil {
		t.Fatalf("Find %s: %v", id, err)
	}
	if got.ConsumedAt != nil || got.Revoked {
		t.Fatalf("token %s outside the cascade was retired: %+v", id, got)
	}
}

// TestRefreshCascades_ReachRecordsTheIndexHasNotCaughtUp pins the
// property the cascades owe the replay and revocation paths: a token
// whose Save returned before the cascade started is retired by it, even
// when the index the cascade could enumerate it through does not show
// it yet. Every token of the chain is hidden from the indexes here, so
// only a strongly consistent enumeration can reach them.
func TestRefreshCascades_ReachRecordsTheIndexHasNotCaughtUp(t *testing.T) {
	t.Parallel()
	client := newEmulatorClient(t)

	cascades := []struct {
		name   string
		revoke func(ctx context.Context, s *oidcdynamo.Store, chain []string) error
	}{
		{"RevokeChain", func(ctx context.Context, s *oidcdynamo.Store, chain []string) error {
			return s.RefreshTokens().RevokeChain(ctx, chain[0])
		}},
		{"RevokeByGrant", func(ctx context.Context, s *oidcdynamo.Store, _ []string) error {
			return s.RefreshTokens().RevokeByGrant(ctx, "grant-rotation")
		}},
		{"RevokeByClient", func(ctx context.Context, s *oidcdynamo.Store, _ []string) error {
			revoker, ok := s.RefreshTokens().(store.RevokeByClient)
			if !ok {
				t.Fatalf("%T does not implement store.RevokeByClient", s.RefreshTokens())
			}
			return revoker.RevokeByClient(ctx, "client-rotation")
		}},
	}
	for i, tc := range cascades {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, api := newLaggingStore(t, client, fmt.Sprintf("lag%d_", i))
			chain := saveChain(t, s, "lag")
			saveBystander(t, s, "lag-bystander")
			api.hide(chain...)

			if err := tc.revoke(t.Context(), s, chain); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			for _, id := range chain {
				requireRevoked(t, s, id)
			}
			requireLive(t, s, "lag-bystander")
		})
	}
}

// TestRefreshCascades_ReachRotationsTheIndexHasNotCaughtUp is the same
// property for the two ways the token endpoint writes a rotation: inside
// a transaction that consumes the predecessor, and through the
// grace-window write that carries the sealed retry response.
func TestRefreshCascades_ReachRotationsTheIndexHasNotCaughtUp(t *testing.T) {
	t.Parallel()
	client := newEmulatorClient(t)
	s, api := newLaggingStore(t, client, "lagrot_")
	ctx := t.Context()

	root := newRotationToken("lagrot-root", nil)
	if err := s.RefreshTokens().Save(ctx, root); err != nil {
		t.Fatalf("Save root: %v", err)
	}
	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if _, err := tx.RefreshTokens().Consume(ctx, root.ID); err != nil {
		t.Fatalf("tx Consume: %v", err)
	}
	child := newRotationToken("lagrot-child", &root.ID)
	if err := tx.RefreshTokens().Save(ctx, child); err != nil {
		t.Fatalf("tx Save child: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := s.RefreshTokens().Consume(ctx, child.ID); err != nil {
		t.Fatalf("Consume child: %v", err)
	}
	grandchild := newRotationToken("lagrot-grandchild", &child.ID)
	retry := requireRetryStore(t, s.RefreshTokens())
	if err := retry.SaveRotationWithRetry(ctx, grandchild, []byte("sealed")); err != nil {
		t.Fatalf("SaveRotationWithRetry: %v", err)
	}
	api.hide(root.ID, child.ID, grandchild.ID)

	if err := s.RefreshTokens().RevokeChain(ctx, root.ID); err != nil {
		t.Fatalf("RevokeChain: %v", err)
	}
	for _, id := range []string{root.ID, child.ID, grandchild.ID} {
		requireRevoked(t, s, id)
	}
}

// TestRefreshCascades_TxRevokeChainReachesUnindexedChain drives the
// staged form of the chain walk, which reads its links through the
// transaction's buffer rather than through the revoking write.
func TestRefreshCascades_TxRevokeChainReachesUnindexedChain(t *testing.T) {
	t.Parallel()
	client := newEmulatorClient(t)
	s, api := newLaggingStore(t, client, "lagtx_")
	ctx := t.Context()

	chain := saveChain(t, s, "lagtx")
	api.hide(chain...)

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.RefreshTokens().RevokeChain(ctx, chain[0]); err != nil {
		t.Fatalf("tx RevokeChain: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	for _, id := range chain {
		requireRevoked(t, s, id)
	}
}

// TestRefreshCascades_TxRevokeChainConflictsWithConcurrentRotation pins
// the commit-time half of the staged walk: a rotation that joins a node's
// children after the transaction read them must fail the commit, since
// the walk never saw the descendant and would otherwise leave it live.
func TestRefreshCascades_TxRevokeChainConflictsWithConcurrentRotation(t *testing.T) {
	t.Parallel()
	client := newEmulatorClient(t)
	s, _ := newLaggingStore(t, client, "lagrace_")
	ctx := t.Context()

	root := newRotationToken("lagrace-root", nil)
	if err := s.RefreshTokens().Save(ctx, root); err != nil {
		t.Fatalf("Save root: %v", err)
	}
	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.RefreshTokens().RevokeChain(ctx, root.ID); err != nil {
		t.Fatalf("tx RevokeChain: %v", err)
	}
	late := newRotationToken("lagrace-late", &root.ID)
	if err := s.RefreshTokens().Save(ctx, late); err != nil {
		t.Fatalf("Save onto a parent the open transaction has not committed yet: %v", err)
	}
	if err := tx.Commit(); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Commit after a rotation joined the walked node: want ErrConflict, got %v", err)
	}
}

// TestRefreshCascades_LegacyRecordsReachedThroughIndexes pins the other
// half of the union. Records written before the adapter stored cascade
// links carry no children set and no root-list entry; the cascades must
// still reach them through the indexes they used to rely on alone.
func TestRefreshCascades_LegacyRecordsReachedThroughIndexes(t *testing.T) {
	t.Parallel()
	client := newEmulatorClient(t)

	cascades := []struct {
		name   string
		revoke func(ctx context.Context, s *oidcdynamo.Store, chain []string) error
	}{
		{"RevokeChain", func(ctx context.Context, s *oidcdynamo.Store, chain []string) error {
			return s.RefreshTokens().RevokeChain(ctx, chain[0])
		}},
		{"RevokeByGrant", func(ctx context.Context, s *oidcdynamo.Store, _ []string) error {
			return s.RefreshTokens().RevokeByGrant(ctx, "grant-rotation")
		}},
		{"RevokeByClient", func(ctx context.Context, s *oidcdynamo.Store, _ []string) error {
			return s.RefreshTokens().(store.RevokeByClient).RevokeByClient(ctx, "client-rotation")
		}},
	}
	for i, tc := range cascades {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			prefix := fmt.Sprintf("legacy%d_", i)
			s, _ := newLaggingStore(t, client, prefix)
			chain := saveChain(t, s, "legacy")
			saveBystander(t, s, "legacy-bystander")
			stripCascadeLinks(t, client, prefix+"refresh_tokens", chain, "grant-rotation")

			if err := tc.revoke(t.Context(), s, chain); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			for _, id := range chain {
				requireRevoked(t, s, id)
			}
			requireLive(t, s, "legacy-bystander")
		})
	}
}

// stripCascadeLinks rewrites stored tokens into the shape a record written
// before the cascade links has: no children set on any token, and no root
// list for the grant.
func stripCascadeLinks(t *testing.T, client *awsdynamodb.Client, table string, ids []string, grantID string) {
	t.Helper()
	for _, id := range ids {
		_, err := client.UpdateItem(t.Context(), &awsdynamodb.UpdateItemInput{
			TableName:                aws.String(table),
			Key:                      map[string]types.AttributeValue{"pk": &types.AttributeValueMemberS{Value: patterns.Digest(id)}},
			UpdateExpression:         aws.String("REMOVE #children"),
			ExpressionAttributeNames: map[string]string{"#children": "children"},
		})
		if err != nil {
			t.Fatalf("strip children of %s: %v", id, err)
		}
	}
	_, err := client.DeleteItem(t.Context(), &awsdynamodb.DeleteItemInput{
		TableName: aws.String(table),
		Key:       map[string]types.AttributeValue{"pk": &types.AttributeValueMemberS{Value: "grant-roots#" + grantID}},
	})
	if err != nil {
		t.Fatalf("delete root list of %s: %v", grantID, err)
	}
	out, err := client.Scan(t.Context(), &awsdynamodb.ScanInput{
		TableName:      aws.String(table),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		t.Fatalf("scan %s: %v", table, err)
	}
	for _, it := range out.Items {
		if _, linked := it["children"]; linked {
			t.Fatalf("item %v still carries a children set", it["pk"])
		}
		if pk, _ := it["pk"].(*types.AttributeValueMemberS); pk != nil && pk.Value == "grant-roots#"+grantID {
			t.Fatalf("the root list of %s is still stored", grantID)
		}
	}
}
