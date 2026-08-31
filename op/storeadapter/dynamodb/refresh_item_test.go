//go:build testcontainers

package oidcdynamo_test

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
)

// TestRefreshTokens_ItemsCarryOnlyQueriedAttributes pins the write cost
// of the busiest table in a deployment. A refresh rotation writes one
// item per issued token, and every attribute projected beside the
// document is copied into each index that keys on it. An attribute kept
// only for an index nothing queries is paid for on every rotation and
// returns nothing.
//
// The projected set is asserted as a whole rather than by naming the
// attribute that was removed, so the next attribute added without a
// reader is caught the same way.
func TestRefreshTokens_ItemsCarryOnlyQueriedAttributes(t *testing.T) {
	t.Parallel()

	s, client := newWrappedStore(t, "refattr_", nil)
	ctx := t.Context()

	parent := "refresh-parent"
	if err := s.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID:        parent,
		ClientID:  "client-attr",
		GrantID:   "grant-attr",
		Subject:   "sub-attr",
		Scope:     []string{"openid"},
		ExpiresAt: contract.Reference.Add(24 * time.Hour),
		CreatedAt: contract.Reference,
	}); err != nil {
		t.Fatalf("Save parent: %v", err)
	}
	if err := s.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID:        "refresh-child",
		ClientID:  "client-attr",
		GrantID:   "grant-attr",
		Subject:   "sub-attr",
		Scope:     []string{"openid"},
		ParentID:  &parent,
		ExpiresAt: contract.Reference.Add(24 * time.Hour),
		CreatedAt: contract.Reference,
	}); err != nil {
		t.Fatalf("Save child: %v", err)
	}

	// The attributes a stored refresh item may carry: its key, the
	// document, the two expiry renderings, the three index keys, the two
	// state flags, and the record version the transactional writes
	// condition on.
	allowed := map[string]bool{
		"pk":             true,
		"doc":            true,
		"expires_at":     true,
		"ttl":            true,
		"grant_id":       true,
		"client_id":      true,
		"parent_id":      true,
		"consumed_at":    true,
		"revoked":        true,
		"record_version": true,
		"retry_response": true,
	}
	out, err := client.Scan(ctx, &awsdynamodb.ScanInput{
		TableName:      aws.String("refattr_refresh_tokens"),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		t.Fatalf("scan refresh tokens: %v", err)
	}
	if len(out.Items) != 2 {
		t.Fatalf("scan returned %d items, want the 2 saved tokens", len(out.Items))
	}
	for _, item := range out.Items {
		for attr := range item {
			if !allowed[attr] {
				t.Errorf("a stored refresh item carries attribute %q, which no index or condition reads; "+
					"an attribute written on every rotation has to be read by something", attr)
			}
		}
	}
}
