package oidcsql_test

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// TestPublicWritesRejectNonJSONValues proves embedder-controlled JSON fields
// return a stable error before a SQL call rather than panicking the request
// goroutine. It covers each public write surface that serialises any values.
func TestPublicWritesRejectNonJSONValues(t *testing.T) {
	t.Parallel()
	b := newSQLiteFactory(t)(t)
	ctx := context.Background()
	now := b.Now()
	users, ok := b.Store.(interface {
		PutUser(context.Context, *store.User) error
	})
	if !ok {
		t.Fatal("SQL store does not expose PutUser")
	}

	cases := []struct {
		name string
		call func() error
	}{
		{
			name: "grant claims function",
			call: func() error {
				return b.Store.Grants().Save(ctx, &store.Grant{
					ID: "invalid-json-grant", Subject: "sub", ClientID: "client",
					Claims: map[string]any{"bad": func() {}}, CreatedAt: now, UpdatedAt: now,
				})
			},
		},
		{
			name: "refresh extra NaN",
			call: func() error {
				return b.Store.RefreshTokens().Save(ctx, &store.RefreshToken{
					ID: "invalid-json-refresh", ClientID: "client", Subject: "sub", GrantID: "grant",
					AccessTokenExtra: map[string]any{"bad": math.NaN()}, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
				})
			},
		},
		{
			name: "user claims cycle",
			call: func() error {
				cycle := map[string]any{}
				cycle["self"] = cycle
				return users.PutUser(ctx, &store.User{Subject: "invalid-json-user", Claims: cycle, UpdatedAt: now})
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := tc.call(); !errors.Is(err, oidcsql.ErrInvalidJSON) {
				t.Fatalf("write error=%v, want ErrInvalidJSON", err)
			}
		})
	}
}
