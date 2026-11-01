package clientencjwks_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientencjwks"
	"github.com/libraz/go-oidc-provider/op/store"
)

func TestEncryptNested(t *testing.T) {
	t.Parallel()

	priv := mustRSAKey(t)
	client := &store.Client{
		ID:   "rp",
		JWKs: inlineJWKs(t, rsaPublicJWK(priv, "k1", "enc", "RSA-OAEP-256")),
	}
	r := clientencjwks.New(clientencjwks.Config{})
	const signed = "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"

	t.Run("wraps in a five-segment JWE", func(t *testing.T) {
		t.Parallel()
		out, err := r.EncryptNested(context.Background(), client, "RSA-OAEP-256", "A256GCM", signed)
		if err != nil {
			t.Fatalf("EncryptNested: %v", err)
		}
		if got := strings.Count(out, ".") + 1; got != 5 {
			t.Fatalf("segments=%d want 5: %q", got, out)
		}
	})

	t.Run("no registered encryption returns the signed token", func(t *testing.T) {
		t.Parallel()
		out, err := r.EncryptNested(context.Background(), client, "", "", signed)
		if err != nil || out != signed {
			t.Fatalf("out=%q err=%v want signed, nil", out, err)
		}
	})

	t.Run("resolution failure keeps its sentinel", func(t *testing.T) {
		t.Parallel()
		_, err := r.EncryptNested(context.Background(), client, "RSA-OAEP-256", "BOGUS", signed)
		if err == nil || errors.Is(err, clientencjwks.ErrNoEncryptionConfigured) {
			t.Fatalf("err=%v want a resolution failure", err)
		}
	})
}
