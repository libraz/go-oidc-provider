package contract

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// --- AuthorizationCodeStore --------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var authCodeCases = []subtest{
	{"SaveFind", authCodeSaveFind},
	{"ConsumeOnce", authCodeConsumeOnce},
	{"FindMissing", authCodeFindMissing},
	{"ConsumeMissing", authCodeConsumeMissing},
	{"Expired", authCodeExpired},
	{"DuplicateSave", authCodeDuplicateSave},
}

func authCodeSaveFind(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	code := newAuthCode(b.Now(), "ac-1")
	code.AuthTime = b.Now().Add(-time.Minute)
	code.ACR = "urn:acr:pwd"
	code.AMR = []string{"pwd", "otp"}
	code.AuthorizationDetails = []map[string]any{{"type": "payment", "amount": "100"}}
	code.Claims = recordedClaimsRequest()
	code.AuthorizationRecorded = true
	if err := b.Store.AuthorizationCodes().Save(ctx, code); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := b.Store.AuthorizationCodes().Find(ctx, "ac-1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.ID != "ac-1" || got.ConsumedAt != nil {
		t.Fatalf("unexpected code: %+v", got)
	}
	assertAuthCodeAuthorization(t, got, code)
}

// assertAuthCodeAuthorization requires the per-authorization state to
// round-trip, or a backend to drop all of it so the row reads back
// unrecorded and the token endpoint falls back to the shared grant. A
// partial round-trip is a defect.
func assertAuthCodeAuthorization(t *testing.T, got, want *store.AuthorizationCode) {
	t.Helper()
	if got.AuthorizationRecorded {
		if !got.AuthTime.Equal(want.AuthTime) || got.ACR != want.ACR ||
			!reflect.DeepEqual(got.AMR, want.AMR) ||
			!reflect.DeepEqual(got.AuthorizationDetails, want.AuthorizationDetails) ||
			!reflect.DeepEqual(got.Claims, want.Claims) {
			t.Fatalf("authorization state mismatch: got auth_time=%v acr=%q amr=%v details=%v claims=%v",
				got.AuthTime, got.ACR, got.AMR, got.AuthorizationDetails, got.Claims)
		}
		return
	}
	if !got.AuthTime.IsZero() || got.ACR != "" || len(got.AMR) != 0 ||
		len(got.AuthorizationDetails) != 0 || len(got.Claims) != 0 {
		t.Fatalf("unrecorded row carries authorization state: auth_time=%v acr=%q amr=%v details=%v claims=%v",
			got.AuthTime, got.ACR, got.AMR, got.AuthorizationDetails, got.Claims)
	}
}

func authCodeConsumeOnce(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	code := newAuthCode(b.Now(), "ac-2")
	if err := b.Store.AuthorizationCodes().Save(ctx, code); err != nil {
		t.Fatalf("Save: %v", err)
	}
	first, err := b.Store.AuthorizationCodes().Consume(ctx, "ac-2")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if first.ConsumedAt == nil {
		t.Fatal("first Consume returned record with nil ConsumedAt")
	}
	_, err = b.Store.AuthorizationCodes().Consume(ctx, "ac-2")
	if !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second Consume: want ErrAlreadyConsumed, got %v", err)
	}
	got, err := b.Store.AuthorizationCodes().Find(ctx, "ac-2")
	if err != nil {
		t.Fatalf("Find after consume: %v", err)
	}
	if got.ConsumedAt == nil {
		t.Fatalf("Find after consume returned ConsumedAt=nil: %+v", got)
	}
}

func authCodeFindMissing(t *testing.T, f Factory) {
	b := f(t)
	_, err := b.Store.AuthorizationCodes().Find(context.Background(), "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find missing: want ErrNotFound, got %v", err)
	}
}

func authCodeConsumeMissing(t *testing.T, f Factory) {
	b := f(t)
	_, err := b.Store.AuthorizationCodes().Consume(context.Background(), "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Consume missing: want ErrNotFound, got %v", err)
	}
}

func authCodeExpired(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	code := newAuthCode(b.Now(), "ac-exp")
	code.ExpiresAt = b.Now().Add(-time.Hour)
	if err := b.Store.AuthorizationCodes().Save(ctx, code); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := b.Store.AuthorizationCodes().Find(ctx, "ac-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find expired: want ErrNotFound, got %v", err)
	}
	if _, err := b.Store.AuthorizationCodes().Consume(ctx, "ac-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Consume expired: want ErrNotFound, got %v", err)
	}
}

func authCodeDuplicateSave(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	code := newAuthCode(b.Now(), "ac-dup")
	if err := b.Store.AuthorizationCodes().Save(ctx, code); err != nil {
		t.Fatalf("Save: %v", err)
	}
	err := b.Store.AuthorizationCodes().Save(ctx, code)
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate Save: want ErrAlreadyExists, got %v", err)
	}
}
