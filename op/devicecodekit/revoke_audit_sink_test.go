package devicecodekit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/redact"
	"github.com/libraz/go-oidc-provider/op/devicecodekit"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// The revocation record's cascade tallies are the evidence public
// godoc tells an operator to read when deciding whether a revocation
// reached every credential minted from the device code. They are
// counts and booleans, but their key names contain "token", which the
// key-name redactor matches by substring. Every other test here
// inspects an in-process Emitter that never crosses that boundary, so
// this one drives the production sink pair (audit.Slog over a
// redact-wrapped handler) instead.
func TestRevoke_CascadeTalliesSurviveToSlogSink(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)

	s := inmem.New(inmem.WithClock(fixedClock{now: now}))
	ds := s.DeviceCodes()
	const grantID = "dev-audit-sink"
	if err := ds.Save(ctx, &store.DeviceCode{
		ID:        grantID,
		UserCode:  "SINKCODE",
		ClientID:  "client-1",
		Status:    store.DeviceCodeStatusPending,
		IssuedAt:  now,
		ExpiresAt: now.Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("Save device code: %v", err)
	}
	if err := ds.Approve(ctx, grantID, "user-1", now); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, err := ds.Consume(ctx, grantID); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if err := s.AccessTokens().Register(ctx, store.AccessTokenRecord{
		JTI:       "jwt-sink",
		GrantID:   grantID,
		ClientID:  "client-1",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Register JWT shadow: %v", err)
	}
	if err := s.OpaqueAccessTokens().Save(ctx, &store.OpaqueAccessToken{
		ID:        "opaque-sink",
		GrantID:   grantID,
		ClientID:  "client-1",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save opaque access token: %v", err)
	}
	if err := s.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID:        "refresh-sink",
		GrantID:   grantID,
		ClientID:  "client-1",
		Subject:   "user-1",
		Origin:    store.RefreshOriginDeviceCode,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save refresh token: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(redact.WrapHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	deps := &devicecodekit.Deps{
		DeviceCodes:        ds,
		AccessTokens:       s.AccessTokens(),
		OpaqueAccessTokens: s.OpaqueAccessTokens(),
		RefreshTokens:      s.RefreshTokens(),
		AccessTokenTTL:     15 * time.Minute,
		Clock:              fixedClock{now: now},
		Audit:              audit.Slog(logger),
	}
	if err := devicecodekit.Revoke(ctx, deps, grantID, devicecodekit.DenyReasonUserRevokedDevice); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	extras := loggedExtras(t, buf.Bytes(), "device_code.revoked")
	for key, want := range map[string]any{
		"revoked_access_tokens":          float64(1),
		"revoked_opaque_access_tokens":   float64(1),
		"refresh_token_cascade_complete": true,
	} {
		if got := extras[key]; got != want {
			t.Errorf("extras.%s reached the sink as %v, want %v; the cascade evidence is unreadable",
				key, got, want)
		}
	}
}

// loggedExtras returns the "extras" group of the logged record whose
// "event" attribute equals name.
func loggedExtras(tb testing.TB, out []byte, name string) map[string]any {
	tb.Helper()
	for _, line := range bytes.Split(bytes.TrimSpace(out), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			tb.Fatalf("decode log line %q: %v", line, err)
		}
		if rec["event"] != name {
			continue
		}
		extras, ok := rec["extras"].(map[string]any)
		if !ok {
			tb.Fatalf("record %q carries no extras group: %v", name, rec)
		}
		return extras
	}
	tb.Fatalf("no %q record was written; log was:\n%s", name, out)
	return nil
}
