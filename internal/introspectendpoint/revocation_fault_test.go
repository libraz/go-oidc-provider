package introspectendpoint_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// errGrantRevocationsUnavailable is the transport-shaped error the
// faulting store below returns, standing in for a database outage.
var errGrantRevocationsUnavailable = errors.New("grant revocations store unavailable")

// faultingGrantRevocations wraps the real in-memory
// [store.GrantRevocationStore] and makes IsRevoked fail unconditionally,
// so a test can drive the substore-fault path without a fake database —
// every other call goes to the real implementation.
type faultingGrantRevocations struct {
	store.GrantRevocationStore
}

func (faultingGrantRevocations) IsRevoked(context.Context, string, string, time.Time) (bool, error) {
	return false, errGrantRevocationsUnavailable
}

// faultingStore is the real [inmem.Store] with its GrantRevocations
// substore replaced by [faultingGrantRevocations].
type faultingStore struct {
	*inmem.Store
}

func (s *faultingStore) GrantRevocations() store.GrantRevocationStore {
	return faultingGrantRevocations{GrantRevocationStore: s.Store.GrantRevocations()}
}

// TestAudit_IntrospectionRevocationFault_EmitsEventAndStaysInactive pins
// the fail-open gate's finding: a GrantRevocations.IsRevoked transport
// fault at /introspect MUST still answer {"active": false} — RFC 7662
// §2.2 forbids leaking the sub-class on the wire — but MUST NOT vanish.
// The old code dropped the error entirely, so an operator had no way to
// tell a storage outage from a quiet stream of expired tokens; the fix
// carries it to the same fault-audit channel the opaque / refresh-token
// lookups already use.
func TestAudit_IntrospectionRevocationFault_EmitsEventAndStaysInactive(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	capture := newAuditCapture()
	// testkit.NewProvider always constructs its own inmem.Store and only
	// exposes it as Provider.Store; RegisterClient writes there, not
	// wherever a caller-supplied op.WithStore points. The faulting store
	// therefore has to be built and registered against directly, the
	// same way byo_userstore_test.go's hybrid-store tests do.
	base := inmem.New(inmem.WithClock(clock))
	faulting := &faultingStore{Store: base}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithFeature(feature.Introspect),
			op.WithAuditLogger(capture.logger()),
			op.WithStore(faulting),
		),
	)
	const secret = "rp-introspect-revocation-fault-secret" //nolint:gosec // G101: test fixture credential
	hash, err := op.HashClientSecret(secret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	rp := &store.Client{
		ID:                      "rp-introspect-revocation-fault",
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SecretHash:              hash,
	}
	if err := base.RegisterClient(context.Background(), rp); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	iat := clock.now
	tok, err := tokens.SignAccessToken(
		tokens.SigningKey{KeyID: tk.SigningKey.KeyID, Signer: tk.SigningKey.Signer},
		tokens.AccessTokenClaims{
			Issuer:    tk.Issuer,
			Subject:   "user-revocation-fault",
			Audience:  []string{tk.Issuer},
			ClientID:  rp.ID,
			GrantID:   "grant-revocation-fault",
			IssuedAt:  iat.Unix(),
			ExpiresAt: iat.Add(time.Hour).Unix(),
			JTI:       "at-revocation-fault",
			Scope:     []string{"openid"},
		},
	)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}

	form := url.Values{"token": {tok}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, secret)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200; body=%s; www-authenticate=%s", resp.StatusCode, b, resp.Header.Get("WWW-Authenticate"))
	}
	body := decodeJSON(t, resp)
	if got, _ := body["active"].(bool); got {
		t.Errorf("active=%v want false (a substore fault must not read as a valid token)", got)
	}
	if len(body) != 1 {
		t.Errorf("inactive response has %d members, want exactly 1 per RFC 7662 §2.2; body=%v", len(body), body)
	}

	events := capture.findEvents(t, string(op.AuditIntrospectionError))
	if len(events) != 1 {
		t.Fatalf("got %d introspection.error events, want exactly 1; capture=%s", len(events), capture.buf.String())
	}
	rec := events[0]
	if got := rec["client_id"]; got != rp.ID {
		t.Errorf("client_id=%v want %q", got, rp.ID)
	}
	extras, _ := rec["extras"].(map[string]any)
	if extras == nil {
		t.Fatalf("extras missing on introspection.error: %v", rec)
	}
	if got := extras["reason"]; got != "store_unavailable" {
		t.Errorf("extras.reason=%v want store_unavailable", got)
	}
}
