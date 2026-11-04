package introspectendpoint_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/audit"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// errGrantsUnavailable is the transport-shaped error [faultingGrants]
// returns, standing in for a database outage.
var errGrantsUnavailable = errors.New("grant store unavailable")

// faultingGrants wraps the real in-memory GrantStore and makes Find fail
// unconditionally; every other call goes to the real implementation.
type faultingGrants struct {
	store.GrantClientLister
}

func (faultingGrants) Find(context.Context, string) (*store.Grant, error) {
	return nil, errGrantsUnavailable
}

// grantFaultStore is the real [inmem.Store] with its Grants substore
// replaced by [faultingGrants].
type grantFaultStore struct {
	*inmem.Store
	grants faultingGrants
}

func (s *grantFaultStore) Grants() store.GrantStore {
	return s.grants
}

// TestHandler_GrantLookupFault_EmitsEventAndStaysInactive introspects a
// recorded token whose grant cannot be read. The grant could have
// withdrawn authorization_details, so the token must not be reported
// active without it; the wire answer is inactive per RFC 7662 §2.2, like
// every other store fault here, and the fault reaches the audit stream.
func TestHandler_GrantLookupFault_EmitsEventAndStaysInactive(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		save func(tb testing.TB, f *fixture, clientID string)
	}{
		{
			name: "opaque access token",
			save: func(tb testing.TB, f *fixture, clientID string) {
				f.saveOpaqueAccessToken(tb, &store.OpaqueAccessToken{
					ID: "grant-fault-token", GrantID: "grant-fault", Subject: "user-grant-fault",
					ClientID: clientID, Scope: []string{"openid"}, Audience: f.prov.Issuer,
					IssuedAt: f.clock.now, ExpiresAt: f.clock.now.Add(time.Hour),
					AuthorizationRecorded: true,
				})
			},
		},
		{
			name: "refresh token",
			save: func(tb testing.TB, f *fixture, clientID string) {
				f.saveRefreshToken(tb, &store.RefreshToken{
					ID: "grant-fault-token", ClientID: clientID, Subject: "user-grant-fault",
					GrantID: "grant-fault", Scope: []string{"openid"},
					ExpiresAt: f.clock.now.Add(time.Hour), CreatedAt: f.clock.now,
					AuthorizationRecorded: true,
				})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
			capture := newAuditCapture()
			base := inmem.New(inmem.WithClock(clock))
			lister, ok := base.Grants().(store.GrantClientLister)
			if !ok {
				t.Fatal("inmem GrantStore does not implement store.GrantClientLister")
			}
			prov := testkit.NewProvider(t,
				testkit.WithClock(clock),
				testkit.WithOptions(
					op.WithFeature(feature.Introspect),
					op.WithAuditLogger(capture.logger()),
					op.WithStore(&grantFaultStore{Store: base, grants: faultingGrants{GrantClientLister: lister}}),
				),
			)
			prov.Store = base
			f := &fixture{
				prov:     prov,
				endpoint: prov.Server.URL + "/oidc/introspect",
				signer:   tokens.SigningKey{KeyID: prov.SigningKey.KeyID, Signer: prov.SigningKey.Signer},
				clock:    clock,
			}
			client, secret := f.confidentialClient(t, "client-grant-fault")
			saveGrantWithDetails(t, f, "grant-fault", "user-grant-fault", client.ID)
			tc.save(t, f, client.ID)

			resp := f.post(t, url.Values{"token": {"grant-fault-token"}}, client.ID, secret)
			defer resp.Body.Close()
			body := decodeJSON(t, resp)
			if resp.StatusCode != http.StatusOK || len(body) != 1 || body["active"] != false {
				t.Fatalf("status=%d body=%v want 200 {\"active\":false}", resp.StatusCode, body)
			}
			events := capture.findEvents(t, string(audit.IntrospectionError))
			if len(events) != 1 {
				t.Fatalf("got %d introspection.error events, want exactly 1; capture=%s", len(events), capture.buf.String())
			}
			extras, _ := events[0]["extras"].(map[string]any)
			if got := extras["reason"]; got != "store_unavailable" {
				t.Errorf("extras.reason=%v want store_unavailable", got)
			}
		})
	}
}
