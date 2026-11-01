package op_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// ssfPlainStore hides every extension of the wrapped store, so it is not
// a store.SharedSignalsStore.
type ssfPlainStore struct{ store.Store }

// ssfNilEventsStore is a SharedSignalsStore whose event substore is
// absent, as a composite store routed to a backend without SSF reports.
type ssfNilEventsStore struct{ *inmem.Store }

func (ssfNilEventsStore) SSFEvents() store.SSFEventStore { return nil }

// ssfNoListerStore keeps the SSF substores but hides the grant
// substore's GrantClientLister extension.
type ssfNoListerStore struct{ *inmem.Store }

func (s ssfNoListerStore) Grants() store.GrantStore {
	return struct{ store.GrantStore }{s.Store.Grants()}
}

// ssfOptions is a client_credentials-only configuration with the
// transmitter on; extra options replace or add to it.
func ssfOptions(t *testing.T, st store.Store, cookieKeys bool, extra ...op.Option) []op.Option {
	t.Helper()
	opts := []op.Option{
		op.WithIssuer(testkit.DefaultIssuer),
		op.WithStore(st),
		op.WithKeyset(op.Keyset{testkit.NewSigningKey(t, testkit.DefaultKeyID)}),
		op.WithGrants(grant.ClientCredentials),
		op.WithSharedSignals(),
	}
	if cookieKeys {
		opts = append(opts, op.WithCookieKeys(testkit.NewCookieKey(t)))
	}
	return append(opts, extra...)
}

func newSSFProvider(t *testing.T, opts []op.Option) (*op.Provider, error) {
	t.Helper()
	p, err := op.New(opts...)
	if p != nil {
		t.Cleanup(func() { _ = p.Shutdown(t.Context()) })
	}
	return p, err
}

// TestWithSharedSignals_NewRejections pins each construction-time
// requirement of the transmitter against an otherwise valid
// configuration.
func TestWithSharedSignals_NewRejections(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		opts func(t *testing.T) []op.Option
		want string
	}{
		{"store without SSF", func(t *testing.T) []op.Option {
			return ssfOptions(t, ssfPlainStore{inmem.New()}, true)
		}, "store.SharedSignalsStore"},
		{"nil SSF substore", func(t *testing.T) []op.Option {
			return ssfOptions(t, ssfNilEventsStore{inmem.New()}, true)
		}, "non-nil SSFStreams() and SSFEvents()"},
		{"grants without client lister", func(t *testing.T) []op.Option {
			return ssfOptions(t, ssfNoListerStore{inmem.New()}, true)
		}, "GrantClientLister"},
		{"no cookie keys", func(t *testing.T) []op.Option {
			return ssfOptions(t, inmem.New(), false)
		}, "WithCookieKeys"},
		{"reserved scope prefix", func(t *testing.T) []op.Option {
			return ssfOptions(t, inmem.New(), true, op.WithScope(op.Scope{Name: "ssf.read"}))
		}, "scope prefix is reserved"},
		{"insecure push on a public issuer", func(t *testing.T) []op.Option {
			opts := ssfOptions(t, inmem.New(), true, op.WithAllowInsecureSharedSignalsPushForDev())
			opts[0] = op.WithIssuer("https://op.example.com")
			return opts
		}, "requires a development issuer"},
		{"route collision", func(t *testing.T) []op.Option {
			return ssfOptions(t, inmem.New(), true, op.WithEndpoints(op.Endpoints{SSFStatus: "/token"}))
		}, "route collision"},
		{"poll prefix collision", func(t *testing.T) []op.Option {
			return ssfOptions(t, inmem.New(), true, op.WithEndpoints(op.Endpoints{SSFVerify: "/ssf/poll/verify"}))
		}, "route collision"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := newSSFProvider(t, tc.opts(t))
			var opErr *op.Error
			if !errors.As(err, &opErr) || !strings.Contains(opErr.Description, tc.want) {
				t.Fatalf("New = %v, want a configuration error containing %q", err, tc.want)
			}
		})
	}
}

// TestWithSharedSignals_Baseline proves the rejection cases above fail
// for their own reason: the same configuration builds, and without the
// transmitter the ssf. names and SSF paths are free.
func TestWithSharedSignals_Baseline(t *testing.T) {
	t.Parallel()
	if _, err := newSSFProvider(t, ssfOptions(t, inmem.New(), true)); err != nil {
		t.Fatalf("New with WithSharedSignals: %v", err)
	}
	off := []op.Option{
		op.WithIssuer(testkit.DefaultIssuer),
		op.WithStore(ssfPlainStore{inmem.New()}),
		op.WithKeyset(op.Keyset{testkit.NewSigningKey(t, testkit.DefaultKeyID)}),
		op.WithGrants(grant.ClientCredentials),
		op.WithScope(op.Scope{Name: "ssf.read"}),
		op.WithEndpoints(op.Endpoints{SSFStatus: "/token"}),
	}
	if _, err := newSSFProvider(t, off); err != nil {
		t.Fatalf("New without WithSharedSignals: %v", err)
	}
}

// TestWithSharedSignals_RegistersReceiverScopes checks that ssf.read
// and ssf.manage are issued through client_credentials without a
// WithScope from the embedder, and that their registration as
// Public: false keeps them out of discovery.
func TestWithSharedSignals_RegistersReceiverScopes(t *testing.T) {
	t.Parallel()
	tk := newSSFE2EProvider(t)
	for _, scope := range []string{"ssf.read", "ssf.manage"} {
		status, body := ssfToken(t, tk, ssfE2EPushClient, scope)
		if status != http.StatusOK || body["scope"] != scope {
			t.Errorf("client_credentials %s: status=%d body=%v", scope, status, body)
		}
	}
	resp := ssfBrowserGet(t, tk.HTTPClient(nil), tk.Server.URL+"/.well-known/openid-configuration")
	defer func() { _ = resp.Body.Close() }()
	var doc struct {
		ScopesSupported []string `json:"scopes_supported"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	for _, s := range doc.ScopesSupported {
		if strings.HasPrefix(s, "ssf.") {
			t.Errorf("discovery advertises %s", s)
		}
	}
}
