package authorizeendpoint_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// The contexts the operator below enrolled, and the one an attacker
// names.
const (
	advertisedACR   = "urn:example:aal2"
	unadvertisedACR = "urn:example:aal3"
)

// acrAdvertisedFixture is a provider that publishes a two-entry
// acr_values_supported list and mounts /par, so every way an acr_values
// entry can reach the authorization endpoint is drivable.
type acrAdvertisedFixture struct {
	tk    *testkit.Provider
	rp    *store.Client
	cl    *http.Client
	clock fakeClock
}

func newACRAdvertisedFixture(t *testing.T, clientID string) *acrAdvertisedFixture {
	t.Helper()
	clock := fakeClock{now: time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithACRValuesSupported("urn:example:aal1", advertisedACR),
			op.WithFeature(feature.PAR),
		),
	)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "none",
		PublicClient:            true,
	})
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &acrAdvertisedFixture{tk: tk, rp: rp, cl: tk.HTTPClient(jar), clock: clock}
}

// authorize issues GET /authorize with the supplied values and returns
// the redirect target plus the cookies the response set.
func (f *acrAdvertisedFixture) authorize(t *testing.T, values url.Values) (*url.URL, []*http.Cookie) {
	t.Helper()
	resp, err := newGet(f.tk.Server.URL + "/oidc/auth?" + values.Encode()).Do(f.cl)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status=%d body=%s", resp.StatusCode, string(dump))
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	return loc, resp.Cookies()
}

// seedPARRecord persists a pushed authorization request carrying acr
// directly on the store. It stands in for a request_uri minted before
// the operator narrowed the advertised list: /par refuses to mint one
// for an unadvertised value now, so the replay can only be built here.
func (f *acrAdvertisedFixture) seedPARRecord(t *testing.T, acr string) string {
	t.Helper()
	req := &authorize.Request{
		ClientID:            f.rp.ID,
		ResponseType:        "code",
		RedirectURI:         f.rp.RedirectURIs[0],
		Scope:               []string{"openid", "profile", "email"},
		State:               "state-abc",
		Nonce:               "n-0S6_WzA2Mj",
		CodeChallenge:       e2eChallenge(),
		CodeChallengeMethod: "S256",
		ACRValues:           []string{acr},
	}
	raw, err := json.Marshal(authorize.SnapshotFrom(req, f.clock.now))
	if err != nil {
		t.Fatalf("marshal PAR snapshot: %v", err)
	}
	uri := authorize.PARRequestURIPrefix + "seeded-" + acr
	if err := f.tk.Store.PushedAuthRequests().Save(context.Background(), &store.PushedAuthRequest{
		URI:       uri,
		ClientID:  f.rp.ID,
		RawParams: raw,
		ExpiresAt: f.clock.now.Add(time.Minute),
		CreatedAt: f.clock.now,
	}); err != nil {
		t.Fatalf("Save PAR record: %v", err)
	}
	return uri
}

// TestEndToEnd_UnadvertisedACRRejectedAtEveryEntry drives each of the
// three routes an acr_values entry takes into the authorization
// endpoint against an OP that published acr_values_supported.
//
// A value outside the advertised set names a context the operator never
// enrolled. Honouring it would let the client pick the `acr` claim of
// the issued id_token, and the value survives further than that: the
// decision matrix records it on the session, so it becomes an input to
// every later request. The backchannel endpoint has always refused
// these; the front channel must answer the same way.
func TestEndToEnd_UnadvertisedACRRejectedAtEveryEntry(t *testing.T) {
	t.Parallel()

	t.Run("inline parameter", func(t *testing.T) {
		t.Parallel()
		f := newACRAdvertisedFixture(t, "rp-acr-inline")
		values := e2eAuthorizeValues(f.rp.ID, f.rp.RedirectURIs[0])
		values.Set("acr_values", unadvertisedACR)
		loc, cookies := f.authorize(t, values)
		requireUnadvertisedACRRefusal(t, loc, cookies)
	})

	t.Run("claims parameter", func(t *testing.T) {
		t.Parallel()
		f := newACRAdvertisedFixture(t, "rp-acr-claims")
		values := e2eAuthorizeValues(f.rp.ID, f.rp.RedirectURIs[0])
		values.Set("claims", `{"id_token":{"acr":{"essential":true,"values":["`+unadvertisedACR+`"]}}}`)
		loc, cookies := f.authorize(t, values)
		requireUnadvertisedACRRefusal(t, loc, cookies)
	})

	t.Run("PAR snapshot replay", func(t *testing.T) {
		t.Parallel()
		f := newACRAdvertisedFixture(t, "rp-acr-par")
		loc, cookies := f.authorize(t, url.Values{
			"client_id":   {f.rp.ID},
			"request_uri": {f.seedPARRecord(t, unadvertisedACR)},
		})
		requireUnadvertisedACRRefusal(t, loc, cookies)
	})

	t.Run("client default backfill", func(t *testing.T) {
		t.Parallel()
		f := newACRAdvertisedFixture(t, "rp-acr-default")
		updated := *f.rp
		updated.DefaultACRValues = []string{unadvertisedACR}
		if err := f.tk.Store.UpdateClient(context.Background(), &updated); err != nil {
			t.Fatalf("UpdateClient: %v", err)
		}
		// The request names no acr at all; the unadvertised value comes
		// from the registration.
		loc, cookies := f.authorize(t, e2eAuthorizeValues(f.rp.ID, f.rp.RedirectURIs[0]))
		requireUnadvertisedACRRefusal(t, loc, cookies)
	})
}

// TestEndToEnd_AdvertisedACRStillStartsTheCeremony is the control: the
// gate refuses what the operator did not enrol and nothing else, so a
// request naming an advertised context proceeds to the ceremony as
// before.
func TestEndToEnd_AdvertisedACRStillStartsTheCeremony(t *testing.T) {
	t.Parallel()

	f := newACRAdvertisedFixture(t, "rp-acr-advertised")
	values := e2eAuthorizeValues(f.rp.ID, f.rp.RedirectURIs[0])
	values.Set("acr_values", advertisedACR)
	loc, _ := f.authorize(t, values)
	if got := loc.Query().Get("error"); got != "" {
		t.Fatalf("an advertised acr was refused with %q: %s", got, loc)
	}
	if !strings.HasPrefix(loc.Path, "/oidc/interaction/") {
		t.Fatalf("Location=%s want the interaction redirect", loc)
	}
}

// TestEndToEnd_NoAdvertisementAdmitsAnyACR pins the compatibility
// posture: an OP that published no acr_values_supported constrains
// nothing, so a deployment that never opted into the metadata keeps its
// verbatim behaviour.
func TestEndToEnd_NoAdvertisementAdmitsAnyACR(t *testing.T) {
	t.Parallel()

	f := newE2EFlow(t, "rp-acr-unadvertised-op")
	values := f.values()
	values.Set("acr_values", unadvertisedACR)
	loc := f.authorize(t, values)
	if got := loc.Query().Get("error"); got != "" {
		t.Fatalf("an OP that advertised nothing refused acr_values with %q: %s", got, loc)
	}
}

// requireUnadvertisedACRRefusal asserts the redirect carries
// invalid_request, no authorization code, and that nothing about the
// refused request was persisted into a browser session.
func requireUnadvertisedACRRefusal(t *testing.T, loc *url.URL, cookies []*http.Cookie) {
	t.Helper()
	if code := loc.Query().Get("code"); code != "" {
		t.Fatalf("a code was issued for an acr the OP never advertised: %s", loc)
	}
	if got := loc.Query().Get("error"); got != "invalid_request" {
		t.Fatalf("error=%q want invalid_request (redirect %s)", got, loc)
	}
	if c := findCookie(cookies, cookie.SessionProfile.Name); c != nil && c.Value != "" {
		t.Errorf("the refused request established a session cookie: %v", c)
	}
	if c := findCookie(cookies, cookie.InteractionProfile.Name); c != nil && c.Value != "" {
		t.Errorf("the refused request started an interaction: %v", c)
	}
}
