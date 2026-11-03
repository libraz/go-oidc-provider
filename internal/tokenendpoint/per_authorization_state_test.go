package tokenendpoint_test

import (
	"context"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	httptestutil "github.com/libraz/go-oidc-provider/internal/testutil/httptest"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// One (subject, client) grant is shared by every authorization of the pair,
// so a later authorization rewrites what it holds. The authentication, the
// authorization_details and the claims request a code was issued under are
// recorded on the code and carried down its refresh chain; these tests
// stamp the grant with a later authorization's values and require the
// code's own to reach the wire.

// idTokenClaimsRequest encodes a claims request asking for name at the
// id_token location.
func idTokenClaimsRequest(name string) map[string]any {
	return authorize.EncodeClaimsToGrant(&authorize.ClaimsRequest{
		IDToken: map[string]authorize.ClaimSpec{name: {Essential: true}},
	})
}

// TestAuthCode_IDTokenReportsTheCodesOwnAuthentication redeems a code
// issued under a password-only authentication after a later MFA
// authorization re-stamped the grant.
func TestAuthCode_IDTokenReportsTheCodesOwnAuthentication(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	pwdTime := f.clock.now.Add(-10 * time.Minute)
	f.seedGrant(t, &store.Grant{
		ID: "grant-own-authn", Subject: "user-own-authn", ClientID: client.ID,
		Scope:    []string{"openid"},
		AuthTime: f.clock.now.Add(-time.Minute),
		ACR:      "urn:acr:mfa",
		AMR:      []string{"pwd", "otp"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID: "code-own-authn", ClientID: client.ID, Subject: "user-own-authn",
		GrantID: "grant-own-authn", RedirectURI: client.RedirectURIs[0],
		Scope: []string{"openid"}, CodeChallenge: challenge, CodeChallengeMethod: "S256",
		AuthTime: pwdTime, ACR: "urn:acr:pwd", AMR: []string{"pwd"},
		AuthorizationRecorded: true,
	})

	resp := f.post(t, authCodeForm("code-own-authn", client.RedirectURIs[0], verifier), client.ID, secret)
	defer resp.Body.Close()
	body := decodeJSON(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%v", resp.StatusCode, body)
	}
	idClaims := decodeIDTokenClaims(t, body["id_token"].(string))
	if got := idClaims["auth_time"]; got != float64(pwdTime.Unix()) {
		t.Errorf("auth_time=%v want %d (the code's authentication)", got, pwdTime.Unix())
	}
	if got := idClaims["acr"]; got != "urn:acr:pwd" {
		t.Errorf("acr=%v want urn:acr:pwd", got)
	}
	if amr, _ := idClaims["amr"].([]any); len(amr) != 1 || amr[0] != "pwd" {
		t.Errorf("amr=%v want [pwd]", idClaims["amr"])
	}
}

// TestAuthCode_LegacyCodeTakesAuthenticationFromGrant pins the fallback for
// a code row written without its authorization state.
func TestAuthCode_LegacyCodeTakesAuthenticationFromGrant(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	f.seedGrant(t, &store.Grant{
		ID: "grant-legacy-code", Subject: "user-legacy-code", ClientID: client.ID,
		Scope: []string{"openid"}, ACR: "urn:acr:grant",
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID: "code-legacy", ClientID: client.ID, Subject: "user-legacy-code",
		GrantID: "grant-legacy-code", RedirectURI: client.RedirectURIs[0],
		Scope: []string{"openid"}, CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})

	resp := f.post(t, authCodeForm("code-legacy", client.RedirectURIs[0], verifier), client.ID, secret)
	defer resp.Body.Close()
	body := decodeJSON(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%v", resp.StatusCode, body)
	}
	if got := decodeIDTokenClaims(t, body["id_token"].(string))["acr"]; got != "urn:acr:grant" {
		t.Errorf("acr=%v want urn:acr:grant from the grant", got)
	}
}

// TestAuthCode_ClaimsRequestComesFromTheCodeThroughRefresh redeems a code
// whose claims request named email after a later authorization left a
// phone_number request on the grant, then refreshes the chain it rooted.
func TestAuthCode_ClaimsRequestComesFromTheCodeThroughRefresh(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const subject = "user-own-claims"
	f.prov.Store.PutUser(context.Background(), &store.User{
		Subject: subject,
		Claims:  map[string]any{"email": "own@example.com", "phone_number": "+1-555-0101"},
	})
	f.seedGrant(t, &store.Grant{
		ID: "grant-own-claims", Subject: subject, ClientID: client.ID,
		Scope:  []string{"openid", "offline_access"},
		Claims: idTokenClaimsRequest("phone_number"),
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID: "code-own-claims", ClientID: client.ID, Subject: subject,
		GrantID: "grant-own-claims", RedirectURI: client.RedirectURIs[0],
		Scope: []string{"openid", "offline_access"}, CodeChallenge: challenge, CodeChallengeMethod: "S256",
		AuthTime: f.clock.now, Claims: idTokenClaimsRequest("email"),
		AuthorizationRecorded: true,
	})

	resp := f.post(t, authCodeForm("code-own-claims", client.RedirectURIs[0], verifier), client.ID, secret)
	body := decodeJSON(t, resp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange status=%d body=%v", resp.StatusCode, body)
	}
	assertOwnClaimsRequest(t, "code exchange", decodeIDTokenClaims(t, body["id_token"].(string)))
	if got, ok := decodeJWTPayload(t, body["access_token"].(string))["userinfo_claims"].(map[string]any); !ok || len(got) != 0 {
		t.Errorf("access token userinfo_claims=%v want {} (the code requested no userinfo claims)", got)
	}

	refreshToken, _ := body["refresh_token"].(string)
	rec, err := f.prov.Store.RefreshTokens().Find(context.Background(), refreshToken)
	if err != nil {
		t.Fatalf("RefreshTokens.Find: %v", err)
	}
	if !rec.AuthorizationRecorded || authorize.DecodeClaimsFromGrant(rec.Claims) == nil {
		t.Fatalf("chain root recorded=%v claims=%v; want the code's claims request", rec.AuthorizationRecorded, rec.Claims)
	}
	resp = f.post(t, refreshForm(refreshToken, ""), client.ID, secret)
	defer resp.Body.Close()
	body = decodeJSON(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status=%d body=%v", resp.StatusCode, body)
	}
	assertOwnClaimsRequest(t, "refresh", decodeIDTokenClaims(t, body["id_token"].(string)))
}

func assertOwnClaimsRequest(tb testing.TB, surface string, idClaims map[string]any) {
	tb.Helper()
	if got := idClaims["email"]; got != "own@example.com" {
		tb.Errorf("%s id_token email=%v want own@example.com", surface, got)
	}
	if got, ok := idClaims["phone_number"]; ok {
		tb.Errorf("%s id_token phone_number=%v; the grant's later claims request leaked in", surface, got)
	}
}

// TestAuthCode_AuthorizationDetailsComeFromTheCode redeems a code whose
// authorization granted no details after a later authorization added a
// payment to the grant, then refreshes the chain it rooted.
func TestAuthCode_AuthorizationDetailsComeFromTheCode(t *testing.T) {
	t.Parallel()

	f := newFixtureWithOptions(t, paymentAuthorizationDetailsOption())
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	f.seedGrant(t, &store.Grant{
		ID: "grant-own-details", Subject: "user-own-details", ClientID: client.ID,
		Scope:                []string{"openid", "offline_access"},
		AuthorizationDetails: []map[string]any{{"type": "payment", "amount": "500"}},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID: "code-own-details", ClientID: client.ID, Subject: "user-own-details",
		GrantID: "grant-own-details", RedirectURI: client.RedirectURIs[0],
		Scope: []string{"openid", "offline_access"}, CodeChallenge: challenge, CodeChallengeMethod: "S256",
		AuthTime: f.clock.now, AuthorizationRecorded: true,
	})

	resp := f.post(t, authCodeForm("code-own-details", client.RedirectURIs[0], verifier), client.ID, secret)
	body := decodeJSON(t, resp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange status=%d body=%v", resp.StatusCode, body)
	}
	assertNoAuthorizationDetails(t, "code exchange", body)

	resp = f.post(t, refreshForm(body["refresh_token"].(string), ""), client.ID, secret)
	defer resp.Body.Close()
	body = decodeJSON(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status=%d body=%v", resp.StatusCode, body)
	}
	assertNoAuthorizationDetails(t, "refresh", body)
}

func assertNoAuthorizationDetails(tb testing.TB, surface string, body map[string]any) {
	tb.Helper()
	if got, ok := body["authorization_details"]; ok {
		tb.Errorf("%s response authorization_details=%v; the grant's later details leaked in", surface, got)
	}
	if got, ok := decodeJWTPayload(tb, body["access_token"].(string))["authorization_details"]; ok {
		tb.Errorf("%s access token authorization_details=%v; the grant's later details leaked in", surface, got)
	}
}

// TestRefresh_RecordedChainIsNarrowedNotWidenedByTheGrant rotates a chain
// recorded with two payments while the grant holds one of them and an
// unrelated third: the rotation keeps only the payment both hold.
func TestRefresh_RecordedChainIsNarrowedNotWidenedByTheGrant(t *testing.T) {
	t.Parallel()

	f := newFixtureWithOptions(t, paymentAuthorizationDetailsOption())
	client, secret := f.confidentialClientFixture(t)
	f.seedGrant(t, &store.Grant{
		ID: "grant-narrow", Subject: "user-narrow", ClientID: client.ID,
		Scope: []string{"openid", "offline_access"},
		AuthorizationDetails: []map[string]any{
			{"type": "payment", "amount": "100"},
			{"type": "payment", "amount": "300"},
		},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID: "rt-narrow", ClientID: client.ID, Subject: "user-narrow", GrantID: "grant-narrow",
		Scope: []string{"openid", "offline_access"}, AuthTime: f.clock.now,
		AuthorizationDetails: []map[string]any{
			{"type": "payment", "amount": "100"},
			{"type": "payment", "amount": "200"},
		},
		AuthorizationRecorded: true,
	})

	resp := f.post(t, refreshForm("rt-narrow", ""), client.ID, secret)
	defer resp.Body.Close()
	body := decodeJSON(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%v", resp.StatusCode, body)
	}
	details, _ := body["authorization_details"].([]any)
	if len(details) != 1 {
		t.Fatalf("authorization_details=%v want the one payment both the chain and the grant hold", body["authorization_details"])
	}
	if el, _ := details[0].(map[string]any); el["amount"] != "100" {
		t.Fatalf("authorization_details=%v want amount=100", details)
	}
}

// TestAuthCode_OpaqueAccessTokenRecordsItsAuthorization redeems a code in
// the opaque format: the shadow row carries the code's acr, amr, claims
// request and authorization_details, not the grant's, and introspection
// reports them.
func TestAuthCode_OpaqueAccessTokenRecordsItsAuthorization(t *testing.T) {
	t.Parallel()

	f := newFixtureWithOptions(t, paymentAuthorizationDetailsOption(),
		op.WithAccessTokenFormat(op.AccessTokenFormatOpaque), op.WithFeature(feature.Introspect))
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	own := []map[string]any{{"type": "payment", "amount": "100"}}
	f.seedGrant(t, &store.Grant{
		ID: "grant-opaque-own", Subject: "user-opaque-own", ClientID: client.ID,
		Scope:                []string{"openid"},
		ACR:                  "urn:acr:mfa",
		AMR:                  []string{"pwd", "otp"},
		Claims:               idTokenClaimsRequest("phone_number"),
		AuthorizationDetails: append([]map[string]any{{"type": "payment", "amount": "900"}}, own...),
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID: "code-opaque-own", ClientID: client.ID, Subject: "user-opaque-own",
		GrantID: "grant-opaque-own", RedirectURI: client.RedirectURIs[0],
		Scope: []string{"openid"}, CodeChallenge: challenge, CodeChallengeMethod: "S256",
		AuthTime: f.clock.now, ACR: "urn:acr:pwd", AMR: []string{"pwd"},
		Claims: idTokenClaimsRequest("email"), AuthorizationDetails: own,
		AuthorizationRecorded: true,
	})

	resp := f.post(t, authCodeForm("code-opaque-own", client.RedirectURIs[0], verifier), client.ID, secret)
	defer resp.Body.Close()
	body := decodeJSON(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%v", resp.StatusCode, body)
	}
	rec, err := f.prov.Store.OpaqueAccessTokens().Find(context.Background(), body["access_token"].(string))
	if err != nil {
		t.Fatalf("OpaqueAccessTokens.Find: %v", err)
	}
	if !rec.AuthorizationRecorded {
		t.Error("opaque row AuthorizationRecorded=false")
	}
	if c := authorize.DecodeClaimsFromGrant(rec.Claims); c == nil || len(c.IDToken) != 1 {
		t.Errorf("opaque row claims=%v want the code's email request", rec.Claims)
	} else if _, ok := c.IDToken["email"]; !ok {
		t.Errorf("opaque row claims=%v want the code's email request", rec.Claims)
	}
	if len(rec.AuthorizationDetails) != 1 || rec.AuthorizationDetails[0]["amount"] != "100" {
		t.Errorf("opaque row authorization_details=%v want amount=100 only", rec.AuthorizationDetails)
	}

	introspected := httptestutil.PostForm(t, f.prov.HTTPClient(nil), f.prov.Server.URL+"/oidc/introspect",
		url.Values{"token": {body["access_token"].(string)}}, client.ID, secret)
	defer introspected.Body.Close()
	ib := decodeJSON(t, introspected)
	if ib["active"] != true {
		t.Fatalf("introspection body=%v want active", ib)
	}
	if ib["acr"] != "urn:acr:pwd" {
		t.Errorf("introspection acr=%v want urn:acr:pwd (the code's)", ib["acr"])
	}
	if amr, _ := ib["amr"].([]any); len(amr) != 1 || amr[0] != "pwd" {
		t.Errorf("introspection amr=%v want [pwd]", ib["amr"])
	}
}

// grantFindFaultStore is the reference store with its GrantStore replaced
// by a fault-injecting decorator. It carries no BeginTx, so the refresh
// path runs against these substores rather than a transaction's.
type grantFindFaultStore struct {
	store.Store
	grants store.GrantStore
}

func (s grantFindFaultStore) Grants() store.GrantStore {
	return s.grants
}

// newGrantFindFaultFixture builds a fixture over decorated while seeding
// lands in backing, the reference store decorated wraps.
func newGrantFindFaultFixture(t *testing.T, decorated store.Store, backing *inmem.Store, clock fixedClock, opts ...op.Option) *fixture {
	t.Helper()
	prov := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(append([]op.Option{op.WithStore(decorated), op.WithUserStore(backing.Users())}, opts...)...),
	)
	prov.Store = backing
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		signer:   tokens.SigningKey{KeyID: prov.SigningKey.KeyID, Signer: prov.SigningKey.Signer},
		clock:    clock,
	}
}

// assertServerError requires a 500 server_error answer.
func assertServerError(tb testing.TB, resp *http.Response) {
	tb.Helper()
	body := decodeJSON(tb, resp)
	if resp.StatusCode != http.StatusInternalServerError || body["error"] != "server_error" {
		tb.Fatalf("status=%d body=%v want 500 server_error", resp.StatusCode, body)
	}
}

// TestAuthCode_GrantLookupFaultAnswersServerError redeems a recorded code
// while its grant cannot be read: the grant could have withdrawn
// authorization_details, so the exchange must not proceed without it.
func TestAuthCode_GrantLookupFaultAnswersServerError(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	backing := inmem.New(inmem.WithClock(clock))
	var beginCount atomic.Int32
	f := newGrantFindFaultFixture(t, grantFindFailsOnceStore{
		Store:         backing,
		grants:        newFailOnceGrantStore(t, backing, 0),
		transactional: backing,
		beginCount:    &beginCount,
	}, backing, clock)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	f.seedGrant(t, &store.Grant{
		ID: "grant-code-fault", Subject: "user-code-fault", ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID: "code-grant-fault", ClientID: client.ID, Subject: "user-code-fault",
		GrantID: "grant-code-fault", RedirectURI: client.RedirectURIs[0],
		Scope: []string{"openid"}, CodeChallenge: challenge, CodeChallengeMethod: "S256",
		AuthTime: f.clock.now, AuthorizationRecorded: true,
	})

	resp := f.post(t, authCodeForm("code-grant-fault", client.RedirectURIs[0], verifier), client.ID, secret)
	defer resp.Body.Close()
	assertServerError(t, resp)
}

// TestRefresh_GrantLookupFaultAnswersServerError rotates a recorded chain
// whose grant reads at the preflight and then faults when the issued
// authorization is resolved.
func TestRefresh_GrantLookupFaultAnswersServerError(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	backing := inmem.New(inmem.WithClock(clock))
	f := newGrantFindFaultFixture(t, grantFindFaultStore{
		Store:  backing,
		grants: newFailOnceGrantStore(t, backing, 1),
	}, backing, clock, op.WithGrants(grant.RefreshToken), paymentAuthorizationDetailsOption())
	client, secret := f.confidentialClientFixture(t)
	f.seedGrant(t, &store.Grant{
		ID: "grant-rt-fault", Subject: "user-rt-fault", ClientID: client.ID,
		Scope:                []string{"openid", "offline_access"},
		AuthorizationDetails: []map[string]any{{"type": "payment", "amount": "100"}},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID: "rt-grant-fault", ClientID: client.ID, Subject: "user-rt-fault", GrantID: "grant-rt-fault",
		Scope: []string{"openid", "offline_access"}, AuthTime: f.clock.now,
		AuthorizationDetails:  []map[string]any{{"type": "payment", "amount": "100"}},
		AuthorizationRecorded: true,
	})

	resp := f.post(t, refreshForm("rt-grant-fault", ""), client.ID, secret)
	defer resp.Body.Close()
	assertServerError(t, resp)
}
