package tokenendpoint_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// switchableUserStore decorates the reference user store so a test can
// deprovision a subject, or make the directory unreachable, mid-test.
type switchableUserStore struct {
	store.UserStore

	mu    sync.Mutex
	gone  map[string]bool
	fault error
}

func (s *switchableUserStore) FindBySubject(ctx context.Context, sub string) (*store.User, error) {
	s.mu.Lock()
	gone, fault := s.gone[sub], s.fault
	s.mu.Unlock()
	if fault != nil {
		return nil, fault
	}
	if gone {
		return nil, store.ErrNotFound
	}
	return s.UserStore.FindBySubject(ctx, sub)
}

func (s *switchableUserStore) setGone(sub string, gone bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gone == nil {
		s.gone = map[string]bool{}
	}
	s.gone[sub] = gone
}

func (s *switchableUserStore) setFault(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fault = err
}

var errUserDirectoryDown = errors.New("user directory unreachable")

// newDeprovisionFixture wires the provider's claim and redemption lookups
// to a switchable user store holding subject.
func newDeprovisionFixture(t *testing.T, subject string) (*fixture, *switchableUserStore) {
	t.Helper()
	backing := inmem.New()
	seedSubject(t, backing, subject)
	users := &switchableUserStore{UserStore: backing.Users()}
	return newFixtureWithOptions(t, op.WithUserStore(users)), users
}

func assertOAuthError(t *testing.T, resp *http.Response, status int, code string) {
	t.Helper()
	body := decodeJSON(t, resp)
	if resp.StatusCode != status || body["error"] != code {
		t.Fatalf("status=%d error=%v, want %d %s; body=%v", resp.StatusCode, body["error"], status, code, body)
	}
	if _, ok := body["access_token"]; ok {
		t.Fatalf("an error response carried an access_token: %v", body)
	}
}

func TestDeprovisionedSubject_AuthCodeRefusedAndGrantTornDown(t *testing.T) {
	t.Parallel()
	const subject = "user-deprovisioned-code"
	const grantID = "grant-deprovisioned-code"
	f, users := newDeprovisionFixture(t, subject)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	redirect := client.RedirectURIs[0]
	scope := []string{"openid", "offline_access"}
	f.seedGrant(t, &store.Grant{ID: grantID, Subject: subject, ClientID: client.ID, Scope: scope})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID: "rt-earlier-exchange", ClientID: client.ID, Subject: subject, GrantID: grantID, Scope: scope,
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID: "code-deprovisioned", ClientID: client.ID, Subject: subject, GrantID: grantID,
		RedirectURI: redirect, Scope: scope, CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})

	users.setGone(subject, true)
	resp := f.post(t, authCodeForm("code-deprovisioned", redirect, verifier), client.ID, secret)
	defer resp.Body.Close()
	assertOAuthError(t, resp, http.StatusBadRequest, "invalid_grant")

	assertGrantTombstoned(t, f, grantID, f.clock.now.Add(-time.Second))
	// The earlier exchange's refresh token died with the grant, not with
	// the subject check: it stays refused once the subject is back.
	users.setGone(subject, false)
	again := f.post(t, refreshForm("rt-earlier-exchange", ""), client.ID, secret)
	defer again.Body.Close()
	assertOAuthError(t, again, http.StatusBadRequest, "invalid_grant")
}

// TestDeprovisionedSubject_RefreshRefusedAndGrantTornDown pins that a
// refresh redemption for a deprovisioned subject is refused with
// invalid_grant and tears the backing grant down, rather than
// redeeming on the stale token's own validity alone.
//
// Tracks: CVE-2026-16103 — token redemption skipped the subject's
// disabled/deleted re-check. The black-box counterpart of this surface
// is pinned by TestSubjectDeprovisioning_RefreshRefusedAndAccessTokenDead.
func TestDeprovisionedSubject_RefreshRefusedAndGrantTornDown(t *testing.T) {
	t.Parallel()
	const subject = "user-deprovisioned-refresh"
	const grantID = "grant-deprovisioned-refresh"
	f, users := newDeprovisionFixture(t, subject)
	client, secret := f.confidentialClientFixture(t)
	scope := []string{"openid", "offline_access"}
	f.seedGrant(t, &store.Grant{ID: grantID, Subject: subject, ClientID: client.ID, Scope: scope})
	for _, id := range []string{"rt-presented", "rt-sibling"} {
		f.seedRefreshToken(t, &store.RefreshToken{
			ID: id, ClientID: client.ID, Subject: subject, GrantID: grantID, Scope: scope,
		})
	}

	users.setGone(subject, true)
	resp := f.post(t, refreshForm("rt-presented", ""), client.ID, secret)
	defer resp.Body.Close()
	assertOAuthError(t, resp, http.StatusBadRequest, "invalid_grant")

	assertGrantTombstoned(t, f, grantID, f.clock.now.Add(-time.Second))
	users.setGone(subject, false)
	sibling := f.post(t, refreshForm("rt-sibling", ""), client.ID, secret)
	defer sibling.Body.Close()
	assertOAuthError(t, sibling, http.StatusBadRequest, "invalid_grant")
}

func TestDeprovisionedSubject_GraceRetryRefused(t *testing.T) {
	t.Parallel()
	const subject = "user-deprovisioned-grace"
	const grantID = "grant-deprovisioned-grace"
	f, users := newDeprovisionFixture(t, subject)
	client, secret := f.confidentialClientFixture(t)
	scope := []string{"openid", "offline_access"}
	f.seedGrant(t, &store.Grant{ID: grantID, Subject: subject, ClientID: client.ID, Scope: scope})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID: "rt-grace", ClientID: client.ID, Subject: subject, GrantID: grantID, Scope: scope,
	})
	first := f.post(t, refreshForm("rt-grace", ""), client.ID, secret)
	defer first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first rotation status=%d body=%v", first.StatusCode, decodeJSON(t, first))
	}

	// A retry inside the grace window is served while the subject exists,
	// so the refusal below comes from the subject check, not replay.
	served := f.post(t, refreshForm("rt-grace", ""), client.ID, secret)
	defer served.Body.Close()
	if served.StatusCode != http.StatusOK {
		t.Fatalf("grace retry status=%d body=%v", served.StatusCode, decodeJSON(t, served))
	}

	users.setGone(subject, true)
	retry := f.post(t, refreshForm("rt-grace", ""), client.ID, secret)
	defer retry.Body.Close()
	assertOAuthError(t, retry, http.StatusBadRequest, "invalid_grant")
	assertGrantTombstoned(t, f, grantID, f.clock.now.Add(-time.Second))
}

func TestDeprovisionedSubject_UserStoreFaultIsServerError(t *testing.T) {
	t.Parallel()
	const subject = "user-directory-fault"
	const grantID = "grant-directory-fault"
	f, users := newDeprovisionFixture(t, subject)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	redirect := client.RedirectURIs[0]
	scope := []string{"openid", "offline_access"}
	f.seedGrant(t, &store.Grant{ID: grantID, Subject: subject, ClientID: client.ID, Scope: scope})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID: "rt-fault", ClientID: client.ID, Subject: subject, GrantID: grantID, Scope: scope,
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID: "code-fault", ClientID: client.ID, Subject: subject, GrantID: grantID,
		RedirectURI: redirect, Scope: scope, CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})

	users.setFault(errUserDirectoryDown)
	code := f.post(t, authCodeForm("code-fault", redirect, verifier), client.ID, secret)
	defer code.Body.Close()
	assertOAuthError(t, code, http.StatusInternalServerError, "server_error")
	refresh := f.post(t, refreshForm("rt-fault", ""), client.ID, secret)
	defer refresh.Body.Close()
	assertOAuthError(t, refresh, http.StatusInternalServerError, "server_error")

	// A fault revokes nothing: the refresh chain redeems once the
	// directory answers again.
	users.setFault(nil)
	recovered := f.post(t, refreshForm("rt-fault", ""), client.ID, secret)
	defer recovered.Body.Close()
	if recovered.StatusCode != http.StatusOK {
		t.Fatalf("refresh after the fault cleared: status=%d body=%v", recovered.StatusCode, decodeJSON(t, recovered))
	}
}

func cibaForm(authReqID string) url.Values {
	form := url.Values{}
	form.Set("grant_type", "urn:openid:params:grant-type:ciba")
	form.Set("auth_req_id", authReqID)
	return form
}

func TestDeprovisionedSubject_CIBARefusedAndApprovalSpent(t *testing.T) {
	t.Parallel()
	f := newCIBAFixture(t)
	f.seedCIBARequest(t, &store.CIBARequest{ID: "auth-req-gone", Scope: []string{"openid"}})
	// The subject approved, then left the user store before the poll.
	if err := f.store.CIBARequests().Approve(context.Background(), "auth-req-gone", "user-gone", "", f.clock.now); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	rec := f.post(t, cibaForm("auth-req-gone"))
	if rec.Code != http.StatusBadRequest || cibaDecodeError(t, rec.Body.Bytes()) != "invalid_grant" {
		t.Fatalf("status=%d body=%s, want 400 invalid_grant", rec.Code, rec.Body.String())
	}
	if _, err := f.store.CIBARequests().Consume(context.Background(), "auth-req-gone"); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("approval still redeemable after the refusal: Consume err=%v", err)
	}
}

func TestDeprovisionedSubject_CIBAUserStoreFaultKeepsApproval(t *testing.T) {
	t.Parallel()
	f := newCIBAFixture(t)
	users := &switchableUserStore{UserStore: f.store.Users()}
	f.deps.UserStore = users
	seedSubject(t, f.store, "user-ciba-fault")
	f.seedCIBARequest(t, &store.CIBARequest{ID: "auth-req-fault", Scope: []string{"openid"}})
	if err := f.store.CIBARequests().Approve(context.Background(), "auth-req-fault", "user-ciba-fault", "", f.clock.now); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	users.setFault(errUserDirectoryDown)
	rec := f.post(t, cibaForm("auth-req-fault"))
	if rec.Code != http.StatusInternalServerError || rec.Body.Len() == 0 || cibaDecodeError(t, rec.Body.Bytes()) != "server_error" {
		t.Fatalf("status=%d body=%s, want 500 server_error", rec.Code, rec.Body.String())
	}
	stored, err := f.store.CIBARequests().FindByAuthReqID(context.Background(), "auth-req-fault")
	if err != nil || stored.Status != store.CIBARequestStatusApproved {
		t.Fatalf("approval after the fault: status=%v err=%v, want Approved", stored.Status, err)
	}
	users.setFault(nil)
	f.deps.Clock = fixedClock{now: f.clock.now.Add(ciba.DefaultInterval)}
	if rec := f.post(t, cibaForm("auth-req-fault")); rec.Code != http.StatusOK {
		t.Fatalf("poll after the fault cleared: status=%d body=%s", rec.Code, rec.Body.String())
	}
}
