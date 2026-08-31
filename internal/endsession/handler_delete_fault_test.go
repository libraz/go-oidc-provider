package endsession_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// deleteFaultSessionStore fails the session delete on demand. It is the
// write-side counterpart of [readFaultSessionStore]: the OP can read the
// session it was asked to end, and then cannot remove it. The store
// starts healthy so a session can be issued and its cookie sealed before
// the fault appears.
type deleteFaultSessionStore struct {
	store.SessionStore
	err error
}

func (s *deleteFaultSessionStore) arm(err error) { s.err = err }

func (s *deleteFaultSessionStore) Delete(ctx context.Context, id string) error {
	if s.err != nil {
		return s.err
	}
	return s.SessionStore.Delete(ctx, id)
}

// TestHandler_SessionDeleteFaultDoesNotReportSignOut covers the case the
// audit stream used to be the only witness of: the session row survives
// the logout, and the browser is told the sign-out succeeded anyway. A
// user who deliberately signs out during a storage outage would walk away
// while an attacker holding a previously stolen cookie keeps access until
// the session expires on its own.
//
// The row that carries a post_logout_redirect_uri is the more dangerous
// of the two: the relying party is handed the redirect and drops its own
// session, so the only party still able to observe the live OP session is
// the attacker.
//
// The session cookie must survive too. Clearing it costs the browser the
// only handle it has on the session that is still running, which is the
// same reason the read-fault branch keeps it.
func TestHandler_SessionDeleteFaultDoesNotReportSignOut(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		query url.Values
	}{
		{name: "confirmation page", query: url.Values{}},
		{name: "post logout redirect", query: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var fault *deleteFaultSessionStore
			h := newHarness(t, withSessionStoreWrapper(func(s store.SessionStore) store.SessionStore {
				fault = &deleteFaultSessionStore{SessionStore: s}
				return fault
			}))
			cookieValue, sessionID := h.issueSession(t)

			query := tc.query
			if query == nil {
				query = url.Values{
					"client_id":                {h.clientID},
					"post_logout_redirect_uri": {h.postLogoutURI},
				}
			}
			// The fault covers the delete alone, so the confirmation POST
			// is one the OP fully admitted: every gate passed and the
			// session resolved, and only the destruction failed.
			fault.arm(errors.New("session backend unavailable"))
			resp := confirmScope(t, h, query, cookieValue)
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("status=%d want 503", resp.StatusCode)
			}
			if location := resp.Header.Get("Location"); location != "" {
				t.Errorf("redirected to %q although the session was not destroyed", location)
			}
			if hasAnySessionCookie(resp) {
				t.Errorf("session cookie rewritten although the session it names is still live: %v", resp.Cookies())
			}
			if h.audit.find("session.destroy_failed") == nil {
				t.Errorf("session.destroy_failed not emitted: %#v", h.audit.events)
			}
			if h.audit.find("session.destroyed") != nil {
				t.Errorf("session.destroyed emitted although the delete failed: %#v", h.audit.events)
			}

			fault.arm(nil)
			sess, err := h.store.Sessions().Find(context.Background(), sessionID)
			if err != nil {
				t.Fatalf("Sessions().Find: %v", err)
			}
			if sess == nil {
				t.Fatal("session row is gone; the failed logout must not have deleted anything")
			}
		})
	}
}
