package endsession_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// readFaultSessionStore fails the session read on demand. The store
// starts healthy so a session can be issued and its cookie sealed
// before the fault appears, which is the order a real outage arrives
// in: the browser holds a cookie for a session that exists, and the OP
// then loses the ability to look it up.
type readFaultSessionStore struct {
	store.SessionStore
	err error
}

func (s *readFaultSessionStore) arm(err error) { s.err = err }

func (s *readFaultSessionStore) Find(ctx context.Context, id string) (*store.Session, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.SessionStore.Find(ctx, id)
}

// TestHandler_HintDuringSessionReadFaultDoesNotRedirectAsSignedOut
// covers the exemption the id_token_hint buys. A hint skips the
// confirmation gate when the OP has established that no session
// resolves, because then the request cannot destroy anyone's login
// state. A session read that failed establishes nothing: the session it
// could not read may be live, so the exemption must not apply and the
// RP must not be redirected as though the sign-out had completed.
//
// The assertions run in the order the damage would occur: no redirect
// (the RP is not told the user is signed out), a recorded failure (the
// operator can see the logout did not happen), and the session row
// still present once the backend recovers (there was in fact something
// to terminate all along).
func TestHandler_HintDuringSessionReadFaultDoesNotRedirectAsSignedOut(t *testing.T) {
	t.Parallel()

	var fault *readFaultSessionStore
	h := newHarness(t, withSessionStoreWrapper(func(s store.SessionStore) store.SessionStore {
		fault = &readFaultSessionStore{SessionStore: s}
		return fault
	}))
	cookieValue, sessionID := h.issueSession(t)
	fault.arm(errors.New("session backend unavailable"))

	resp := h.doGET(t, url.Values{
		"id_token_hint":            {h.signIDToken(t, nil)},
		"post_logout_redirect_uri": {h.postLogoutURI},
	}, cookieValue)
	defer resp.Body.Close()

	if location := resp.Header.Get("Location"); location != "" {
		t.Fatalf("status %d redirected to %q; the OP never established that the session was gone",
			resp.StatusCode, location)
	}
	if resp.StatusCode/100 == 2 {
		t.Fatalf("status = %d, want a failure status while the session store cannot answer", resp.StatusCode)
	}
	if h.audit.find("session.destroy_failed") == nil {
		t.Fatalf("session.destroy_failed not emitted: %#v", h.audit.events)
	}
	if h.audit.find("session.destroyed") != nil {
		t.Fatalf("session.destroyed emitted although nothing was read: %#v", h.audit.events)
	}

	fault.arm(nil)
	sess, err := h.store.Sessions().Find(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("Sessions().Find: %v", err)
	}
	if sess == nil {
		t.Fatal("session row is gone; the failed logout must not have deleted anything")
	}
}
