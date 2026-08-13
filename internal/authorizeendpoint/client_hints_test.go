package authorizeendpoint_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
)

// TestAuthorize_ClientHintsReachPersistedChainState pins the hop that
// makes the two LoginContext faces agree.
//
// A rule predicate reads the public op.ClientHints, and that value is
// assembled twice: by the login-flow orchestrator from the chain state
// persisted here, and by the ACR resolver from the terminal request. The
// resolver has always read Accept-Language straight off the request, so
// a chain state that does not record it makes the same predicate see a
// language on one face and nothing on the other, depending only on where
// in the chain it runs.
//
// The remote address is asserted alongside it because it shares the
// property that matters: it must be an address or nothing. netip.Addr
// renders its zero value as the literal "invalid IP", which is not an
// address but reads like one, and reaches the audit trail the same way.
func TestAuthorize_ClientHintsReachPersistedChainState(t *testing.T) {
	t.Parallel()

	const acceptLanguage = "ja,en;q=0.9"

	h := newHarness(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+goodAuthorizeValues().Encode(), http.NoBody)
	req.Header.Set("Accept-Language", acceptLanguage)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status=%d, want 302", resp.StatusCode)
	}
	uid := strings.TrimPrefix(resp.Header.Get("Location"), h.interactionPth+"/")
	if uid == "" {
		t.Fatalf("could not extract uid from Location %q", resp.Header.Get("Location"))
	}

	rec, err := h.store.Interactions().Find(context.Background(), uid)
	if err != nil {
		t.Fatalf("Find interaction: %v", err)
	}
	state, err := authorize.UnmarshalState(rec.RawState)
	if err != nil {
		t.Fatalf("UnmarshalState: %v", err)
	}
	var authnState authn.State
	if err := json.Unmarshal(state.Authn, &authnState); err != nil {
		t.Fatalf("decode persisted chain state: %v", err)
	}

	if authnState.AcceptLanguage != acceptLanguage {
		t.Errorf("AcceptLanguage = %q, want %q — the orchestrator face cannot populate "+
			"op.ClientHints.AcceptLanguage from a chain state that never recorded it",
			authnState.AcceptLanguage, acceptLanguage)
	}
	if got := authnState.RemoteIPString(); got == "invalid IP" {
		t.Errorf("RemoteIPString() = %q; a predicate cannot tell that placeholder from an "+
			"observed address", got)
	}
}
