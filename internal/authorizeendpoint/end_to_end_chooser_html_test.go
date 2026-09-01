package authorizeendpoint_test

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestEndToEnd_ChooserRendersUsablePageOnDefaultHTMLSurface drives
// prompt=select_account through a Provider whose only interaction
// surface is the zero-configuration one — [interaction.HTMLDriver],
// which op.New installs when the embedder supplies neither a SPA shell
// nor a Driver of its own. The chooser interaction is registered for
// every Provider, so this is the page an embedder who configured
// nothing actually serves.
//
// The assertions are what the page has to carry to be answerable at
// all: every account in the group is a control the user can activate,
// each is labelled with the name the user store holds rather than the
// opaque subject, the add-account link is present, and no message key
// reaches the user as text.
func TestEndToEnd_ChooserRendersUsablePageOnDefaultHTMLSurface(t *testing.T) {
	t.Parallel()

	clock := &monotonicChooserClock{
		now:  time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC),
		step: time.Microsecond,
	}
	cookieKey := []byte(chooserCookieKey)
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithCookieKeys(cookieKey),
			// Replaces the testkit's auto-consent driver with the
			// library's own zero-configuration surface. Nothing else
			// about the Provider is customised.
			op.WithInteractionDriver(interaction.HTMLDriver{}),
		),
	)

	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-chooser-html",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	ctx := context.Background()
	// The user records the chooser labels its rows from. This is the
	// same store the OP projects claims out of; the chooser reads the
	// "name" claim rather than inventing a parallel notion of display
	// name.
	accounts := []struct{ subject, name string }{
		{"user-A", "Alice Example"},
		{"user-B", "Bob Example"},
	}
	for _, account := range accounts {
		tk.Store.PutUser(ctx, &store.User{
			Subject: account.subject,
			Claims:  map[string]any{"name": account.name},
		})
	}

	mgr, _ := newChooserSessionsManager(t, tk.Store.Sessions(), cookieKey, clock)
	sessA := establishFresh(t, mgr,
		sessions.Login{Subject: accounts[0].subject, AuthTime: clock.Current()}, clock.Current())
	sessB := establishAddAccount(t, mgr, sessA.Cookie, sessions.Login{
		Subject:  accounts[1].subject,
		AuthTime: clock.Current(),
	}, clock.Current())

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := tk.HTTPClient(jar)

	values := e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0])
	values.Set("prompt", "select_account")
	authReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		tk.Server.URL+"/oidc/auth?"+values.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /authorize: %v", err)
	}
	authReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie})
	authResp, err := client.Do(authReq)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status=%d, want 302", authResp.StatusCode)
	}
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	interactionCookie := findCookie(authResp.Cookies(), cookie.InteractionProfile.Name)
	if interactionCookie == nil {
		t.Fatal("interaction cookie missing on authorize 302")
	}

	stepReq, err := http.NewRequestWithContext(ctx, http.MethodGet, tk.Server.URL+location.Path, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest GET interaction: %v", err)
	}
	stepReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie})
	stepReq.AddCookie(interactionCookie)
	stepResp, err := client.Do(stepReq)
	if err != nil {
		t.Fatalf("GET interaction: %v", err)
	}
	defer stepResp.Body.Close()
	if stepResp.StatusCode != http.StatusOK {
		t.Fatalf("interaction GET status=%d", stepResp.StatusCode)
	}
	if got := stepResp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("Content-Type=%q, want text/html (the default surface is the HTML driver)", got)
	}
	raw, err := io.ReadAll(stepResp.Body)
	if err != nil {
		t.Fatalf("read interaction body: %v", err)
	}
	page := string(raw)

	for _, session := range []sessions.Outcome{sessA, sessB} {
		control := `name="session_id" value="` + session.SessionID + `"`
		if !strings.Contains(page, control) {
			t.Errorf("session %q is not submittable from the rendered chooser: %s", session.SessionID, page)
		}
	}
	// The display names prove the whole reference path: the built-in
	// chooser resolved them from the shipped user store and the shipped
	// driver rendered them. A subject appearing where the name should
	// be means the resolution silently produced nothing.
	for _, account := range accounts {
		if !strings.Contains(page, account.name) {
			t.Errorf("the chooser row for %q is not labelled %q; the user store lookup produced nothing "+
				"and the user is left picking between opaque identifiers: %s",
				account.subject, account.name, page)
		}
	}
	if !strings.Contains(page, `<a href="`) {
		t.Errorf("the chooser page carries no add-account link, so an account outside the group is unreachable: %s", page)
	}
	for _, key := range []string{"interaction.chooser", "chooser.session_id"} {
		if strings.Contains(page, key) {
			t.Errorf("the rendered page shows the raw message key %q: %s", key, page)
		}
	}
}
