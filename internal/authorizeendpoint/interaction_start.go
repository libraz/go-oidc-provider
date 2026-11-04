package authorizeendpoint

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/consent"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// startInteraction creates the persisted interaction record with a
// freshly-initialised orchestrator [authn.State], sets the
// __Host-oidc_interaction cookie, and redirects the browser to
// /interaction/{uid}. The orchestrator runs on the first GET and
// emits the initial prompt.
// hint is the decision-matrix outcome: hint.grant is the grant the
// dispatcher resolved for (subject, client_id), or nil when no cached
// grant covers this attempt. When it is non-nil and already covers the
// requested scope, the helper pre-marks the built-in consent
// interaction as already run so the user is not prompted to re-confirm
// scopes they have already granted. hint.reauth carries the
// "may not be served from the existing session" verdict onto the
// orchestrator state.
func startInteraction(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
	hint authorizeHint,
) {
	if deps.Authn == nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "interaction is not configured")
		return
	}
	uid, err := keys.RandomBase64URL(uidByteLength)
	if err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not allocate interaction id")
		return
	}
	now := deps.now().UTC()
	authnState := initialAuthnState(r, deps, req, client, active, hint, uid, now)
	authnRaw, err := encodeAuthnState(authnState)
	if err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not marshal interaction state")
		return
	}
	state := authorize.RequestState{
		Library: authorize.SnapshotFrom(req, now),
		Authn:   authnRaw,
	}
	raw, err := authorize.MarshalState(state)
	if err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not marshal interaction state")
		return
	}
	rec := &store.Interaction{
		ID:        uid,
		ClientID:  client.ID,
		RawState:  raw,
		ExpiresAt: now.Add(deps.InteractionTTL),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := deps.Interactions.Save(r.Context(), rec); err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not persist interaction")
		return
	}
	if err := setInteractionCookie(w, deps, uid); err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not set interaction cookie")
		return
	}
	httpx.StampNoStore(w)
	target := deps.authorizeRedirectBase() + "/" + uid
	http.Redirect(w, r, target, http.StatusFound)
}

func initialAuthnState(
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
	hint authorizeHint,
	uid string,
	now time.Time,
) authn.State {
	existing := hint.grant
	willRunChooser := slices.Contains(req.Prompt, interaction.PromptSelectAccount) && active != nil
	addAccount := chooserAddAccountRequested(req, active)
	// prompt=create binds the account Registration creates, never the
	// session's: no subject, entry authentication or grant carries over.
	registration := slices.Contains(req.Prompt, interaction.PromptCreate)
	subject := currentSubject(active)
	if registration {
		subject = ""
	}
	interactionsRun := initialInteractionsRun(req, existing, willRunChooser || addAccount || registration)
	// The first-party auto-grant is not derived from any subject's cached
	// grant, so the bindsOtherSubject refusal above does not apply to it.
	autoGranted := hint.autoGrant != nil || hint.consentAutoGranted
	if autoGranted {
		interactionsRun[consent.Name] = true
	}
	return authn.State{
		ReauthRequired:           hint.reauth,
		EntryAuthn:               entryAuthn(active, hint.reauth || willRunChooser || addAccount),
		InteractionUID:           uid,
		ClientID:                 client.ID,
		Client:                   projectClientView(client, req.RedirectURI),
		Subject:                  subject,
		RemoteIP:                 clientIPFromRequest(r, deps),
		UserAgent:                truncateUserAgent(r.UserAgent()),
		AcceptLanguage:           r.Header.Get("Accept-Language"),
		AuthTime:                 now,
		ActiveFactorIdx:          -1,
		Phase:                    hint.startPhase,
		InteractionsRun:          interactionsRun,
		ConsentAutoGranted:       autoGranted,
		RequestedScopes:          append([]string(nil), req.Scope...),
		ACRValues:                requestedACRValues(req),
		ChooserGroupID:           activeChooserGroupID(active, willRunChooser),
		ChooserAddAccount:        addAccount,
		ChooserAddAccountGroupID: chooserAddAccountGroupID(req, active),
		Registration:             registration,
	}
}

// initialInteractionsRun decides whether the built-in consent interaction
// starts out already marked as run.
//
// bindsOtherSubject reports that the chain is expected to bind an account
// other than the cookie-resolved one — the chooser picking a sibling
// session, an AddAccountURL-derived login joining a second account to
// the group, or a prompt=create chain binding the account its
// Registration step creates. The grant the dispatcher looked up
// describes the *current* subject, so it says nothing about what the
// incoming one has approved: pre-marking consent there would carry one
// account's approval over to another. The terminal gate re-runs the coverage predicate against the
// bound subject and fails the ceremony closed, so the pre-mark does not
// leak a code — it costs the second account its consent screen and, with
// it, the whole authorization.
//
// Otherwise the pre-marking uses the same coverage predicate the
// dispatcher used to decide it needed an interaction at all, so a
// request routed here *because* consent is owed always reaches the
// consent screen.
func initialInteractionsRun(req *authorize.Request, existing *store.Grant, bindsOtherSubject bool) map[string]bool {
	interactionsRun := map[string]bool{}
	if !bindsOtherSubject && consentAlreadyCovered(req, existing) {
		interactionsRun[consent.Name] = true
	}
	return interactionsRun
}

func activeChooserGroupID(active *sessions.Active, willRunChooser bool) string {
	if willRunChooser && active.Session != nil {
		return active.Session.ChooserGroupID
	}
	return ""
}

func chooserAddAccountRequested(req *authorize.Request, active *sessions.Active) bool {
	return req.InternalAddAccount && active != nil && active.Session != nil &&
		active.Session.ChooserGroupID != "" &&
		active.Session.ChooserGroupID == req.InternalChooserGroupID
}

func chooserAddAccountGroupID(req *authorize.Request, active *sessions.Active) string {
	if chooserAddAccountRequested(req, active) {
		return active.Session.ChooserGroupID
	}
	return ""
}

// entryAuthn records the authentication of the session a chain takes
// its subject from. A chain that must re-authenticate, or that may bind
// another account (the chooser, add-account), records none.
func entryAuthn(active *sessions.Active, mayNotServe bool) *authn.EntryAuthn {
	if mayNotServe || active == nil || active.Session == nil || active.Session.Subject == "" {
		return nil
	}
	return &authn.EntryAuthn{
		Subject:  active.Session.Subject,
		ACR:      active.Session.ACR,
		AMR:      slices.Clone(active.Session.AMR),
		AuthTime: active.Session.AuthTime,
	}
}

// currentSubject returns the active session's subject or empty when there
// is no session. The helper exists so the call sites stay free of nil
// handling boilerplate.
func currentSubject(active *sessions.Active) string {
	if active == nil || active.Session == nil {
		return ""
	}
	return active.Session.Subject
}

// projectClientView builds the read-only template projection of
// [store.Client]. The function intentionally ships the field set
// fixed by [interaction.ClientView] — adding a field here is a
// deliberate widening of the template trust boundary and requires
// its own ADR.
//
// A client resolved from a client ID metadata document is self-asserted,
// so its view also names the document host and this request's redirect
// host (and whether that host is loopback) for the user to judge, and
// drops the logo: hotlinking a document-supplied logo_uri lets the
// document host observe the consent screen.
func projectClientView(c *store.Client, redirectURI string) interaction.ClientView {
	if c == nil {
		return interaction.ClientView{}
	}
	view := interaction.ClientView{
		ClientID:  c.ID,
		Name:      c.ClientName,
		LogoURL:   c.LogoURI,
		ClientURI: c.ClientURI,
		PolicyURI: c.PolicyURI,
		TosURI:    c.TosURI,
	}
	if c.Source != store.ClientSourceMetadataDocument {
		return view
	}
	view.LogoURL = ""
	if u, err := url.Parse(c.ID); err == nil {
		view.MetadataDocumentHost = u.Host
	}
	if u, err := url.Parse(redirectURI); err == nil {
		view.RedirectHost = u.Hostname()
		view.RedirectLoopback = isLoopbackHost(view.RedirectHost)
	}
	return view
}

// isLoopbackHost reports whether host is "localhost" or a loopback IP
// literal (127.0.0.0/8, ::1).
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// setInteractionCookie seals uid under the interaction AAD and writes it as
// the __Host-oidc_interaction cookie.
func setInteractionCookie(w http.ResponseWriter, deps resolved, uid string) error {
	value, err := deps.CookieCodec.Seal([]byte(uid), []byte(interactionAAD))
	if err != nil {
		return fmt.Errorf("authorizeendpoint: seal interaction cookie: %w", err)
	}
	c, err := cookie.Build(cookie.InteractionProfile, value)
	if err != nil {
		return fmt.Errorf("authorizeendpoint: build interaction cookie: %w", err)
	}
	http.SetCookie(w, c)
	return nil
}
