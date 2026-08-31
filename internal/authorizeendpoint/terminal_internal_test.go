package authorizeendpoint

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// terminalNow is the instant every row below validates against.
var terminalNow = time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

// terminalDeps is a resolved value with just enough wiring for the
// validator: a clock, the claims toggle in its default (on) state, and
// the grant substore the consent re-check reads when the exit did not
// resolve a grant itself.
func terminalDeps(grants store.GrantStore) resolved {
	return resolved{Deps: Deps{
		Grants:                 grants,
		Clock:                  fixedAuthorizeClock(terminalNow),
		ClaimsParameterEnabled: true,
	}}
}

func terminalGrant() *store.Grant {
	return &store.Grant{
		ID:       "grant-terminal",
		Subject:  "user-1",
		ClientID: "client-1",
		Scope:    []string{"openid", "profile"},
		AuthTime: terminalNow.Add(-time.Hour),
	}
}

// TestValidateTerminalAuthorization covers the invariants the single
// gate re-establishes for every exit that emits an authorization code.
// Each row is an authorization some exit believed it could serve, and
// the sentinel the gate answers with.
func TestValidateTerminalAuthorization(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name string
		req  *authorize.Request
		in   terminalAuthorization
		want error
	}{
		{
			name: "consistent silent mint passes",
			req:  &authorize.Request{ClientID: "client-1", Scope: []string{"openid"}},
			in: terminalAuthorization{
				Subject:                "user-1",
				Scope:                  []string{"openid"},
				AuthTime:               terminalNow.Add(-time.Hour),
				SessionBacked:          true,
				ConsentFromCachedGrant: true,
				Grant:                  terminalGrant(),
			},
		},
		{
			name: "no subject bound",
			req:  &authorize.Request{ClientID: "client-1"},
			in:   terminalAuthorization{Grant: terminalGrant()},
			want: errTerminalSubjectMissing,
		},
		{
			name: "grant belongs to another subject",
			req:  &authorize.Request{ClientID: "client-1", Scope: []string{"openid"}},
			in: terminalAuthorization{
				Subject: "user-2",
				Scope:   []string{"openid"},
				Grant:   terminalGrant(),
			},
			want: errTerminalGrantMismatch,
		},
		{
			name: "grant does not hold the scope the code would carry",
			req:  &authorize.Request{ClientID: "client-1", Scope: []string{"openid", "email"}},
			in: terminalAuthorization{
				Subject: "user-1",
				Scope:   []string{"openid", "email"},
				Grant:   terminalGrant(),
			},
			want: errTerminalGrantMismatch,
		},
		{
			name: "grant carries another request's claims projection",
			req: &authorize.Request{
				ClientID: "client-1",
				Scope:    []string{"openid"},
				Claims: &authorize.ClaimsRequest{
					IDToken: map[string]authorize.ClaimSpec{"email": {Essential: true}},
				},
			},
			in: terminalAuthorization{
				Subject: "user-1",
				Scope:   []string{"openid"},
				Grant:   terminalGrant(),
			},
			want: errTerminalGrantMismatch,
		},
		{
			name: "session-backed exit under prompt=login",
			req: &authorize.Request{
				ClientID: "client-1",
				Scope:    []string{"openid"},
				Prompt:   []string{interaction.PromptLogin},
			},
			in: terminalAuthorization{
				Subject:       "user-1",
				Scope:         []string{"openid"},
				AuthTime:      terminalNow.Add(-time.Hour),
				SessionBacked: true,
				Grant:         terminalGrant(),
			},
			want: errStaleAuthentication,
		},
		{
			name: "session-backed exit past max_age",
			req:  &authorize.Request{ClientID: "client-1", Scope: []string{"openid"}, MaxAge: ptrInt64(60)},
			in: terminalAuthorization{
				Subject:       "user-1",
				Scope:         []string{"openid"},
				AuthTime:      terminalNow.Add(-time.Hour),
				SessionBacked: true,
				Grant:         terminalGrant(),
			},
			want: errStaleAuthentication,
		},
		{
			name: "a max_age too large to widen into a duration still admits the session",
			req:  &authorize.Request{ClientID: "client-1", Scope: []string{"openid"}, MaxAge: ptrInt64(99999999999)},
			in: terminalAuthorization{
				Subject:                "user-1",
				Scope:                  []string{"openid"},
				AuthTime:               terminalNow.Add(-time.Hour),
				SessionBacked:          true,
				ConsentFromCachedGrant: true,
				Grant:                  terminalGrant(),
			},
		},
		{
			name: "session-backed exit outside the requested acr",
			req: &authorize.Request{
				ClientID:  "client-1",
				Scope:     []string{"openid"},
				ACRValues: []string{"urn:example:strong"},
			},
			in: terminalAuthorization{
				Subject:       "user-1",
				Scope:         []string{"openid"},
				AuthTime:      terminalNow.Add(-time.Hour),
				ACR:           "urn:example:weak",
				SessionBacked: true,
				Grant:         terminalGrant(),
			},
			want: errACRUnmet,
		},
		{
			name: "a ceremony that ran this attempt owns its own acr",
			req: &authorize.Request{
				ClientID:  "client-1",
				Scope:     []string{"openid"},
				ACRValues: []string{"urn:example:strong"},
			},
			in: terminalAuthorization{
				Subject:         "user-1",
				Scope:           []string{"openid"},
				AuthTime:        terminalNow,
				ACR:             "urn:example:resolved-by-policy",
				ConsentAnswered: true,
			},
		},
		{
			name: "pre-marked consent against a subject with no grant",
			req:  &authorize.Request{ClientID: "client-1", Scope: []string{"openid"}},
			in: terminalAuthorization{
				Subject:                "user-without-grant",
				Scope:                  []string{"openid"},
				AuthTime:               terminalNow,
				ConsentFromCachedGrant: true,
			},
			want: errTerminalConsentUncovered,
		},
		{
			name: "pre-marked consent against the subject that consented",
			req:  &authorize.Request{ClientID: "client-1", Scope: []string{"openid"}},
			in: terminalAuthorization{
				Subject:                "user-1",
				Scope:                  []string{"openid"},
				AuthTime:               terminalNow,
				ConsentFromCachedGrant: true,
			},
		},
		{
			name: "an answered ceremony is authoritative for the subject it ran under",
			req:  &authorize.Request{ClientID: "client-1", Scope: []string{"openid"}},
			in: terminalAuthorization{
				Subject:                "user-without-grant",
				Scope:                  []string{"openid"},
				AuthTime:               terminalNow,
				ConsentAnswered:        true,
				ConsentFromCachedGrant: true,
			},
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			backing := inmem.New(inmem.WithClock(fixedAuthorizeClock(terminalNow)))
			if err := backing.Grants().Save(context.Background(), terminalGrant()); err != nil {
				t.Fatalf("Save grant: %v", err)
			}
			err := validateTerminalAuthorization(
				context.Background(),
				terminalDeps(backing.Grants()),
				row.req,
				row.in,
			)
			if row.want == nil {
				if err != nil {
					t.Fatalf("validateTerminalAuthorization = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, row.want) {
				t.Fatalf("validateTerminalAuthorization = %v, want %v", err, row.want)
			}
		})
	}
}

func ptrInt64(v int64) *int64 { return &v }

// TestTerminateInteraction_ChooserSubjectMismatchRetiresTheRecord covers
// the chooser pick whose session no longer belongs to the subject the
// chain bound. The condition is permanent: the record and the ceremony
// cookies have to go, or the browser replays the same completed chain
// into the same failure with no way out but deleting the row by hand.
func TestTerminateInteraction_ChooserSubjectMismatchRetiresTheRecord(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clock := fixedAuthorizeClock(terminalNow)
	backing := inmem.New(inmem.WithClock(clock))
	cookieCodec, err := cookie.NewCodec(bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatalf("cookie.NewCodec: %v", err)
	}
	sessionCodec, err := sessions.NewCodec(cookieCodec)
	if err != nil {
		t.Fatalf("sessions.NewCodec: %v", err)
	}
	manager, err := sessions.NewManager(sessions.Config{
		Codec: sessionCodec,
		Store: backing.Sessions(),
		Clock: func() time.Time { return terminalNow },
	})
	if err != nil {
		t.Fatalf("sessions.NewManager: %v", err)
	}
	// The session the chooser bound belongs to somebody other than the
	// subject the completed chain reports.
	picked, err := manager.Issue(ctx, sessions.Login{
		Subject:  "user-picked",
		AuthTime: terminalNow,
		ACR:      "urn:example:strong",
		AMR:      []string{"pwd"},
	})
	if err != nil {
		t.Fatalf("Issue picked session: %v", err)
	}

	state := authorize.RequestState{Library: authorize.RequestSnapshot{
		ClientID:     "client-1",
		ResponseType: "code",
		RedirectURI:  "https://rp.example.com/cb",
		State:        "state-1",
		Scope:        []string{"openid"},
	}}
	raw, err := authorize.MarshalState(state)
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}
	rec := &store.Interaction{
		ID:        "interaction-chooser-mismatch",
		ClientID:  "client-1",
		Step:      "interaction.chooser",
		RawState:  raw,
		ExpiresAt: terminalNow.Add(time.Hour),
		CreatedAt: terminalNow,
		UpdatedAt: terminalNow,
	}
	if err := backing.Interactions().Save(ctx, rec); err != nil {
		t.Fatalf("Save interaction: %v", err)
	}

	deps := resolved{Deps: Deps{
		Grants:       backing.Grants(),
		Interactions: backing.Interactions(),
		Sessions:     manager,
		CookieCodec:  cookieCodec,
		Clock:        clock,
		Issuer:       "https://op.example.com",
	}}
	recorder := httptest.NewRecorder()
	terminateInteraction(
		recorder,
		httptest.NewRequestWithContext(ctx, http.MethodPost,
			"https://op.example.com/interaction/"+rec.ID, http.NoBody),
		deps,
		rec,
		state,
		authn.State{
			ChooserBoundSubject:      true,
			ChooserGroupID:           picked.ChooserGroupID,
			ChooserSelectedSessionID: picked.SessionID,
		},
		interaction.Result{Subject: "user-other"},
	)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s, want a redirect carrying the refusal",
			recorder.Code, recorder.Body.String())
	}
	loc, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if code := loc.Query().Get("code"); code != "" {
		t.Fatalf("a code was issued for a session owned by another subject: %s", loc)
	}
	if got := loc.Query().Get("error"); got != errAccessDenied {
		t.Fatalf("error=%q want %q (redirect %s)", got, errAccessDenied, loc)
	}
	if _, err := backing.Interactions().Find(ctx, rec.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the completed interaction survived a permanent refusal: %v", err)
	}
	assertClearedCookies(t, recorder, cookie.InteractionProfile.Name, cookie.CSRFProfile.Name)
}

// assertClearedCookies fails unless the response instructs the browser
// to drop every named cookie.
func assertClearedCookies(t *testing.T, recorder *httptest.ResponseRecorder, names ...string) {
	t.Helper()
	cleared := map[string]bool{}
	for _, c := range recorder.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			cleared[c.Name] = true
		}
	}
	for _, name := range names {
		if !cleared[name] {
			t.Errorf("%s was not cleared: Set-Cookie=%v", name, recorder.Header().Values("Set-Cookie"))
		}
	}
}
