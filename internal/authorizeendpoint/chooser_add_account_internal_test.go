package authorizeendpoint

import (
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// chooserStampFixture builds the inputs stampChooserAddAccountURL needs:
// a live chooser prompt and the persisted request snapshot.
func chooserStampFixture() (*interaction.Prompt, authn.State, authorize.RequestState) {
	prompt := &interaction.Prompt{
		Type: authn.ChooserPromptType,
		Data: interaction.ChooserPromptData{},
	}
	st := authn.State{ChooserGroupID: "grp-1"}
	reqState := authorize.RequestState{
		Library: authorize.RequestSnapshot{
			ClientID:     "client-1",
			ResponseType: "code",
			RedirectURI:  "https://rp.example/callback",
			Scope:        []string{"openid"},
		},
	}
	return prompt, st, reqState
}

func chooserAddAccountURL(t *testing.T, prompt *interaction.Prompt) string {
	t.Helper()
	data, ok := prompt.Data.(interaction.ChooserPromptData)
	if !ok {
		t.Fatalf("prompt data is %T, want ChooserPromptData", prompt.Data)
	}
	return data.AddAccountURL
}

// TestStampChooserAddAccountURL_NonPARStampsURL pins that, absent a PAR
// mandate, the chooser prompt receives a followable bare-param
// /authorize add-account URL carrying the OP-private markers.
func TestStampChooserAddAccountURL_NonPARStampsURL(t *testing.T) {
	t.Parallel()

	deps := resolved{Deps: Deps{AuthorizePath: "/oidc/auth"}}
	prompt, st, reqState := chooserStampFixture()

	if err := stampChooserAddAccountURL(deps, prompt, st, reqState); err != nil {
		t.Fatalf("stampChooserAddAccountURL: %v", err)
	}
	got := chooserAddAccountURL(t, prompt)
	if got == "" {
		t.Fatal("AddAccountURL empty without RequirePAR; chooser add-account link missing")
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse AddAccountURL %q: %v", got, err)
	}
	if u.Path != "/oidc/auth" {
		t.Fatalf("AddAccountURL path=%q want /oidc/auth", u.Path)
	}
	q := u.Query()
	if q.Get("_oidc_add_account") != "1" || q.Get("_oidc_chooser_group") != "grp-1" {
		t.Fatalf("AddAccountURL missing add-account markers: %s", got)
	}
	if q.Get("prompt") != interaction.PromptLogin {
		t.Fatalf("AddAccountURL prompt=%q want %q", q.Get("prompt"), interaction.PromptLogin)
	}
}

// TestStampChooserAddAccountURL_RequirePARLeavesEmpty pins that under a
// PAR mandate (FAPI 2.0) the OP does NOT hand the chooser UI a bare-param
// /authorize URL: /authorize rejects any request without a request_uri
// before the markers are read, so such a link is unfollowable. Leaving
// AddAccountURL empty lets the driver suppress the broken affordance
// instead of rendering a link that 400s.
func TestStampChooserAddAccountURL_RequirePARLeavesEmpty(t *testing.T) {
	t.Parallel()

	deps := resolved{Deps: Deps{AuthorizePath: "/oidc/auth", RequirePAR: true}}
	prompt, st, reqState := chooserStampFixture()

	if err := stampChooserAddAccountURL(deps, prompt, st, reqState); err != nil {
		t.Fatalf("stampChooserAddAccountURL: %v", err)
	}
	if got := chooserAddAccountURL(t, prompt); got != "" {
		t.Fatalf("AddAccountURL=%q under RequirePAR, want empty (OP would reject the bare-param URL)", got)
	}
}

// TestChooserAddAccountRequested_Forgery pins the security boundary that
// stops session grafting: the OP-private _oidc_add_account /
// _oidc_chooser_group markers are honoured ONLY when the request still
// presents a session cookie whose chooser group equals the marker's
// group. A forged marker presented with no session, a session for a
// different group, or an empty group MUST NOT graft the new login into
// the attacker-named group — the request falls back to a fresh login
// that starts its own chooser group (ChooserAddAccount=false, group="").
func TestChooserAddAccountRequested_Forgery(t *testing.T) {
	t.Parallel()

	activeWithGroup := func(group string) *sessions.Active {
		return &sessions.Active{Session: &store.Session{ChooserGroupID: group}}
	}

	tests := []struct {
		name       string
		req        *authorize.Request
		active     *sessions.Active
		wantHonour bool
	}{
		{
			name:       "legitimate matching group",
			req:        &authorize.Request{InternalAddAccount: true, InternalChooserGroupID: "grp-A"},
			active:     activeWithGroup("grp-A"),
			wantHonour: true,
		},
		{
			name:       "forged marker, no session",
			req:        &authorize.Request{InternalAddAccount: true, InternalChooserGroupID: "grp-A"},
			active:     nil,
			wantHonour: false,
		},
		{
			name:       "forged marker, nil session record",
			req:        &authorize.Request{InternalAddAccount: true, InternalChooserGroupID: "grp-A"},
			active:     &sessions.Active{Session: nil},
			wantHonour: false,
		},
		{
			name:       "forged marker, session for a different group",
			req:        &authorize.Request{InternalAddAccount: true, InternalChooserGroupID: "grp-A"},
			active:     activeWithGroup("grp-B"),
			wantHonour: false,
		},
		{
			name:       "empty group must not match empty marker",
			req:        &authorize.Request{InternalAddAccount: true, InternalChooserGroupID: ""},
			active:     activeWithGroup(""),
			wantHonour: false,
		},
		{
			name:       "marker absent even with matching group",
			req:        &authorize.Request{InternalAddAccount: false, InternalChooserGroupID: "grp-A"},
			active:     activeWithGroup("grp-A"),
			wantHonour: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := chooserAddAccountRequested(tc.req, tc.active)
			if got != tc.wantHonour {
				t.Fatalf("chooserAddAccountRequested=%v want %v", got, tc.wantHonour)
			}
			// The group surfaced into the authn state must follow the
			// gate: a non-honoured request leaks no group, so the fresh
			// login starts its own chooser group.
			gotGroup := chooserAddAccountGroupID(tc.req, tc.active)
			if tc.wantHonour {
				if gotGroup != tc.active.Session.ChooserGroupID {
					t.Fatalf("chooserAddAccountGroupID=%q want %q", gotGroup, tc.active.Session.ChooserGroupID)
				}
			} else if gotGroup != "" {
				t.Fatalf("chooserAddAccountGroupID=%q want empty for a non-honoured request", gotGroup)
			}
		})
	}
}
