package endsession

import (
	"strings"
	"testing"
)

// A request-controlled value that spells a later placeholder must be
// rendered literally, and the real value must reach its own field.
func TestBuildConfirmationBodyDoesNotRewriteSubstitutedValues(t *testing.T) {
	t.Parallel()

	body := buildConfirmationBody("tok", confirmationForm{
		action:           "/end_session",
		clientID:         "{STATE}",
		state:            "{POST_LOGOUT}",
		postLogout:       "https://rp.example.com/after",
		uiLocales:        "{SCOPE_MESSAGE}",
		scopeFingerprint: "{CHOOSER_GROUP_ID}",
		chooserGroupID:   "grp",
		page:             confirmationPage{title: "T", body: "msg", button: "Go"},
	})

	for _, want := range []string{
		`name="client_id" value="{STATE}"`,
		`name="state" value="{POST_LOGOUT}"`,
		`name="post_logout_redirect_uri" value="https://rp.example.com/after"`,
		`name="ui_locales" value="{SCOPE_MESSAGE}"`,
		`name="logout_scope_fingerprint" value="{CHOOSER_GROUP_ID}"`,
		`name="chooser_group_id" value="grp"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
}

func TestRenderLoggedOutBodyDoesNotRewriteSubstitutedValues(t *testing.T) {
	t.Parallel()

	body := renderLoggedOutBody(loggedOutPage{locale: "en", title: "{BODY}", body: "real body"})
	if got := strings.Count(body, "<p>real body</p>"); got != 1 {
		t.Fatalf("body paragraph count=%d want 1:\n%s", got, body)
	}
	if got := strings.Count(body, "{BODY}"); got != 2 {
		t.Fatalf("literal {BODY} count=%d want 2 (title and h1):\n%s", got, body)
	}
}
