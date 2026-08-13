package interaction_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// The account chooser is registered for every Provider, so a
// zero-configuration deployment that answers prompt=select_account
// renders it through HTMLDriver. The screen has to carry the whole
// decision: which accounts exist, how to pick one, and how to reach a
// login for an account that is not listed. None of that can come from
// the [interaction.FieldSpec] list, whose single field is an opaque
// session identifier the user has never been shown.

// chooserFixture is the prompt the built-in chooser interaction emits
// for a two-account group: one row the user store could label, one it
// could not.
func chooserFixture() interaction.Prompt {
	authTime := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	return interaction.Prompt{
		Type: "interaction.chooser",
		Data: interaction.ChooserPromptData{
			Accounts: []interaction.ChooserAccount{
				{SessionID: "sess-A", Subject: "alice", DisplayName: "Alice Example", AuthTime: authTime},
				{SessionID: "sess-B", Subject: "bob", AuthTime: authTime},
			},
			AddAccountURL: "/oidc/auth?prompt=login&client_id=rp-1",
		},
		Inputs: []interaction.FieldSpec{{
			Name:     interaction.ChooserSessionIDField,
			Kind:     interaction.FieldText,
			Label:    "chooser.session_id",
			Required: true,
			MaxLen:   64,
		}},
		StateRef:  "ref-chooser",
		CSRFToken: "csrf-5",
	}
}

// renderHTML returns the document HTMLDriver writes for prompt.
func renderHTML(tb testing.TB, prompt interaction.Prompt) string {
	tb.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oidc/interaction/u-1", http.NoBody)
	if err := (interaction.HTMLDriver{}).Render(rec, req, prompt); err != nil {
		tb.Fatalf("Render: %v", err)
	}
	return rec.Body.String()
}

// TestHTMLDriver_ChooserListsEveryAccountAndAddAccountLink asserts the
// three things the screen is useless without: every account in the
// group is present as a control that submits that account's session
// identifier, the identifier travels with the control rather than
// being typed, and the add-account link is rendered.
func TestHTMLDriver_ChooserListsEveryAccountAndAddAccountLink(t *testing.T) {
	t.Parallel()

	prompt := chooserFixture()
	data, ok := prompt.Data.(interaction.ChooserPromptData)
	if !ok {
		t.Fatalf("fixture Data is %T, want ChooserPromptData", prompt.Data)
	}
	body := renderHTML(t, prompt)

	for _, account := range data.Accounts {
		control := `<button type="submit" name="` + interaction.ChooserSessionIDField +
			`" value="` + account.SessionID + `">`
		if !strings.Contains(body, control) {
			t.Errorf("account %q (session %q) is not a submittable control; the user cannot pick it: %s",
				account.Subject, account.SessionID, body)
		}
	}

	if !strings.Contains(body, `href="/oidc/auth?prompt=login&amp;client_id=rp-1"`) {
		t.Errorf("AddAccountURL is not rendered as a link; an account absent from the group is unreachable: %s", body)
	}

	// The opaque identifier must never be something the user is asked
	// to supply. A text input named session_id is the shape that made
	// this screen unanswerable.
	if strings.Contains(body, `<input name="`+interaction.ChooserSessionIDField+`" type="text"`) {
		t.Errorf("session_id is rendered as a text input; its value is opaque and the user cannot know it: %s", body)
	}
}

// TestHTMLDriver_ChooserEmptyGroupStillOffersAddAccount pins the
// zero-account case. An empty chooser group is reachable (every session
// in it expired), and the page must still say so and offer the way out
// rather than rendering a form with nothing in it.
func TestHTMLDriver_ChooserEmptyGroupStillOffersAddAccount(t *testing.T) {
	t.Parallel()

	body := renderHTML(t, interaction.Prompt{
		Type:     "interaction.chooser",
		Data:     interaction.ChooserPromptData{AddAccountURL: "/oidc/auth?prompt=login"},
		StateRef: "ref-empty",
	})

	if strings.Contains(body, "<form") {
		t.Errorf("empty chooser rendered a form with nothing to submit: %s", body)
	}
	if !strings.Contains(body, `href="/oidc/auth?prompt=login"`) {
		t.Errorf("empty chooser omitted the add-account link, leaving the page with no affordance at all: %s", body)
	}
}

// TestHTMLDriver_ChooserSuppressesAddAccountLinkWhenUnavailable pins the
// other end: the orchestrator leaves AddAccountURL empty when it cannot
// mint one the OP would accept, and a link to nowhere is worse than no
// link.
func TestHTMLDriver_ChooserSuppressesAddAccountLinkWhenUnavailable(t *testing.T) {
	t.Parallel()

	body := renderHTML(t, interaction.Prompt{
		Type: "interaction.chooser",
		Data: interaction.ChooserPromptData{
			Accounts: []interaction.ChooserAccount{{SessionID: "sess-A", Subject: "alice"}},
		},
		StateRef: "ref-no-add",
	})

	if strings.Contains(body, "<a href") {
		t.Errorf("chooser rendered an anchor despite an empty AddAccountURL: %s", body)
	}
}

// dottedKey matches a bare i18n key — lowercase segments joined by
// dots, no spaces. Visible prose never takes this shape, so a token
// matching it in the rendered text is a key that reached the user
// because nothing resolved it.
var dottedKey = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]+)+$`)

// tagStripper removes markup so the assertion below reads only what a
// browser would display. Attribute values (notably the add-account
// URL, whose query string is not prose) go with it.
var tagStripper = regexp.MustCompile(`<[^>]*>`)

// TestHTMLDriver_ChooserShowsNoUnresolvedKeys asserts that nothing the
// user reads on the chooser page is a raw message key.
//
// Without a Translator the driver has only its built-in English to fall
// back on, which is the zero-configuration case: an embedder who wires
// no catalogue still gets prose. The prompt type and the field's label
// key are both checked explicitly because those are the two that
// reached the page verbatim — the heading was the prompt identifier and
// the input's label was the dotted key itself.
func TestHTMLDriver_ChooserShowsNoUnresolvedKeys(t *testing.T) {
	t.Parallel()

	prompt := chooserFixture()
	body := renderHTML(t, prompt)

	for _, key := range []string{prompt.Type, prompt.Inputs[0].Label} {
		if strings.Contains(body, key) {
			t.Errorf("the rendered page contains the raw key %q: %s", key, body)
		}
	}

	text := tagStripper.ReplaceAllString(body, " ")
	for _, token := range strings.Fields(text) {
		if dottedKey.MatchString(token) {
			t.Errorf("the rendered page shows %q, which is a message key rather than text: %s", token, body)
		}
	}
}
