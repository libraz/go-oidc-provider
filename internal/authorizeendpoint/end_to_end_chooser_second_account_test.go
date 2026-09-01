package authorizeendpoint_test

import (
	"io"
	"net/http"
	"net/url"
	"testing"
)

// TestEndToEnd_ChooserAddAccount_SecondChooserListsBothAccounts drives the
// walkthrough an embedder's add-account link promises, with every hop
// carrying only the cookies the OP itself last set: sign in as the first
// account, ask for prompt=select_account, follow the chooser's own
// AddAccountURL to sign in as the second, then ask again. The second
// chooser MUST offer both accounts.
func TestEndToEnd_ChooserAddAccount_SecondChooserListsBothAccounts(t *testing.T) {
	t.Parallel()
	f := newE2EFlow(t, "rp-chooser-second")

	// Hop 1: a plain authorization establishes the first account's session.
	f.completeLogin(t, f.authorize(t, f.values()), "user-A")

	// Hop 2: the chooser renders for the group that session created.
	values := f.values()
	values.Set("prompt", "select_account")
	first := f.chooserPrompt(t, values)
	if got := len(chooserAccountsFromPrompt(t, first)); got != 1 {
		t.Fatalf("first chooser lists %d account(s), want 1: %v", got, first)
	}
	addAccountURL := chooserAddAccountURLFromPrompt(t, first)
	if addAccountURL == "" {
		t.Fatalf("chooser rendered no AddAccountURL: %v", first)
	}

	// Hop 3: the add-account link signs the second account in. The browser
	// still carries the first account's session cookie, which is what makes
	// the OP-private group marker trustworthy.
	f.completeLogin(t, f.followAddAccount(t, addAccountURL), "user-B")

	// Hop 4: the same chooser request must now offer both accounts.
	second := f.chooserPrompt(t, values)
	accounts := chooserAccountsFromPrompt(t, second)
	subjects := make(map[string]bool, len(accounts))
	for _, a := range accounts {
		subject, _ := a["Subject"].(string)
		subjects[subject] = true
	}
	if len(accounts) != 2 || !subjects["user-A"] || !subjects["user-B"] {
		t.Fatalf("second chooser lists %v, want user-A and user-B in one prompt: %v", subjects, second)
	}
}

// chooserPrompt runs GET /authorize with values and returns the chooser
// prompt envelope the redirect leads to.
func (f *e2eFlow) chooserPrompt(t *testing.T, values url.Values) map[string]any {
	t.Helper()
	loc := f.authorize(t, values)
	resp, err := newGet(f.interactionURL(loc)).Do(f.client)
	if err != nil {
		t.Fatalf("GET chooser interaction: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("chooser interaction status=%d body=%s", resp.StatusCode, string(dump))
	}
	env := decodeMap(t, resp)
	if got, _ := env["type"].(string); got != "interaction.chooser" {
		t.Fatalf("prompt=select_account rendered %q, want interaction.chooser: %v", got, env)
	}
	return env
}

// followAddAccount issues the chooser's own AddAccountURL and returns the
// interaction the OP redirects to.
func (f *e2eFlow) followAddAccount(t *testing.T, addAccountURL string) *url.URL {
	t.Helper()
	resp, err := newGet(f.tk.Server.URL + addAccountURL).Do(f.client)
	if err != nil {
		t.Fatalf("GET AddAccountURL: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("AddAccountURL status=%d body=%s", resp.StatusCode, string(dump))
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("AddAccountURL Location: %v", err)
	}
	return loc
}
