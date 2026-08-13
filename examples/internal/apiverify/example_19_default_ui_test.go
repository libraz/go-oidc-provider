//go:build apiverify

package apiverify

import "testing"

// 19's deliverable is the surface an embedder gets for configuring
// nothing: login, consent and the prompt=select_account chooser all
// rendered by the driver op.New falls back to. Every other example that
// reaches a chooser replaces that driver first — 12 with a template
// override, 13 with the JSON driver — so before this row the default
// chooser render had no example-tier coverage at all, and a default
// surface that could not render a chooser stayed shipped across three
// audits without any example noticing.
//
// The walkthrough is the same one 12 and 13 drive, deliberately: the
// claim under test is that swapping the driver is optional, which only
// holds if the unconfigured surface reaches the same end state.
func TestExample19DefaultUI(t *testing.T) {
	runChooserAddAccountFlow(t, "../../19-default-ui", "http://127.0.0.1:8080",
		authorizeParams("demo-rp", "http://127.0.0.1:8081/callback", "openid profile email"),
		htmlSubmitter{},
		exampleUser{username: "alice", password: "alice-password", label: "Alice Example"},
		exampleUser{username: "bob", password: "bob-password", label: "Bob Example"},
	)
}
