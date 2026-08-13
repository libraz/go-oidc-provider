//go:build apiverify

package apiverify

import "testing"

// 13's deliverable is the built-in chooser rendered as a JSON envelope:
// Prompt{Type: "interaction.chooser"} carrying one Accounts entry per
// live session plus AddAccountURL. The walkthrough is the same as 12's
// — the two examples differ only in which driver renders it — so the
// same driver runs it with the JSON submitter.
//
// Asserting the login prompt came back as JSON, which is what this test
// used to do, pins the configured driver but never the chooser: the
// envelope under test is emitted by a different interaction, three hops
// later, and only once two accounts share a group.
func TestExample13MultiAccount(t *testing.T) {
	runChooserAddAccountFlow(t, "../../13-multi-account", "http://127.0.0.1:8080",
		authorizeParams("demo-rp", "http://localhost:8081/callback", "openid profile email"),
		jsonSubmitter{},
		exampleUser{username: "alice", password: "alice-password", label: "Alice Example"},
		exampleUser{username: "bob", password: "bob-password", label: "Bob Example"},
	)
}
