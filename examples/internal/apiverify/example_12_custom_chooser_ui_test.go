//go:build apiverify

package apiverify

import "testing"

// 12's deliverable is the WithChooserUI template: a page listing every
// account in the browser's chooser group, each pickable, with a link
// that adds another. None of that exists until a session does, and the
// second account joins only by following the chooser's own link — so
// the walkthrough in the header doc is the test.
//
// The earlier smoke stopped at the login prompt, which is the
// precondition rather than the deliverable, and passed throughout the
// period when the default surface could not render a chooser at all.
func TestExample12CustomChooserUI(t *testing.T) {
	runChooserAddAccountFlow(t, "../../12-custom-chooser-ui", "http://127.0.0.1:8080",
		authorizeParams("demo-rp", "http://localhost:8081/callback", "openid profile email"),
		htmlSubmitter{},
		exampleUser{username: "alice", password: "alice-password", label: "Alice Example"},
		exampleUser{username: "bob", password: "bob-password", label: "Bob Example"},
	)
}
