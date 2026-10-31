package hygiene_test

import (
	"path/filepath"
	"strings"
	"testing"
)

// Client authentication accepts a client's previous secret only while
// VerifyOpts.Now is before its expiry, and a zero Now fails closed. An
// endpoint that builds its options without Now therefore rejects the
// previous secret silently, and one without Audit hides that a client
// still uses it. Both fields are plain values the compiler cannot
// require, so every library construction site is checked here.
var clientAuthLiteralWatch = []struct {
	// qualified is the spelling used outside the declaring package.
	qualified string
	// local is the unqualified spelling, matched only under declDir
	// because the bare name is reused by unrelated types elsewhere.
	local    string
	declDir  string
	minSites int
}{
	{
		qualified: "endpointsupport.AuthenticateOpts",
		local:     "AuthenticateOpts",
		declDir:   "internal/endpointsupport",
		minSites:  4,
	},
}

var clientAuthRequiredFields = []string{"Now", "Audit"}

// TestClientAuthLiteralsSetNowAndAudit asserts that every non-test
// composite literal of endpointsupport.AuthenticateOpts assigns both Now
// and Audit.
func TestClientAuthLiteralsSetNowAndAudit(t *testing.T) {
	t.Parallel()

	sites := collectLiteralSites(t, repoRoot(t))
	for _, w := range clientAuthLiteralWatch {
		t.Run(w.qualified, func(t *testing.T) {
			t.Parallel()

			found := append([]literalSite(nil), sites[w.qualified]...)
			prefix := filepath.ToSlash(w.declDir) + "/"
			for _, s := range sites[w.local] {
				if strings.HasPrefix(filepath.ToSlash(s.where), prefix) {
					found = append(found, s)
				}
			}
			if len(found) < w.minSites {
				t.Fatalf("found %d construction site(s) for %s, expected at least %d; "+
					"the scan stopped matching rather than the source having improved",
					len(found), w.qualified, w.minSites)
			}
			for _, s := range found {
				for _, f := range clientAuthRequiredFields {
					if !s.fields[f] {
						t.Errorf("%s builds %s without %s; the previous-secret window and its audit event "+
							"depend on every endpoint setting it", s.where, w.qualified, f)
					}
				}
			}
		})
	}
}
