package op

import (
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/cimd"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestCIMD_Validate_RejectsFAPIProfiles pins that every FAPI profile,
// FAPI-CIBA included, refuses client ID metadata documents.
func TestCIMD_Validate_RejectsFAPIProfiles(t *testing.T) {
	t.Parallel()

	for _, p := range []profile.Profile{profile.FAPI2Baseline, profile.FAPI2MessageSigning, profile.FAPICIBA} {
		c := &config{cimd: &ClientIDMetadataDocuments{}, profiles: []profile.Profile{p}}
		err := c.validateClientIDMetadataDocuments()
		if err == nil {
			t.Errorf("%s: CIMD accepted under a FAPI profile", p)
			continue
		}
		if !strings.Contains(err.Error(), "FAPI") || !strings.Contains(err.Error(), profileOptionName(p)) {
			t.Errorf("%s: error %q must name the FAPI profile", p, err)
		}
	}
}

// TestCIMD_Validate_AcceptsBaselineAndNoProfile pins that the profiles
// keeping "none" admit the option, and that the check is inert when the
// option is off.
func TestCIMD_Validate_AcceptsBaselineAndNoProfile(t *testing.T) {
	t.Parallel()

	for _, c := range []*config{
		{cimd: &ClientIDMetadataDocuments{}},
		{cimd: &ClientIDMetadataDocuments{}, profiles: []profile.Profile{profile.OAuth21}},
		{profiles: []profile.Profile{profile.FAPI2Baseline}},
	} {
		if err := c.validateClientIDMetadataDocuments(); err != nil {
			t.Errorf("profiles=%v cimd=%v: unexpected error %v", c.profiles, c.cimd != nil, err)
		}
	}
}

// TestCIMD_ProfileWithoutNoneAuth pins the generic guard behind the
// "none" requirement: a profile whose allow-list omits none is named, a
// nil list (no restriction) is not.
func TestCIMD_ProfileWithoutNoneAuth(t *testing.T) {
	t.Parallel()

	allowed := func(p profile.Profile) []string {
		switch p {
		case profile.FAPI2Baseline:
			return []string{"private_key_jwt"}
		case profile.FAPI2MessageSigning:
			return []string{"none", "private_key_jwt"}
		case profile.OAuth21, profile.OIDCCore, profile.FAPICIBA:
			return nil
		}
		return nil
	}
	if p, ok := profileWithoutNoneAuth([]profile.Profile{profile.OAuth21, profile.FAPI2MessageSigning}, allowed); ok {
		t.Errorf("profiles keeping none reported %s", p)
	}
	p, ok := profileWithoutNoneAuth([]profile.Profile{profile.OAuth21, profile.FAPI2Baseline}, allowed)
	if !ok || p != profile.FAPI2Baseline {
		t.Errorf("got (%s, %v), want (%s, true)", p, ok, profile.FAPI2Baseline)
	}
}

// TestCIMD_FirstPartyRejectsURLClientID pins that a client ID metadata
// document URL can never be granted first-party auto-consent: the
// first-party set is drawn from static clients only.
func TestCIMD_FirstPartyRejectsURLClientID(t *testing.T) {
	t.Parallel()

	const id = "https://mcp.example.com/client.json"
	c := &config{cimd: &ClientIDMetadataDocuments{}, firstPartyClients: []string{id}}
	err := c.validateFirstPartyClients()
	if err == nil || !strings.Contains(err.Error(), id) {
		t.Fatalf("validateFirstPartyClients = %v, want unknown client_id %s", err, id)
	}
}

// TestCIMD_ClientStoreAccessor pins that the accessor answers with the
// configured store until the decorator is built, and with the one
// decorator afterwards.
func TestCIMD_ClientStoreAccessor(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	off := &config{store: st}
	buildClientStore(off, scoperegistry.New(nil))
	if off.clients != nil {
		t.Fatal("decorator built without WithClientIDMetadataDocuments")
	}
	if off.clientStore() != st.Clients() {
		t.Fatal("accessor must fall back to the configured store")
	}

	on := &config{store: st, cimd: &ClientIDMetadataDocuments{}}
	buildClientStore(on, scoperegistry.New(nil))
	got, ok := on.clientStore().(*cimd.Store)
	if !ok {
		t.Fatalf("accessor = %T, want *cimd.Store", on.clientStore())
	}
	if on.clientStore() != got {
		t.Fatal("accessor must return the single decorator")
	}
}
