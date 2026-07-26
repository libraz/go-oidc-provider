package op_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
)

// discoveredGrants returns grant_types_supported from the discovery
// document of a Provider built with the supplied options. Discovery is
// the observable the assertions below want: it is what a relying party
// reads to decide which flows the OP will honour, so a grant that
// silently fell out of the resolved set shows up here.
func discoveredGrants(t *testing.T, opts ...op.Option) []string {
	t.Helper()

	provider, err := op.New(append(validBaseOptsWithInmem(t), opts...)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("get discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status=%d want 200", resp.StatusCode)
	}
	var body struct {
		GrantTypesSupported []string `json:"grant_types_supported"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	return body.GrantTypesSupported
}

// TestGrantResolution_DedicatedOptionKeepsDefaults pins the composition
// rule for the grant options that own their own wiring: enabling one of
// them adds a grant, it does not select the grant set. A deployment that
// bolts CIBA or the device grant onto an existing OP keeps serving the
// authorization-code flow it was already serving.
func TestGrantResolution_DedicatedOptionKeepsDefaults(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		opt  op.Option
		want grant.Type
	}{
		{"ciba", op.WithCIBA(op.WithCIBAHintResolver(stubCIBAHintResolver{})), grant.CIBA},
		{"device-code", op.WithDeviceCodeGrant(), grant.DeviceCode},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := discoveredGrants(t, tc.opt)
			for _, want := range []grant.Type{grant.AuthorizationCode, grant.RefreshToken, tc.want} {
				if !slices.Contains(got, want.String()) {
					t.Errorf("grant_types_supported = %v, want it to contain %s", got, want)
				}
			}
		})
	}
}

// TestGrantResolution_OrderIndependent checks that pairing a dedicated
// grant option with [op.WithGrants] produces the same provider whichever
// order the options are written in. WithGrants overwrites the selected
// list, so a resolution that ran during option application would drop
// whichever half was applied first.
func TestGrantResolution_OrderIndependent(t *testing.T) {
	t.Parallel()

	ciba := func() op.Option { return op.WithCIBA(op.WithCIBAHintResolver(stubCIBAHintResolver{})) }
	grants := func() op.Option {
		return op.WithGrants(grant.AuthorizationCode, grant.RefreshToken, grant.ClientCredentials)
	}

	cibaFirst := discoveredGrants(t, ciba(), grants())
	grantsFirst := discoveredGrants(t, grants(), ciba())
	if !slices.Equal(cibaFirst, grantsFirst) {
		t.Fatalf("option order changed the grant set: ciba-first=%v grants-first=%v", cibaFirst, grantsFirst)
	}
	for _, want := range []grant.Type{
		grant.AuthorizationCode, grant.RefreshToken, grant.ClientCredentials, grant.CIBA,
	} {
		if !slices.Contains(cibaFirst, want.String()) {
			t.Errorf("grant_types_supported = %v, want it to contain %s", cibaFirst, want)
		}
	}
}

// TestGrantResolution_WithGrantsAloneSelectsExactly confirms the
// composition rule did not turn [op.WithGrants] into an additive
// option: on its own it still replaces the default pair, so a
// deployment can narrow the token endpoint to exactly what it lists.
func TestGrantResolution_WithGrantsAloneSelectsExactly(t *testing.T) {
	t.Parallel()

	got := discoveredGrants(t, op.WithGrants(grant.AuthorizationCode, grant.ClientCredentials))
	if slices.Contains(got, grant.RefreshToken.String()) {
		t.Errorf("grant_types_supported = %v, want the default refresh_token dropped", got)
	}
	for _, want := range []grant.Type{grant.AuthorizationCode, grant.ClientCredentials} {
		if !slices.Contains(got, want.String()) {
			t.Errorf("grant_types_supported = %v, want it to contain %s", got, want)
		}
	}
}

// TestGrantResolution_NoDuplicateWhenNamedTwice checks the idempotence
// half of the contract: naming a grant in [op.WithGrants] and enabling
// its dedicated option both is a supported spelling, and discovery must
// not advertise the grant twice.
func TestGrantResolution_NoDuplicateWhenNamedTwice(t *testing.T) {
	t.Parallel()

	got := discoveredGrants(t,
		op.WithGrants(grant.AuthorizationCode, grant.RefreshToken, grant.CIBA),
		op.WithCIBA(op.WithCIBAHintResolver(stubCIBAHintResolver{})),
	)
	seen := 0
	for _, g := range got {
		if g == grant.CIBA.String() {
			seen++
		}
	}
	if seen != 1 {
		t.Errorf("grant_types_supported = %v, want exactly one CIBA entry, got %d", got, seen)
	}
}
