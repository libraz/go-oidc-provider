package scoperegistry_test

import (
	"slices"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
)

// TestRegistry_IsRegistered exercises the three states the lookup must
// distinguish: a known name, an unknown name, and the nil-receiver
// fallback callers rely on for "no registry configured".
func TestRegistry_IsRegistered(t *testing.T) {
	t.Parallel()

	r := scoperegistry.New([]scoperegistry.Entry{
		{Name: "openid", Public: true},
		{Name: "internal:metrics", Public: false},
	})

	cases := []struct {
		name string
		want bool
	}{
		{"openid", true},
		{"internal:metrics", true},
		{"unknown", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := r.IsRegistered(tc.name); got != tc.want {
			t.Errorf("IsRegistered(%q)=%v want %v", tc.name, got, tc.want)
		}
	}

	var nilReg *scoperegistry.Registry
	if nilReg.IsRegistered("openid") {
		t.Error("nil receiver IsRegistered must return false")
	}
}

// TestRegistry_IsPublic confirms the discovery-eligibility semantics:
// only registered scopes whose Public flag is true return true; unknown
// names and a nil receiver collapse to false.
func TestRegistry_IsPublic(t *testing.T) {
	t.Parallel()

	r := scoperegistry.New([]scoperegistry.Entry{
		{Name: "openid", Public: true},
		{Name: "read:projects", Public: true},
		{Name: "internal:metrics", Public: false},
	})

	cases := []struct {
		name string
		want bool
	}{
		{"openid", true},
		{"read:projects", true},
		{"internal:metrics", false},
		{"unknown", false},
	}
	for _, tc := range cases {
		if got := r.IsPublic(tc.name); got != tc.want {
			t.Errorf("IsPublic(%q)=%v want %v", tc.name, got, tc.want)
		}
	}

	var nilReg *scoperegistry.Registry
	if nilReg.IsPublic("openid") {
		t.Error("nil receiver IsPublic must return false")
	}
}

// TestRegistry_Allows enumerates the AllowedClients allowlist semantics.
// The "unknown scope" branch must fail-closed — an admission gate
// defaults to deny; "empty AllowedClients" must mean every
// client; "non-empty AllowedClients" must enforce membership.
func TestRegistry_Allows(t *testing.T) {
	t.Parallel()

	r := scoperegistry.New([]scoperegistry.Entry{
		{Name: "openid", Public: true},
		{Name: "billing:write", Public: true, AllowedClients: []string{"svc-billing", "svc-admin"}},
	})

	cases := []struct {
		name     string
		scope    string
		clientID string
		want     bool
	}{
		{"empty_allowlist_any_client", "openid", "any-client", true},
		{"non_empty_allowlist_member", "billing:write", "svc-billing", true},
		{"non_empty_allowlist_other_member", "billing:write", "svc-admin", true},
		{"non_empty_allowlist_outsider", "billing:write", "rp-public", false},
		// Unknown scopes pass through Allows: the upstream pipeline
		// (client.Scopes intersection, refresh-token scope widening)
		// is the gate that rejects unregistered names, and the
		// registry is documented as an AllowedClients-only contract.
		// Callers needing strict registration enforcement consult
		// [Registry.IsRegistered] separately.
		{"unknown_scope_passes_through", "unknown:scope", "any", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := r.Allows(tc.scope, tc.clientID); got != tc.want {
				t.Errorf("Allows(%q, %q)=%v want %v", tc.scope, tc.clientID, got, tc.want)
			}
		})
	}

	var nilReg *scoperegistry.Registry
	if !nilReg.Allows("billing:write", "any") {
		t.Error("nil receiver Allows must return true to disable the check")
	}
}

// TestRegistry_New_PanicsOnPaddedScopeName pins that the constructor
// surfaces whitespace-padded scope names as panics rather than
// silently storing entries that can never match a wire request.
func TestRegistry_New_PanicsOnPaddedScopeName(t *testing.T) {
	t.Parallel()

	cases := []string{" openid", "openid ", " openid ", "\topenid"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if r := recover(); r == nil {
					t.Fatalf("New(%q) did not panic", name)
				}
			}()
			scoperegistry.New([]scoperegistry.Entry{{Name: name, Public: true}})
		})
	}
}

// TestRegistry_PublicNames pins the discovery-document advertising rule:
// only scopes with Public:true appear, the result is sorted in stable
// lexicographic order, and a fresh slice is returned on each call so a
// caller mutation cannot pollute the cached order.
func TestRegistry_PublicNames(t *testing.T) {
	t.Parallel()

	r := scoperegistry.New([]scoperegistry.Entry{
		{Name: "phone", Public: true},
		{Name: "openid", Public: true},
		{Name: "internal:metrics", Public: false},
		{Name: "read:projects", Public: true},
		{Name: "email", Public: true},
	})

	got := r.PublicNames()
	want := []string{"email", "openid", "phone", "read:projects"}
	if !slices.Equal(got, want) {
		t.Errorf("PublicNames=%v want %v", got, want)
	}

	// Mutating the returned slice MUST NOT alter what the next call
	// sees; the registry hands out a fresh clone.
	got[0] = "tampered"
	again := r.PublicNames()
	if !slices.Equal(again, want) {
		t.Errorf("after mutation PublicNames=%v want %v", again, want)
	}

	// Determinism: a second New with the same entries in a different
	// order yields the same advertised order.
	r2 := scoperegistry.New([]scoperegistry.Entry{
		{Name: "read:projects", Public: true},
		{Name: "email", Public: true},
		{Name: "openid", Public: true},
		{Name: "phone", Public: true},
	})
	if got2 := r2.PublicNames(); !slices.Equal(got2, []string{"email", "openid", "phone", "read:projects"}) {
		t.Errorf("PublicNames not deterministic across constructors: %v", got2)
	}

	var nilReg *scoperegistry.Registry
	if nilReg.PublicNames() != nil {
		t.Error("nil receiver PublicNames must return nil")
	}
}

// TestRegistry_DefensiveCopy_AllowedClients verifies that the
// constructor copies AllowedClients out of the caller's input. The
// guarantee matters because the op layer hands the registry slices that
// originate from public op.Scope values; a later mutation by the
// embedder must not silently change admission policy at runtime.
func TestRegistry_DefensiveCopy_AllowedClients(t *testing.T) {
	t.Parallel()

	allowed := []string{"svc-billing", "svc-admin"}
	r := scoperegistry.New([]scoperegistry.Entry{
		{Name: "billing:write", Public: true, AllowedClients: allowed},
	})

	if !r.Allows("billing:write", "svc-billing") {
		t.Fatal("svc-billing must be permitted before mutation")
	}

	// Mutate every element of the caller-owned slice; the registry
	// must continue to enforce the original allowlist.
	for i := range allowed {
		allowed[i] = "evil"
	}

	if !r.Allows("billing:write", "svc-billing") {
		t.Error("registry must keep the original allowlist after caller mutation")
	}
	if r.Allows("billing:write", "evil") {
		t.Error("registry must not honour values written into the caller slice after construction")
	}
}

// TestRegistry_New_NilOrEmpty confirms the "registry exists but
// describes no scopes" path. The constructor must yield a usable
// receiver whose IsRegistered is uniformly false and whose PublicNames
// is empty (not nil) so callers can range over it without nil checks.
func TestRegistry_New_NilOrEmpty(t *testing.T) {
	t.Parallel()

	for _, in := range [][]scoperegistry.Entry{nil, {}} {
		r := scoperegistry.New(in)
		if r == nil {
			t.Fatal("New must not return a nil registry")
		}
		if r.IsRegistered("openid") {
			t.Error("empty registry must report no scopes registered")
		}
		if names := r.PublicNames(); len(names) != 0 {
			t.Errorf("PublicNames=%v want empty", names)
		}
	}
}

// TestRegistry_New_SkipsBlankNames mirrors the implementation contract:
// entries whose Name is empty are dropped silently because the op layer
// already rejects them at construction time. Threading them through to
// the registry would be a programming bug, but the registry must remain
// well-defined either way.
func TestRegistry_New_SkipsBlankNames(t *testing.T) {
	t.Parallel()

	r := scoperegistry.New([]scoperegistry.Entry{
		{Name: "", Public: true},
		{Name: "openid", Public: true},
	})
	if r.IsRegistered("") {
		t.Error("blank name must not be registered")
	}
	if !r.IsRegistered("openid") {
		t.Error("openid must remain registered alongside the dropped blank entry")
	}
}
