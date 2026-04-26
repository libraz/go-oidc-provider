package userinfo_test

import (
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/userinfo"
)

// TestBuild_AlwaysReleasesSub checks the sub claim is present even when
// no scopes are granted (the openid scope is implicit at /userinfo: a
// caller that reaches this layer has already had bearer auth verified).
func TestBuild_AlwaysReleasesSub(t *testing.T) {
	t.Parallel()

	out, err := userinfo.Build(userinfo.Input{
		Subject: "user-1",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := out["sub"]; got != "user-1" {
		t.Errorf("sub=%v want user-1", got)
	}
	if len(out) != 1 {
		t.Errorf("len=%d want 1, got %v", len(out), out)
	}
}

// TestBuild_RejectsEmptySubject locks the contract that callers must
// supply a non-empty Subject — every UserInfo response includes "sub".
func TestBuild_RejectsEmptySubject(t *testing.T) {
	t.Parallel()

	_, err := userinfo.Build(userinfo.Input{Subject: ""})
	if !errors.Is(err, userinfo.ErrSubjectRequired) {
		t.Errorf("err=%v want ErrSubjectRequired", err)
	}
}

// TestBuild_ProfileScopeReleasesProfileClaims walks the standard
// scope→claims mapping for "profile". The test deliberately omits
// "name" from Source so we observe that absent values are skipped.
func TestBuild_ProfileScopeReleasesProfileClaims(t *testing.T) {
	t.Parallel()

	out, err := userinfo.Build(userinfo.Input{
		Subject: "user-1",
		Scopes:  []string{"profile"},
		Source: map[string]any{
			"given_name":         "Alice",
			"family_name":        "Carroll",
			"preferred_username": "alice",
			"updated_at":         int64(1700000000),
			// "name" intentionally absent.
			"email": "alice@example.com", // not in profile group; must be filtered.
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if out["given_name"] != "Alice" {
		t.Errorf("given_name=%v", out["given_name"])
	}
	if out["preferred_username"] != "alice" {
		t.Errorf("preferred_username=%v", out["preferred_username"])
	}
	if _, ok := out["name"]; ok {
		t.Errorf("name should be absent when not in Source")
	}
	if _, ok := out["email"]; ok {
		t.Errorf("email released by profile scope: %v", out["email"])
	}
}

// TestBuild_EmailScopeReleasesEmailClaims confirms email scope releases
// email + email_verified, and only those.
func TestBuild_EmailScopeReleasesEmailClaims(t *testing.T) {
	t.Parallel()

	out, err := userinfo.Build(userinfo.Input{
		Subject: "user-1",
		Scopes:  []string{"email"},
		Source: map[string]any{
			"email":          "alice@example.com",
			"email_verified": true,
			"phone_number":   "+1 555-0100",
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if out["email"] != "alice@example.com" {
		t.Errorf("email=%v", out["email"])
	}
	if v, ok := out["email_verified"].(bool); !ok || !v {
		t.Errorf("email_verified=%v", out["email_verified"])
	}
	if _, ok := out["phone_number"]; ok {
		t.Error("phone_number leaked through email scope")
	}
}

// TestBuild_PhoneAndAddressScopes covers the remaining standard scopes.
func TestBuild_PhoneAndAddressScopes(t *testing.T) {
	t.Parallel()

	out, err := userinfo.Build(userinfo.Input{
		Subject: "user-1",
		Scopes:  []string{"phone", "address"},
		Source: map[string]any{
			"phone_number":          "+1 555-0100",
			"phone_number_verified": true,
			"address": map[string]any{
				"locality": "Wonderland",
				"country":  "US",
			},
			"email": "drop-me@example.com",
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if out["phone_number"] != "+1 555-0100" {
		t.Errorf("phone_number=%v", out["phone_number"])
	}
	addr, ok := out["address"].(map[string]any)
	if !ok || addr["locality"] != "Wonderland" {
		t.Errorf("address=%v", out["address"])
	}
	if _, ok := out["email"]; ok {
		t.Error("email leaked through phone+address scopes")
	}
}

// TestBuild_OpenIDScopeAddsNoExtras locks the rule that "openid" alone
// only releases sub.
func TestBuild_OpenIDScopeAddsNoExtras(t *testing.T) {
	t.Parallel()

	out, err := userinfo.Build(userinfo.Input{
		Subject: "user-1",
		Scopes:  []string{"openid"},
		Source: map[string]any{
			"name":  "Alice Carroll",
			"email": "alice@example.com",
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(out) != 1 || out["sub"] != "user-1" {
		t.Errorf("openid scope leaked extras: %v", out)
	}
}

// TestBuild_CustomScopeReleasesNamedClaims verifies the
// CustomScopeClaims hook releases caller-mapped claim names.
func TestBuild_CustomScopeReleasesNamedClaims(t *testing.T) {
	t.Parallel()

	out, err := userinfo.Build(userinfo.Input{
		Subject:           "user-1",
		Scopes:            []string{"projects:read"},
		CustomScopeClaims: map[string][]string{"projects:read": {"project_ids"}},
		Source: map[string]any{
			"project_ids": []string{"p-1", "p-2"},
			"email":       "drop-me@example.com",
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ids, ok := out["project_ids"].([]string)
	if !ok || len(ids) != 2 || ids[0] != "p-1" {
		t.Errorf("project_ids=%v", out["project_ids"])
	}
	if _, ok := out["email"]; ok {
		t.Error("email leaked through custom scope")
	}
}

// TestBuild_UnknownScopeIgnored verifies unknown scopes are silently
// dropped (per OIDC Core 1.0 §5.4 the OP "MAY" release additional claims
// for them, and we choose not to).
func TestBuild_UnknownScopeIgnored(t *testing.T) {
	t.Parallel()

	out, err := userinfo.Build(userinfo.Input{
		Subject: "user-1",
		Scopes:  []string{"not-a-known-scope"},
		Source: map[string]any{
			"name": "Alice Carroll",
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(out) != 1 || out["sub"] != "user-1" {
		t.Errorf("unknown scope leaked claims: %v", out)
	}
}

// TestBuild_DoesNotMutateInput pins the contract that Build leaves its
// inputs untouched even when it filters / clones internally.
func TestBuild_DoesNotMutateInput(t *testing.T) {
	t.Parallel()

	src := map[string]any{
		"name":  "Alice",
		"email": "alice@example.com",
	}
	scopes := []string{"profile"}
	_, err := userinfo.Build(userinfo.Input{
		Subject: "user-1",
		Scopes:  scopes,
		Source:  src,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(src) != 2 || src["email"] != "alice@example.com" {
		t.Errorf("Source mutated: %v", src)
	}
	if len(scopes) != 1 || scopes[0] != "profile" {
		t.Errorf("Scopes mutated: %v", scopes)
	}
}
