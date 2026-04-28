package op_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestPublicScope_SetsPublicTrueAndTitle pins the contract: the
// helper produces a [op.Scope] whose Name and Title carry the
// supplied values and whose Public flag is true. AllowedClients
// stays empty so the scope is open to every registered client by
// default.
func TestPublicScope_SetsPublicTrueAndTitle(t *testing.T) {
	t.Parallel()

	got := op.PublicScope("read:projects", "Read your projects")
	if got.Name != "read:projects" {
		t.Errorf("Name = %q, want %q", got.Name, "read:projects")
	}
	if got.Title != "Read your projects" {
		t.Errorf("Title = %q, want %q", got.Title, "Read your projects")
	}
	if !got.Public {
		t.Errorf("Public = false, want true")
	}
	if len(got.AllowedClients) != 0 {
		t.Errorf("AllowedClients = %v, want empty", got.AllowedClients)
	}
}

// TestInternalScope_SetsPublicFalse pins the contract: the helper
// produces a [op.Scope] whose Name carries the supplied value and
// whose Public flag is false. Title stays empty so the embedder can
// supply it via I18n if a consent prompt ever needs to render it.
func TestInternalScope_SetsPublicFalse(t *testing.T) {
	t.Parallel()

	got := op.InternalScope("internal:metrics")
	if got.Name != "internal:metrics" {
		t.Errorf("Name = %q, want %q", got.Name, "internal:metrics")
	}
	if got.Public {
		t.Errorf("Public = true, want false")
	}
	if got.Title != "" {
		t.Errorf("Title = %q, want empty", got.Title)
	}
}

// TestPublicScope_FieldShape locks every other field at its
// zero-value default so a future change that adds a side effect to
// the helper has to update this test deliberately.
func TestPublicScope_FieldShape(t *testing.T) {
	t.Parallel()

	got := op.PublicScope("read:projects", "Read your projects")
	if got.Description != "" {
		t.Errorf("Description = %q, want empty", got.Description)
	}
	if got.Icon != "" {
		t.Errorf("Icon = %q, want empty", got.Icon)
	}
	if got.Category != "" {
		t.Errorf("Category = %q, want empty", got.Category)
	}
	if len(got.Claims) != 0 {
		t.Errorf("Claims = %v, want empty", got.Claims)
	}
	if got.Required {
		t.Errorf("Required = true, want false")
	}
	if len(got.I18n) != 0 {
		t.Errorf("I18n = %v, want empty", got.I18n)
	}
}

// TestInternalScope_FieldShape locks every other field at its
// zero-value default for the same reason as
// [TestPublicScope_FieldShape].
func TestInternalScope_FieldShape(t *testing.T) {
	t.Parallel()

	got := op.InternalScope("internal:metrics")
	if got.Title != "" || got.Description != "" {
		t.Errorf("Title/Description must be empty: %+v", got)
	}
	if got.Icon != "" || got.Category != "" {
		t.Errorf("Icon/Category must be empty: %+v", got)
	}
	if len(got.Claims) != 0 || len(got.I18n) != 0 || len(got.AllowedClients) != 0 {
		t.Errorf("slices/maps must be empty: %+v", got)
	}
	if got.Required {
		t.Errorf("Required = true, want false")
	}
}
