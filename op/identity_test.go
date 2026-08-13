package op_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

func TestSubject_StringAndZero(t *testing.T) {
	t.Parallel()

	if !op.Subject("").IsZero() {
		t.Error("empty Subject must be zero")
	}
	if op.Subject("u-1").IsZero() {
		t.Error("non-empty Subject must not be zero")
	}
	if got := op.Subject("u-1").String(); got != "u-1" {
		t.Errorf("String()=%q want u-1", got)
	}
}

func TestParseScopeSet_AndStringRoundtrip(t *testing.T) {
	t.Parallel()

	in := "openid profile email"
	set := op.ParseScopeSet(in)
	if !set.Has(op.ScopeNameOpenID) {
		t.Error("ScopeNameOpenID missing")
	}
	if !set.Has(op.ScopeNameProfile) {
		t.Error("ScopeNameProfile missing")
	}
	if set.Has(op.ScopeNameOfflineAccess) {
		t.Error("offline_access must not be present")
	}
	// String must be deterministic regardless of input order.
	got := set.String()
	if got != "email openid profile" {
		t.Errorf("String()=%q want sorted scopes", got)
	}
	if op.ParseScopeSet("").String() != "" {
		t.Error("empty input must produce empty string")
	}
}

func TestClaims_Get(t *testing.T) {
	t.Parallel()

	c := op.Claims{"name": "Ada"}
	if v, ok := c.Get("name"); !ok || v != "Ada" {
		t.Errorf("Get(name)=%v,%v want Ada,true", v, ok)
	}
	if _, ok := c.Get("missing"); ok {
		t.Error("missing key must not report ok")
	}
	var nilClaims op.Claims
	if _, ok := nilClaims.Get("anything"); ok {
		t.Error("nil Claims must not report ok")
	}
}
