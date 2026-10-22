package tokenendpoint

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestNewGrantID_OnlyConsentLineageWritesAGrant pins the three lineages:
// only a redemption the user approved writes a Grant, an inherited one
// issues under the existing grant, and an unbacked one writes nothing.
func TestNewGrantID_OnlyConsentLineageWritesAGrant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := inmem.New()
	deps := Deps{Grants: st.Grants()}

	consent, err := newGrantID(ctx, deps, grantIssuance{Lineage: grantLineageConsent, Grant: store.Grant{
		Subject: "user-1", ClientID: "device-client", Scope: []string{"openid"},
	}})
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	if g, err := st.Grants().FindBySubjectClient(ctx, "user-1", "device-client"); err != nil || g.ID != consent {
		t.Fatalf("consent grant = (%+v, %v), want the recorded %q", g, err, consent)
	}

	inherited, err := newGrantID(ctx, deps, grantIssuance{Lineage: grantLineageInherit, InheritedID: consent})
	if err != nil || inherited != consent {
		t.Fatalf("inherit = (%q, %v), want %q", inherited, err, consent)
	}
	unbacked, err := newGrantID(ctx, deps, grantIssuance{Lineage: grantLineageUnbacked})
	if err != nil || unbacked == "" || unbacked == consent {
		t.Fatalf("unbacked = (%q, %v), want a fresh identifier", unbacked, err)
	}
	if _, err := st.Grants().Find(ctx, unbacked); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unbacked identity has a Grant record: err=%v", err)
	}
	if list, err := st.Grants().ListBySubject(ctx, "user-1"); err != nil || len(list) != 1 {
		t.Errorf("ListBySubject = (%d records, %v), want only the consent grant", len(list), err)
	}

	if _, err := newGrantID(ctx, deps, grantIssuance{Lineage: grantLineageInherit}); err == nil {
		t.Error("inherit with no grant: want an error")
	}
	if _, err := newGrantID(ctx, deps, grantIssuance{}); err == nil {
		t.Error("unset lineage: want an error")
	}
}
