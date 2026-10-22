package authorizeendpoint_test

import (
	"context"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// TestEndToEnd_OverlappingCodesKeepTheirOwnClaimsRequest issues two codes
// for one subject and client before either is redeemed: the interactive
// pass asks for email, the silent pass for phone_number. Both hang off the
// same grant, so each code must carry its own claims request rather than
// the one the latest authorization left on the grant.
func TestEndToEnd_OverlappingCodesKeepTheirOwnClaimsRequest(t *testing.T) {
	t.Parallel()

	const subject = "user-overlapping-codes"
	f := newE2EFlow(t, "rp-overlapping-codes")
	f.tk.Store.PutUser(context.Background(), &store.User{
		Subject: subject,
		Claims:  map[string]any{"email": "overlap@example.com", "phone_number": "+1-555-0100"},
	})

	first := f.values()
	first.Set("claims", `{"id_token":{"email":{"essential":true}}}`)
	code1 := f.completeLogin(t, f.authorize(t, first), subject)

	second := f.values()
	second.Set("prompt", "none")
	second.Set("claims", `{"id_token":{"phone_number":{"essential":true}}}`)
	code2 := f.authorize(t, second).Query().Get("code")
	if code2 == "" {
		t.Fatal("prompt=none was not served from the existing grant")
	}

	for name, code := range map[string]string{"interactive": code1, "silent": code2} {
		rec, err := f.tk.Store.AuthorizationCodes().Find(context.Background(), code)
		if err != nil {
			t.Fatalf("%s code: Find: %v", name, err)
		}
		if !rec.AuthorizationRecorded || rec.AuthTime.IsZero() || rec.Claims == nil {
			t.Errorf("%s code recorded=%v auth_time=%v claims=%v; want its own authorization state",
				name, rec.AuthorizationRecorded, rec.AuthTime, rec.Claims)
		}
	}

	idToken1 := f.exchange(t, code1)
	if got := idToken1["email"]; got != "overlap@example.com" {
		t.Errorf("code 1 id_token email=%v want overlap@example.com", got)
	}
	if got, ok := idToken1["phone_number"]; ok {
		t.Errorf("code 1 id_token phone_number=%v; the later authorization's request leaked into it", got)
	}
	idToken2 := f.exchange(t, code2)
	if got := idToken2["phone_number"]; got != "+1-555-0100" {
		t.Errorf("code 2 id_token phone_number=%v want +1-555-0100", got)
	}
	if got, ok := idToken2["email"]; ok {
		t.Errorf("code 2 id_token email=%v; the earlier authorization's request leaked into it", got)
	}
}
