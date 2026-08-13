package tokenendpoint_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/op/store"
)

// issuedCredentials is the subset of the /token success body the
// grant-identity assertions read back.
type issuedCredentials struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

func decodeIssuedCredentials(t *testing.T, body []byte) issuedCredentials {
	t.Helper()
	var out issuedCredentials
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode success body: %v: %s", err, body)
	}
	return out
}

// assertNoAuditExtraCarries fails when any emitted audit extra holds the
// secret verbatim. The scan is over every event and every key rather than
// the one extra the issuance path is known to populate, because the point
// of the invariant is that the redemption secret has no route into the
// audit stream at all.
func assertNoAuditExtraCarries(t *testing.T, events []audit.Event, secret string) {
	t.Helper()
	for _, ev := range events {
		for k, v := range ev.Extras {
			s, ok := v.(string)
			if !ok {
				continue
			}
			if strings.Contains(s, secret) {
				t.Errorf("audit event %q extra %q = %q leaks the redemption secret", ev.Name, k, s)
			}
		}
	}
}

// TestHandleDeviceCode_GrantIdentityIsNotTheDeviceCode pins the
// separation between the device_code — a bearer secret the substore
// contract requires backends to keep hashed at rest — and the grant
// identifier the OP publishes. The grant identifier travels in the
// access token's "gid" claim (a signed, unencrypted JWT the resource
// server logs), on the refresh-token row (a plaintext column in a SQL
// backend), and in the audit stream, so a redemption that reused the
// device_code there would re-expose the very value hashing was meant to
// protect. The identifier must therefore be freshly allocated and must
// not be derivable from the device_code.
func TestHandleDeviceCode_GrantIdentityIsNotTheDeviceCode(t *testing.T) {
	t.Parallel()
	f := newDeviceCodeFixture(t)
	const deviceCode = "device-code-grant-identity"
	f.seedDeviceCode(t, &store.DeviceCode{
		ID:       deviceCode,
		UserCode: "GRNT-IDNT",
		Scope:    []string{"openid"},
	})
	if err := f.store.DeviceCodes().Approve(context.Background(), deviceCode, "user-grant-identity", f.clock.now); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	emitter := &recordingEmitter{}
	f.deps.Audit = emitter

	rec := f.post(t, url.Values{"grant_type": {devCodeGrantURN}, "device_code": {deviceCode}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	issued := decodeIssuedCredentials(t, rec.Body.Bytes())
	if issued.AccessToken == "" || issued.RefreshToken == "" {
		t.Fatalf("expected both an access token and a refresh token; got %+v", issued)
	}

	gid, _ := decodeJWTPayload(t, issued.AccessToken)["gid"].(string)
	if gid == "" {
		t.Fatal("gid claim missing: redemption must allocate a grant identifier")
	}
	if gid == deviceCode || strings.Contains(gid, deviceCode) {
		t.Errorf("gid = %q carries the raw device_code %q", gid, deviceCode)
	}

	row, err := f.store.RefreshTokens().Find(context.Background(), issued.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshTokens.Find: %v", err)
	}
	if row.GrantID == deviceCode || strings.Contains(row.GrantID, deviceCode) {
		t.Errorf("refresh row GrantID = %q carries the raw device_code %q", row.GrantID, deviceCode)
	}
	// One identity per redemption: the refresh chain and the access token
	// must name the same grant or the revocation cascade splits in two.
	if row.GrantID != gid {
		t.Errorf("refresh row GrantID = %q, want the access token's gid %q", row.GrantID, gid)
	}

	assertNoAuditExtraCarries(t, emitter.events, deviceCode)
}

// TestHandleCIBA_GrantIdentityIsNotTheAuthReqID is the CIBA counterpart
// of TestHandleDeviceCode_GrantIdentityIsNotTheDeviceCode: auth_req_id is
// the bearer secret of the poll, so it must not resurface as the grant
// identifier stamped on the issued credentials or on the audit stream.
func TestHandleCIBA_GrantIdentityIsNotTheAuthReqID(t *testing.T) {
	t.Parallel()
	f := newCIBAFixture(t)
	const authReqID = "auth-req-grant-identity"
	f.seedCIBARequest(t, &store.CIBARequest{
		ID:    authReqID,
		Scope: []string{"openid"},
	})
	if err := f.store.CIBARequests().Approve(context.Background(), authReqID, "user-grant-identity", "", f.clock.now); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	emitter := &recordingEmitter{}
	f.deps.Audit = emitter

	rec := f.post(t, url.Values{
		"grant_type":  {"urn:openid:params:grant-type:ciba"},
		"auth_req_id": {authReqID},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	issued := decodeIssuedCredentials(t, rec.Body.Bytes())
	if issued.AccessToken == "" || issued.RefreshToken == "" {
		t.Fatalf("expected both an access token and a refresh token; got %+v", issued)
	}

	gid, _ := decodeJWTPayload(t, issued.AccessToken)["gid"].(string)
	if gid == "" {
		t.Fatal("gid claim missing: redemption must allocate a grant identifier")
	}
	if gid == authReqID || strings.Contains(gid, authReqID) {
		t.Errorf("gid = %q carries the raw auth_req_id %q", gid, authReqID)
	}

	row, err := f.store.RefreshTokens().Find(context.Background(), issued.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshTokens.Find: %v", err)
	}
	if row.GrantID == authReqID || strings.Contains(row.GrantID, authReqID) {
		t.Errorf("refresh row GrantID = %q carries the raw auth_req_id %q", row.GrantID, authReqID)
	}
	if row.GrantID != gid {
		t.Errorf("refresh row GrantID = %q, want the access token's gid %q", row.GrantID, gid)
	}

	assertNoAuditExtraCarries(t, emitter.events, authReqID)
}

// TestHandleDeviceCode_RotatedRefreshKeepsAllocatedGrantIdentity extends
// the invariant across the refresh chain the device flow roots: the
// rotation inherits the parent's GrantID, so a device_code that leaked
// into the root row would keep resurfacing on every successor long after
// the ceremony ended.
func TestHandleDeviceCode_RotatedRefreshKeepsAllocatedGrantIdentity(t *testing.T) {
	t.Parallel()
	f := newDeviceCodeFixture(t)
	const deviceCode = "device-code-rotation-identity"
	f.seedDeviceCode(t, &store.DeviceCode{
		ID:       deviceCode,
		UserCode: "ROTA-IDNT",
		Scope:    []string{"openid"},
	})
	if err := f.store.DeviceCodes().Approve(context.Background(), deviceCode, "user-rotation-identity", f.clock.now); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	rec := f.post(t, url.Values{"grant_type": {devCodeGrantURN}, "device_code": {deviceCode}})
	if rec.Code != http.StatusOK {
		t.Fatalf("redeem status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	issued := decodeIssuedCredentials(t, rec.Body.Bytes())

	f.deps.Clock = fixedClock{now: f.clock.now.Add(time.Minute)}
	rotated := f.post(t, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {issued.RefreshToken},
	})
	if rotated.Code != http.StatusOK {
		t.Fatalf("rotate status = %d, want 200; body=%s", rotated.Code, rotated.Body.String())
	}
	next := decodeIssuedCredentials(t, rotated.Body.Bytes())
	gid, _ := decodeJWTPayload(t, next.AccessToken)["gid"].(string)
	if gid == deviceCode || strings.Contains(gid, deviceCode) {
		t.Errorf("rotated gid = %q carries the raw device_code %q", gid, deviceCode)
	}
	row, err := f.store.RefreshTokens().Find(context.Background(), next.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshTokens.Find after rotation: %v", err)
	}
	if row.GrantID == deviceCode || strings.Contains(row.GrantID, deviceCode) {
		t.Errorf("rotated refresh row GrantID = %q carries the raw device_code %q", row.GrantID, deviceCode)
	}
}
