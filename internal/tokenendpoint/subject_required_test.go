package tokenendpoint_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/tokenendpoint"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// wireError is the RFC 6749 §5.2 error envelope, decoded down to the two
// fields a client can branch on. The subject-required assertions compare
// both so a configuration difference cannot show through as a different
// description under the same code.
type wireError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func decodeWireError(t *testing.T, body []byte) wireError {
	t.Helper()
	var out wireError
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode error envelope: %v: %s", err, body)
	}
	return out
}

// registerSecondaryClient seeds an extra confidential client so a test can
// contrast two registrations that differ only in refresh eligibility.
func registerSecondaryClient(t *testing.T, s *inmem.Store, id string, grantTypes []string) (string, string) {
	t.Helper()
	const secret = "secondary-client-secret" // test fixture secret, not a real credential.
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	client := &store.Client{
		ID:                      id,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              grantTypes,
		Scopes:                  []string{"openid", "profile"},
	}
	if err := s.RegisterClient(context.Background(), client); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	return id, secret
}

// postTokenAs drives /token under an explicit client credential rather
// than the fixture's default one.
func postTokenAs(t *testing.T, deps tokenendpoint.Deps, clientID, secret string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	rec := httptest.NewRecorder()
	tokenendpoint.Handler(deps).ServeHTTP(rec, req)
	return rec
}

// assertNoCredentialsIssued fails when a rejected redemption still put a
// credential on the wire.
func assertNoCredentialsIssued(t *testing.T, body []byte) {
	t.Helper()
	issued := issuedCredentials{}
	if err := json.Unmarshal(body, &issued); err != nil {
		t.Fatalf("decode body: %v: %s", err, body)
	}
	if issued.AccessToken != "" {
		t.Errorf("access_token issued on a rejected redemption: %q", issued.AccessToken)
	}
	if issued.IDToken != "" {
		t.Errorf("id_token issued on a rejected redemption: %q", issued.IDToken)
	}
	if issued.RefreshToken != "" {
		t.Errorf("refresh_token issued on a rejected redemption: %q", issued.RefreshToken)
	}
}

// TestHandleCIBA_ApprovedWithoutSubject_FailsClosed pins OIDC Core 1.0
// §2: "sub" is REQUIRED, so a record approved without one certifies
// nobody and cannot be redeemed. Issuing anyway would hand the client a
// correctly signed id_token asserting the empty subject, which a relying
// party that verifies only signature / iss / aud accepts and maps onto
// the empty-string account key — conflating every such user.
//
// The rejection is asserted for a refresh-eligible and a refresh-
// ineligible client because the wire outcome must not depend on whether
// a later stage of issuance happens to trip over the missing subject:
// the same wire error has to come back either way.
func TestHandleCIBA_ApprovedWithoutSubject_FailsClosed(t *testing.T) {
	t.Parallel()
	f := newCIBAFixture(t)
	const authReqID = "auth-req-no-subject"
	noRefreshID, noRefreshSecret := registerSecondaryClient(t, f.store,
		"client-ciba-no-refresh", []string{"urn:openid:params:grant-type:ciba"})

	seed := func(t *testing.T, id, clientID string) {
		t.Helper()
		f.seedCIBARequest(t, &store.CIBARequest{ID: id, ClientID: clientID, Scope: []string{"openid"}})
		if err := f.store.CIBARequests().Approve(context.Background(), id, "", "", f.clock.now); err != nil {
			t.Fatalf("Approve: %v", err)
		}
	}
	seed(t, authReqID, f.client.ID)
	seed(t, authReqID+"-no-refresh", noRefreshID)

	form := url.Values{"grant_type": {"urn:openid:params:grant-type:ciba"}, "auth_req_id": {authReqID}}
	refreshEligible := f.post(t, form)
	if refreshEligible.Code != http.StatusBadRequest {
		t.Fatalf("refresh-eligible status = %d, want 400; body=%s", refreshEligible.Code, refreshEligible.Body.String())
	}
	got := decodeWireError(t, refreshEligible.Body.Bytes())
	if got.Error != "invalid_grant" {
		t.Errorf("refresh-eligible error = %q, want invalid_grant", got.Error)
	}
	assertNoCredentialsIssued(t, refreshEligible.Body.Bytes())

	noRefreshForm := url.Values{
		"grant_type":  {"urn:openid:params:grant-type:ciba"},
		"auth_req_id": {authReqID + "-no-refresh"},
	}
	ineligible := postTokenAs(t, f.deps, noRefreshID, noRefreshSecret, noRefreshForm)
	if ineligible.Code != refreshEligible.Code {
		t.Fatalf("refresh-ineligible status = %d, want %d; body=%s",
			ineligible.Code, refreshEligible.Code, ineligible.Body.String())
	}
	if want := decodeWireError(t, ineligible.Body.Bytes()); want != got {
		t.Errorf("refresh-ineligible error = %+v, want the refresh-eligible %+v", want, got)
	}
	assertNoCredentialsIssued(t, ineligible.Body.Bytes())

	// The record stays redeemable-in-principle: the OP refused before the
	// consume CAS, so an embedder that fixes the approval can retry.
	stored, err := f.store.CIBARequests().FindByAuthReqID(context.Background(), authReqID)
	if err != nil {
		t.Fatalf("FindByAuthReqID: %v", err)
	}
	if stored.Status == store.CIBARequestStatusConsumed {
		t.Error("record consumed by a redemption that issued nothing")
	}
}

// TestHandleDeviceCode_ApprovedWithoutSubject_FailsClosed is the device
// counterpart of TestHandleCIBA_ApprovedWithoutSubject_FailsClosed; see
// that test for why an empty subject cannot produce a credential.
func TestHandleDeviceCode_ApprovedWithoutSubject_FailsClosed(t *testing.T) {
	t.Parallel()
	f := newDeviceCodeFixture(t)
	const deviceCode = "device-code-no-subject"
	noRefreshID, noRefreshSecret := registerSecondaryClient(t, f.store,
		"client-devicecode-no-refresh", []string{devCodeGrantURN})

	seed := func(t *testing.T, id, userCode, clientID string) {
		t.Helper()
		f.seedDeviceCode(t, &store.DeviceCode{ID: id, UserCode: userCode, ClientID: clientID, Scope: []string{"openid"}})
		if err := f.store.DeviceCodes().Approve(context.Background(), id, "", f.clock.now); err != nil {
			t.Fatalf("Approve: %v", err)
		}
	}
	seed(t, deviceCode, "NOSU-BJCT", f.client.ID)
	seed(t, deviceCode+"-no-refresh", "NOSU-BJC2", noRefreshID)

	refreshEligible := f.post(t, url.Values{"grant_type": {devCodeGrantURN}, "device_code": {deviceCode}})
	if refreshEligible.Code != http.StatusBadRequest {
		t.Fatalf("refresh-eligible status = %d, want 400; body=%s", refreshEligible.Code, refreshEligible.Body.String())
	}
	got := decodeWireError(t, refreshEligible.Body.Bytes())
	if got.Error != "invalid_grant" {
		t.Errorf("refresh-eligible error = %q, want invalid_grant", got.Error)
	}
	assertNoCredentialsIssued(t, refreshEligible.Body.Bytes())

	ineligible := postTokenAs(t, f.deps, noRefreshID, noRefreshSecret, url.Values{
		"grant_type":  {devCodeGrantURN},
		"device_code": {deviceCode + "-no-refresh"},
	})
	if ineligible.Code != refreshEligible.Code {
		t.Fatalf("refresh-ineligible status = %d, want %d; body=%s",
			ineligible.Code, refreshEligible.Code, ineligible.Body.String())
	}
	if want := decodeWireError(t, ineligible.Body.Bytes()); want != got {
		t.Errorf("refresh-ineligible error = %+v, want the refresh-eligible %+v", want, got)
	}
	assertNoCredentialsIssued(t, ineligible.Body.Bytes())

	stored, err := f.store.DeviceCodes().FindByDeviceCode(context.Background(), deviceCode)
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if stored.Status == store.DeviceCodeStatusConsumed {
		t.Error("record consumed by a redemption that issued nothing")
	}
}

// TestHandleCIBA_SubjectProjectorNeverSeesEmptySubject pins the second
// half of the invariant: an embedder-supplied projector must not be
// handed an empty raw subject, because a projector that maps it onto a
// non-empty value would resurrect the anonymous grant the gate above
// refuses.
func TestHandleCIBA_SubjectProjectorNeverSeesEmptySubject(t *testing.T) {
	t.Parallel()
	f := newCIBAFixture(t)
	const authReqID = "auth-req-projector-empty"
	f.seedCIBARequest(t, &store.CIBARequest{ID: authReqID, Scope: []string{"openid"}})
	if err := f.store.CIBARequests().Approve(context.Background(), authReqID, "", "", f.clock.now); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	var sawEmpty bool
	f.deps.SubjectProjector = func(_ context.Context, raw string, _ *store.Client) (string, error) {
		if raw == "" {
			sawEmpty = true
			return "projector-invented-subject", nil
		}
		return raw, nil
	}

	rec := f.post(t, url.Values{
		"grant_type":  {"urn:openid:params:grant-type:ciba"},
		"auth_req_id": {authReqID},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if sawEmpty {
		t.Error("SubjectProjector was invoked with an empty raw subject")
	}
	assertNoCredentialsIssued(t, rec.Body.Bytes())
}
