package tokenendpoint_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/op/store"
)

// TestRefresh_MTLS_HappyPath rotates an mTLS-bound refresh token.
// The rotated record MUST carry the same thumbprint so subsequent
// refreshes are still gated on the cert.
func TestRefresh_MTLS_HappyPath(t *testing.T) {
	t.Parallel()

	f := mtlsFixture(t)
	client, secret := f.confidentialClientFixture(t)
	cert := generateMTLSLeaf(t)
	thumb := mtls.Thumbprint(cert)

	const tokenID = "rt-mtls-happy" //nolint:gosec // not a credential — opaque test fixture id.
	f.seedGrant(t, &store.Grant{
		ID: "grant-mtls-happy", Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:                 tokenID,
		ClientID:           client.ID,
		Subject:            "user-1",
		GrantID:            "grant-mtls-happy",
		Scope:              []string{"openid"},
		MTLSCertThumbprint: thumb,
	})

	resp := postWithMTLS(t, f.prov, refreshForm(tokenID, ""), client.ID, secret, cert)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeMTLSResp(t, resp))
	}
	body := decodeMTLSResp(t, resp)
	rotated, _ := body["refresh_token"].(string)
	if rotated == "" || rotated == tokenID {
		t.Errorf("refresh_token must rotate; got %q (input %q)", rotated, tokenID)
	}

	// The rotated record MUST carry the same thumbprint.
	rec, err := f.prov.Store.RefreshTokens().Find(context.Background(), rotated)
	if err != nil {
		t.Fatalf("Find rotated: %v", err)
	}
	if rec.MTLSCertThumbprint != thumb {
		t.Errorf("rotated MTLSCertThumbprint=%q want %q", rec.MTLSCertThumbprint, thumb)
	}
}

// TestRefresh_MTLS_MissingCert rejects a refresh of an mTLS-bound
// token when no client cert is presented.
func TestRefresh_MTLS_MissingCert(t *testing.T) {
	t.Parallel()

	f := mtlsFixture(t)
	client, secret := f.confidentialClientFixture(t)
	cert := generateMTLSLeaf(t)

	const tokenID = "rt-mtls-nocert" //nolint:gosec // not a credential — opaque test fixture id.
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:                 tokenID,
		ClientID:           client.ID,
		Subject:            "user-1",
		GrantID:            "grant-mtls-nocert",
		Scope:              []string{"openid"},
		MTLSCertThumbprint: mtls.Thumbprint(cert),
	})

	resp := postWithMTLS(t, f.prov, refreshForm(tokenID, ""), client.ID, secret, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if got := decodeMTLSResp(t, resp)["error"]; got != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", got)
	}
	assertRefreshTokenUnconsumed(t, f, tokenID)
}

// TestRefresh_MTLS_ThumbprintMismatch rejects a refresh whose cert
// is not the bound one.
func TestRefresh_MTLS_ThumbprintMismatch(t *testing.T) {
	t.Parallel()

	f := mtlsFixture(t)
	client, secret := f.confidentialClientFixture(t)
	bound := generateMTLSLeaf(t)
	other := generateMTLSLeaf(t)

	const tokenID = "rt-mtls-mismatch" //nolint:gosec // not a credential — opaque test fixture id.
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:                 tokenID,
		ClientID:           client.ID,
		Subject:            "user-1",
		GrantID:            "grant-mtls-mismatch",
		Scope:              []string{"openid"},
		MTLSCertThumbprint: mtls.Thumbprint(bound),
	})

	resp := postWithMTLS(t, f.prov, refreshForm(tokenID, ""), client.ID, secret, other)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if got := decodeMTLSResp(t, resp)["error"]; got != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", got)
	}
	assertRefreshTokenUnconsumed(t, f, tokenID)
}

// TestRefresh_MTLS_BearerChainStillWorks confirms a bearer chain (no
// MTLSCertThumbprint) refreshes without requiring a cert, even when
// the feature is enabled.
func TestRefresh_MTLS_BearerChainStillWorks(t *testing.T) {
	t.Parallel()

	f := mtlsFixture(t)
	client, secret := f.confidentialClientFixture(t)

	const tokenID = "rt-mtls-bearer" //nolint:gosec // not a credential — opaque test fixture id.
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-bearer-mtls",
		Scope:    []string{"openid"},
	})

	resp := postWithMTLS(t, f.prov, refreshForm(tokenID, ""), client.ID, secret, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeMTLSResp(t, resp))
	}
	if got := decodeMTLSResp(t, resp)["token_type"]; got != "Bearer" {
		t.Errorf("token_type=%v want Bearer", got)
	}
}

// TestRefresh_MTLS_NoUpgrade verifies the documented "no opportunistic
// upgrade" rule: a bearer chain refreshed WITH a cert presented stays
// a bearer chain. Unlike DPoP, mTLS binds at issuance only.
func TestRefresh_MTLS_NoUpgrade(t *testing.T) {
	t.Parallel()

	f := mtlsFixture(t)
	client, secret := f.confidentialClientFixture(t)
	cert := generateMTLSLeaf(t)

	const tokenID = "rt-mtls-no-upgrade" //nolint:gosec // not a credential — opaque test fixture id.
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-no-upgrade",
		Scope:    []string{"openid"},
	})

	resp := postWithMTLS(t, f.prov, refreshForm(tokenID, ""), client.ID, secret, cert)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeMTLSResp(t, resp))
	}
	body := decodeMTLSResp(t, resp)
	if got := body["token_type"]; got != "Bearer" {
		t.Errorf("token_type=%v want Bearer (no mid-chain upgrade)", got)
	}
	rotated, _ := body["refresh_token"].(string)
	rec, err := f.prov.Store.RefreshTokens().Find(context.Background(), rotated)
	if err != nil {
		t.Fatalf("Find rotated: %v", err)
	}
	if rec.MTLSCertThumbprint != "" {
		t.Errorf("rotated MTLSCertThumbprint=%q want empty (no upgrade)", rec.MTLSCertThumbprint)
	}
}
