package op_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestWithDeviceCodeGrant_AcceptsValidConfig confirms the dedicated
// opt-in option constructs without error against the inmem reference
// store (which ships a non-nil [store.DeviceCodeStore]).
func TestWithDeviceCodeGrant_AcceptsValidConfig(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithDeviceCodeGrant(),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
}

// TestWithDeviceCodeGrant_RejectsMissingSubstore pins the
// substore-presence gate. stubStore intentionally returns nil from
// DeviceCodes so an embedder who forgets to wire the substore sees
// the construction error rather than a runtime nil panic on the
// first /device_authorization POST.
func TestWithDeviceCodeGrant_RejectsMissingSubstore(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithDeviceCodeGrant(),
	)...)
	if err == nil {
		t.Fatal("expected error when DeviceCodes substore is nil")
	}
	if !strings.Contains(err.Error(), "DeviceCodes") {
		t.Errorf("err = %v, want it to mention DeviceCodes", err)
	}
}

// TestWithGrants_DeviceCode_RejectsMissingSubstore mirrors
// [TestWithDeviceCodeGrant_RejectsMissingSubstore] for the alternative
// entry point: an embedder that activates the device_code grant via
// [op.WithGrants] (rather than the dedicated [op.WithDeviceCodeGrant]
// option) must still see the construction error when the configured
// Store does not provide a DeviceCodes substore. Prior to the fix
// this path bypassed the gate and the runtime reached a nil-substore
// Save on the first /device_authorization POST.
func TestWithGrants_DeviceCode_RejectsMissingSubstore(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithGrants(grant.DeviceCode),
	)...)
	if err == nil {
		t.Fatal("expected error when DeviceCodes substore is nil under WithGrants(grant.DeviceCode)")
	}
	if !strings.Contains(err.Error(), "DeviceCodes") {
		t.Errorf("err = %v, want it to mention DeviceCodes", err)
	}
}

// TestWithDeviceCodeExpiry_RejectsNonPositive pins the option-site
// validation: zero and negative durations are rejected so a
// misconfiguration surfaces at construction time.
func TestWithDeviceCodeExpiry_RejectsNonPositive(t *testing.T) {
	t.Parallel()

	for _, ttl := range []time.Duration{0, -1 * time.Second} {
		_, err := op.New(append(validBaseOptsWithInmem(t),
			op.WithDeviceCodeGrant(),
			op.WithDeviceCodeExpiry(ttl),
		)...)
		if err == nil {
			t.Fatalf("WithDeviceCodeExpiry(%v): expected error", ttl)
		}
	}
}

// TestWithDeviceCodePollInterval_RejectsNonPositive mirrors
// [TestWithDeviceCodeExpiry_RejectsNonPositive] for the poll-interval
// knob.
func TestWithDeviceCodePollInterval_RejectsNonPositive(t *testing.T) {
	t.Parallel()

	for _, interval := range []time.Duration{0, -1 * time.Second} {
		_, err := op.New(append(validBaseOptsWithInmem(t),
			op.WithDeviceCodeGrant(),
			op.WithDeviceCodePollInterval(interval),
		)...)
		if err == nil {
			t.Fatalf("WithDeviceCodePollInterval(%v): expected error", interval)
		}
	}
}

// TestWithDeviceCodeExpiry_IndependentOfShortAccessTokenTTL pins the
// defect fix: the device_code `expires_in` advertised at
// /device_authorization must be driven by [op.WithDeviceCodeExpiry],
// NOT derived from [op.WithAccessTokenTTL]. Before the fix, a
// deployment running a short access-token TTL (seconds) made the
// device flow impractical because expires_in silently inherited that
// short lifetime. The fixture pins a 90-second access-token TTL
// alongside an explicit 20-minute device_code expiry and asserts the
// wire expires_in reflects the latter.
func TestWithDeviceCodeExpiry_IndependentOfShortAccessTokenTTL(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	const clientSecret = "dev-ttl-secret" //nolint:gosec // test fixture, not a real credential.
	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	client := &store.Client{
		ID:                      "dev-ttl-client",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"urn:ietf:params:oauth:grant-type:device_code"},
		Scopes:                  []string{"openid"},
	}
	if err := s.RegisterClient(context.Background(), client); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	const shortAccessTokenTTL = 90 * time.Second
	const deviceCodeExpiry = 20 * time.Minute

	provider, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(s),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
		op.WithDeviceCodeGrant(),
		op.WithAccessTokenTTL(shortAccessTokenTTL),
		op.WithDeviceCodeExpiry(deviceCodeExpiry),
	)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	t.Cleanup(srv.Close)

	form := url.Values{}
	form.Set("scope", "openid")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/oidc/device_authorization", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ID, clientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /device_authorization: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body struct {
		ExpiresIn int64 `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	wantExpiresIn := int64(deviceCodeExpiry / time.Second)
	if body.ExpiresIn != wantExpiresIn {
		t.Fatalf("expires_in = %d, want %d (independent of the %v access-token TTL)",
			body.ExpiresIn, wantExpiresIn, shortAccessTokenTTL)
	}
	if body.ExpiresIn == int64(shortAccessTokenTTL/time.Second) {
		t.Fatalf("expires_in = %d matches the access-token TTL; the device_code TTL is still coupled", body.ExpiresIn)
	}
}
