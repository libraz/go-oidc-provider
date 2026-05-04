package op_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
)

// stubHintResolver is a deterministic [op.HintResolver] used by the
// option-layer tests. The tests do not exercise /bc-authorize end-to-
// end; they only need a non-nil resolver so [op.WithCIBA] passes its
// construction-time validation.
type stubHintResolver struct {
	subject string
	err     error
}

func (s stubHintResolver) Resolve(_ context.Context, _ op.HintKind, _ string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	if s.subject == "" {
		return "user-123", nil
	}
	return s.subject, nil
}

// TestWithCIBA_AcceptsValidConfig confirms a fully wired [op.WithCIBA]
// constructs without error against the inmem reference store (which
// ships a non-nil [store.CIBARequestStore]).
func TestWithCIBA_AcceptsValidConfig(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithCIBA(op.WithCIBAHintResolver(stubHintResolver{})),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
}

// TestWithCIBA_RejectsMissingHintResolver pins the contract that the
// /bc-authorize endpoint cannot resolve hints without an embedder-
// supplied resolver. Surfacing the misconfiguration at construction
// time spares the embedder from finding out via login_required on
// every request.
func TestWithCIBA_RejectsMissingHintResolver(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithCIBA(),
	)...)
	if err == nil {
		t.Fatal("expected error when WithCIBA is invoked without a HintResolver")
	}
	if !strings.Contains(err.Error(), "HintResolver") {
		t.Errorf("err = %v, want it to mention HintResolver", err)
	}
}

// TestWithCIBA_RejectsMissingSubstore pins the substore-presence gate.
// stubStore intentionally returns nil from CIBARequests so any
// embedder who forgets to wire the substore sees the construction
// error rather than a runtime nil panic on the first /bc-authorize
// POST.
func TestWithCIBA_RejectsMissingSubstore(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithCIBA(op.WithCIBAHintResolver(stubHintResolver{})),
	)...)
	if err == nil {
		t.Fatal("expected error when CIBARequests substore is nil")
	}
	if !strings.Contains(err.Error(), "CIBARequests") {
		t.Errorf("err = %v, want it to mention CIBARequests", err)
	}
}

// TestWithGrants_CIBA_RejectsMissingSubstore mirrors
// [TestWithCIBA_RejectsMissingSubstore] for the alternative entry
// point: an embedder that activates CIBA via [op.WithGrants] (rather
// than the dedicated [op.WithCIBA] option) must still see the
// construction error when the configured Store does not provide a
// CIBARequests substore. Prior to the fix this path bypassed the
// gate and the runtime reached a nil-substore Save on the first
// /bc-authorize POST.
func TestWithGrants_CIBA_RejectsMissingSubstore(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithGrants(grant.CIBA),
	)...)
	if err == nil {
		t.Fatal("expected error when CIBARequests substore is nil under WithGrants(grant.CIBA)")
	}
	if !strings.Contains(err.Error(), "CIBARequests") {
		t.Errorf("err = %v, want it to mention CIBARequests", err)
	}
}

// TestWithGrants_CIBA_RejectsMissingHintResolver mirrors
// [TestWithCIBA_RejectsMissingHintResolver] for the alternative
// entry point: configuring CIBA via [op.WithGrants] without
// supplying a HintResolver MUST surface the same construction error
// as the dedicated option.
func TestWithGrants_CIBA_RejectsMissingHintResolver(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithGrants(grant.CIBA),
	)...)
	if err == nil {
		t.Fatal("expected error when WithGrants(grant.CIBA) is used without a HintResolver")
	}
	if !strings.Contains(err.Error(), "HintResolver") {
		t.Errorf("err = %v, want it to mention HintResolver", err)
	}
}

// TestWithCIBA_DiscoveryAdvertisesEndpoint confirms the discovery
// document advertises the /bc-authorize endpoint and the poll-only
// delivery mode list when the CIBA grant is configured. RPs depend on
// the wire shape to negotiate the grant.
func TestWithCIBA_DiscoveryAdvertisesEndpoint(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithCIBA(op.WithCIBAHintResolver(stubHintResolver{})),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/.well-known/openid-configuration", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("get discovery: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status=%d want 200", resp.StatusCode)
	}
	var body struct {
		BackchannelAuthenticationEndpoint      string   `json:"backchannel_authentication_endpoint"`
		BackchannelTokenDeliveryModesSupported []string `json:"backchannel_token_delivery_modes_supported"`
		BackchannelUserCodeParameterSupported  bool     `json:"backchannel_user_code_parameter_supported"`
		GrantTypesSupported                    []string `json:"grant_types_supported"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasSuffix(body.BackchannelAuthenticationEndpoint, "/bc-authorize") {
		t.Errorf("backchannel_authentication_endpoint=%q want suffix /bc-authorize", body.BackchannelAuthenticationEndpoint)
	}
	if len(body.BackchannelTokenDeliveryModesSupported) != 1 || body.BackchannelTokenDeliveryModesSupported[0] != "poll" {
		t.Errorf("backchannel_token_delivery_modes_supported=%v want [poll]", body.BackchannelTokenDeliveryModesSupported)
	}
	if body.BackchannelUserCodeParameterSupported {
		t.Errorf("backchannel_user_code_parameter_supported=true want false")
	}
	hasCIBA := false
	for _, g := range body.GrantTypesSupported {
		if g == "urn:openid:params:grant-type:ciba" {
			hasCIBA = true
			break
		}
	}
	if !hasCIBA {
		t.Errorf("grant_types_supported=%v want it to include the CIBA URN", body.GrantTypesSupported)
	}
}

// TestWithCIBA_RouterMountsEndpoint confirms the OP mounts
// /bc-authorize on its router. The check is shape-only: a GET reaches
// the handler and gets back HTTP 405 (the handler accepts POST only).
func TestWithCIBA_RouterMountsEndpoint(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithCIBA(op.WithCIBAHintResolver(stubHintResolver{})),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/oidc/bc-authorize", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("get /bc-authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status=%d want 405 (handler is mounted but accepts POST only)", resp.StatusCode)
	}
}

// TestWithCIBA_OmitsEndpointWhenNotConfigured confirms a deployment
// that does not opt into the CIBA grant keeps the /bc-authorize route
// absent (404) and the four CIBA discovery fields absent. The library
// gates the router and the discovery advertisement on the same flag
// so an OP cannot tell clients the endpoint exists while quietly
// serving 404.
func TestWithCIBA_OmitsEndpointWhenNotConfigured(t *testing.T) {
	t.Parallel()

	provider, err := op.New(validBaseOptsWithInmem(t)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/oidc/bc-authorize", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("post /bc-authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status=%d want 404 (route should not be mounted when CIBA grant is off)", resp.StatusCode)
	}

	discoveryReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/.well-known/openid-configuration", nil)
	if err != nil {
		t.Fatalf("discovery request: %v", err)
	}
	discoveryResp, err := srv.Client().Do(discoveryReq)
	if err != nil {
		t.Fatalf("discovery get: %v", err)
	}
	defer discoveryResp.Body.Close()
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(discoveryResp.Body).Decode(&raw); err != nil {
		t.Fatalf("discovery decode: %v", err)
	}
	for _, key := range []string{
		"backchannel_authentication_endpoint",
		"backchannel_token_delivery_modes_supported",
		"backchannel_user_code_parameter_supported",
		"backchannel_authentication_request_signing_alg_values_supported",
	} {
		if _, present := raw[key]; present {
			t.Errorf("discovery includes %q when CIBA grant is off", key)
		}
	}
}

// TestWithCIBADefaultExpiresIn_RejectsNegative pins the option's
// negative-value rejection so a typo cannot silently advertise a
// negative expires_in.
func TestWithCIBADefaultExpiresIn_RejectsNegative(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithCIBA(
			op.WithCIBAHintResolver(stubHintResolver{}),
			op.WithCIBADefaultExpiresIn(-1*time.Second),
		),
	)...)
	if err == nil {
		t.Fatal("expected error for negative WithCIBADefaultExpiresIn")
	}
	if !strings.Contains(err.Error(), "WithCIBADefaultExpiresIn") {
		t.Errorf("err = %v, want it to name the option", err)
	}
}

// TestWithCIBAMaxExpiresIn_RejectsNegative mirrors the
// default-expires-in rejection on the cap option.
func TestWithCIBAMaxExpiresIn_RejectsNegative(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithCIBA(
			op.WithCIBAHintResolver(stubHintResolver{}),
			op.WithCIBAMaxExpiresIn(-1*time.Second),
		),
	)...)
	if err == nil {
		t.Fatal("expected error for negative WithCIBAMaxExpiresIn")
	}
	if !strings.Contains(err.Error(), "WithCIBAMaxExpiresIn") {
		t.Errorf("err = %v, want it to name the option", err)
	}
}

// TestWithCIBAPollInterval_RejectsNegative mirrors the
// expiry-options' negative-value rejection on the poll-interval
// option.
func TestWithCIBAPollInterval_RejectsNegative(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithCIBA(
			op.WithCIBAHintResolver(stubHintResolver{}),
			op.WithCIBAPollInterval(-1*time.Second),
		),
	)...)
	if err == nil {
		t.Fatal("expected error for negative WithCIBAPollInterval")
	}
	if !strings.Contains(err.Error(), "WithCIBAPollInterval") {
		t.Errorf("err = %v, want it to name the option", err)
	}
}

// TestWithCIBAHintResolver_RejectsNil pins the option's nil-resolver
// rejection so a typo cannot silently disable hint resolution.
func TestWithCIBAHintResolver_RejectsNil(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithCIBA(op.WithCIBAHintResolver(nil)),
	)...)
	if err == nil {
		t.Fatal("expected error for nil HintResolver")
	}
	if !strings.Contains(err.Error(), "non-nil HintResolver") {
		t.Errorf("err = %v, want it to mention non-nil HintResolver", err)
	}
}

// TestHintResolverFunc_AdaptsFunction confirms the function-typed
// adapter satisfies [op.HintResolver]. The adapter is the public
// surface every embedder will use; a regression that breaks it would
// force everyone to ship a struct.
func TestHintResolverFunc_AdaptsFunction(t *testing.T) {
	t.Parallel()

	wantSubject := "user-via-fn"
	resolver := op.HintResolverFunc(func(_ context.Context, _ op.HintKind, _ string) (string, error) {
		return wantSubject, nil
	})
	got, err := resolver.Resolve(context.Background(), op.HintLoginHint, "alice")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != wantSubject {
		t.Errorf("subject=%q want %q", got, wantSubject)
	}
}

// TestErrUnknownCIBAUser_IsRecognised pins the public sentinel as
// errors.Is-compatible with the underlying internal sentinel so an
// embedder writing `if errors.Is(err, op.ErrUnknownCIBAUser)` inside
// a [op.HintResolver] gets the expected unknown_user_id mapping.
func TestErrUnknownCIBAUser_IsRecognised(t *testing.T) {
	t.Parallel()

	if op.ErrUnknownCIBAUser == nil {
		t.Fatal("op.ErrUnknownCIBAUser is nil")
	}
	wrapped := errors.Join(op.ErrUnknownCIBAUser, errors.New("context"))
	if !errors.Is(wrapped, op.ErrUnknownCIBAUser) {
		t.Errorf("errors.Is failed against op.ErrUnknownCIBAUser")
	}
}
