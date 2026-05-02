package op_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// fakeCustomGrant is a no-op CustomGrantHandler used to exercise the
// option-site validation paths. The Handle method is never invoked in
// option tests; the dispatcher integration tests live alongside the
// internal dispatcher in a later chunk.
type fakeCustomGrant struct {
	name   string
	policy op.ParamPolicy
}

func (f fakeCustomGrant) Name() string                { return f.name }
func (f fakeCustomGrant) ParamPolicy() op.ParamPolicy { return f.policy }
func (f fakeCustomGrant) Handle(_ context.Context, _ op.CustomGrantRequest) (op.CustomGrantResponse, error) {
	return op.CustomGrantResponse{}, nil
}

func TestWithCustomGrant_AcceptsURNHandler(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t),
		op.WithCustomGrant(fakeCustomGrant{name: "urn:example:grant-type:test"}),
	)...)
	if err != nil {
		t.Fatalf("op.New returned error: %v", err)
	}
	if provider == nil {
		t.Fatal("op.New returned nil provider with no error")
	}
}

func TestWithCustomGrant_RejectsNilHandler(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithCustomGrant(nil))...)
	if !errors.Is(err, op.ErrCustomGrantNil) {
		t.Fatalf("op.New err = %v, want %v", err, op.ErrCustomGrantNil)
	}
}

func TestWithCustomGrant_RejectsEmptyName(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithCustomGrant(fakeCustomGrant{name: ""}))...)
	if !errors.Is(err, op.ErrCustomGrantNameEmpty) {
		t.Fatalf("op.New err = %v, want %v", err, op.ErrCustomGrantNameEmpty)
	}
}

func TestWithCustomGrant_RejectsBuiltinCollision(t *testing.T) {
	t.Parallel()

	cases := []string{
		"authorization_code",
		"refresh_token",
		"client_credentials",
		"urn:ietf:params:oauth:grant-type:device_code",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOpts(t),
				op.WithCustomGrant(fakeCustomGrant{name: name}),
			)...)
			if !errors.Is(err, op.ErrCustomGrantBuiltinCollision) {
				t.Fatalf("op.New err = %v, want %v", err, op.ErrCustomGrantBuiltinCollision)
			}
		})
	}
}

func TestWithCustomGrant_RejectsDuplicateRegistration(t *testing.T) {
	t.Parallel()

	const name = "urn:example:grant-type:dup"
	_, err := op.New(append(validBaseOpts(t),
		op.WithCustomGrant(fakeCustomGrant{name: name}),
		op.WithCustomGrant(fakeCustomGrant{name: name}),
	)...)
	if !errors.Is(err, op.ErrCustomGrantDuplicate) {
		t.Fatalf("op.New err = %v, want %v", err, op.ErrCustomGrantDuplicate)
	}
}

func TestWithCustomGrant_RejectsSecretLikeExempt(t *testing.T) {
	t.Parallel()

	cases := []string{
		"grant_type",
		"client_id",
		"client_secret",
		"code",
		"code_verifier",
		"refresh_token",
		"subject_token",
		"actor_token",
		"password",
		"client_assertion",
		"client_assertion_type",
	}
	for _, dup := range cases {
		t.Run(dup, func(t *testing.T) {
			t.Parallel()
			handler := fakeCustomGrant{
				name:   "urn:example:grant-type:" + dup,
				policy: op.ParamPolicy{Allowed: []string{dup}, DupesAllowed: []string{dup}},
			}
			_, err := op.New(append(validBaseOpts(t), op.WithCustomGrant(handler))...)
			if !errors.Is(err, op.ErrCustomGrantSecretLikeExempt) {
				t.Fatalf("op.New err = %v, want %v", err, op.ErrCustomGrantSecretLikeExempt)
			}
		})
	}
}

func TestWithCustomGrant_AcceptsMultipleDistinctHandlers(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t),
		op.WithCustomGrant(fakeCustomGrant{name: "urn:example:grant-type:a"}),
		op.WithCustomGrant(fakeCustomGrant{name: "urn:example:grant-type:b"}),
		op.WithCustomGrant(fakeCustomGrant{name: "urn:example:grant-type:c"}),
	)...)
	if err != nil {
		t.Fatalf("op.New returned error: %v", err)
	}
	if provider == nil {
		t.Fatal("op.New returned nil provider with no error")
	}
}

// TestWithCustomGrant_AdvertisedInDiscovery confirms that registered
// custom grant_type names appear in the /.well-known/openid-configuration
// grant_types_supported field, in registration order, after the
// built-in grant types. This satisfies RFC 8414 §2: clients
// discovering the OP can negotiate a custom grant without out-of-band
// coordination.
func TestWithCustomGrant_AdvertisedInDiscovery(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t),
		op.WithCustomGrant(fakeCustomGrant{name: "urn:example:grant-type:alpha"}),
		op.WithCustomGrant(fakeCustomGrant{name: "urn:example:grant-type:beta"}),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	defer srv.Close()

	req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/.well-known/openid-configuration", http.NoBody)
	if reqErr != nil {
		t.Fatalf("NewRequest: %v", reqErr)
	}
	resp, doErr := srv.Client().Do(req)
	if doErr != nil {
		t.Fatalf("GET discovery: %v", doErr)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		t.Fatalf("read body: %v", readErr)
	}
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw, ok := wire["grant_types_supported"].([]any)
	if !ok {
		t.Fatalf("grant_types_supported is not a JSON array: %T (%v)",
			wire["grant_types_supported"], wire["grant_types_supported"])
	}
	got := make([]string, 0, len(raw))
	for _, v := range raw {
		s, _ := v.(string)
		got = append(got, s)
	}
	// The trailing two entries MUST be the registered customs in order;
	// the prefix carries whatever built-ins the test base wires in.
	if len(got) < 2 {
		t.Fatalf("grant_types_supported = %v, want at least 2 entries", got)
	}
	last2 := got[len(got)-2:]
	want := []string{"urn:example:grant-type:alpha", "urn:example:grant-type:beta"}
	for i, w := range want {
		if last2[i] != w {
			t.Errorf("grant_types_supported tail[%d] = %q, want %q (full=%v)", i, last2[i], w, got)
		}
	}
}
