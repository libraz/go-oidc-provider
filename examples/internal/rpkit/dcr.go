//go:build example

package rpkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// DCROptions configures a single Dynamic Client Registration call
// (RFC 7591 / OIDC Dynamic Client Registration 1.0). The RP POSTs to
// the OP's registration_endpoint with InitialAccessToken as the
// Bearer credential and Metadata as the JSON body.
type DCROptions struct {
	// Issuer of the OP. The RP discovers registration_endpoint from
	// the OP's well-known document.
	Issuer string

	// InitialAccessToken is the IAT bearer secret the operator
	// hands the RP out-of-band. Empty when the OP runs Open=true.
	InitialAccessToken string

	// Metadata is the JSON body of the registration request. Set
	// the keys RFC 7591 §2 / OIDC DCR §2 names: "client_name",
	// "redirect_uris", "grant_types", "response_types",
	// "token_endpoint_auth_method", and so on. The map is encoded
	// verbatim, so callers control which fields appear on the wire.
	Metadata map[string]any
}

// DCRResult mirrors the subset of the registration response the
// example surface needs (RFC 7591 §3.2.1 / OIDC DCR §3.2). The RP
// uses ClientID + ClientSecret to drive subsequent token requests
// and RegistrationAccessToken + RegistrationClientURI to read /
// update / delete the registration over RFC 7592.
type DCRResult struct {
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret,omitempty"`
	RegistrationAccessToken string `json:"registration_access_token"`
	RegistrationClientURI   string `json:"registration_client_uri"`
	ClientIDIssuedAt        int64  `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   int64  `json:"client_secret_expires_at,omitempty"`

	// Raw is the full decoded JSON response so example /me handlers
	// can render every field the OP returned, not only the ones
	// rpkit pinned above.
	Raw map[string]any `json:"-"`
}

// RegisterClient runs OIDC discovery, POSTs the registration
// metadata, and decodes the response. The IAT is sent as
// "Authorization: Bearer ..." per OIDC DCR §3.1.
func RegisterClient(ctx context.Context, opts DCROptions) (*DCRResult, error) {
	endpoint, err := discoverRegistrationEndpoint(ctx, opts.Issuer)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(opts.Metadata)
	if err != nil {
		return nil, fmt.Errorf("rpkit: encode DCR metadata: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if opts.InitialAccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+opts.InitialAccessToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rpkit: POST %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rpkit: registration endpoint %d: %s",
			resp.StatusCode, string(respBody))
	}

	var out DCRResult
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("rpkit: decode DCR response: %w", err)
	}
	if out.ClientID == "" {
		return nil, errors.New("rpkit: DCR response missing client_id")
	}
	raw := map[string]any{}
	_ = json.Unmarshal(respBody, &raw)
	out.Raw = raw
	return &out, nil
}

func discoverRegistrationEndpoint(ctx context.Context, issuer string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("rpkit: discover %s: %w", issuer, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("rpkit: discovery %d: %s", resp.StatusCode, string(body))
	}
	var doc struct {
		RegistrationEndpoint string `json:"registration_endpoint"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("rpkit: decode discovery: %w", err)
	}
	if doc.RegistrationEndpoint == "" {
		return "", errors.New("rpkit: OP does not advertise registration_endpoint — enable WithDynamicRegistration")
	}
	return doc.RegistrationEndpoint, nil
}
