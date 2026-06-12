package contract

import (
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// This file holds the record builders and small helpers shared between every
// sub-test. They are kept separate from the harness wiring in contract.go so
// that the file containing the contract surface stays focused on test cases.

func newAuthCode(now time.Time, id string) *store.AuthorizationCode {
	return &store.AuthorizationCode{
		ID:          id,
		ClientID:    "client",
		Subject:     "sub",
		GrantID:     "grant",
		RedirectURI: "https://rp.example.com/cb",
		Scope:       []string{"openid"},
		ExpiresAt:   now.Add(time.Hour),
		CreatedAt:   now,
	}
}

func newRefresh(now time.Time, id string, parent *string) *store.RefreshToken {
	return &store.RefreshToken{
		ID:                   id,
		ClientID:             "client",
		Subject:              "sub",
		SubjectPublic:        true,
		GrantID:              "grant",
		Scope:                []string{"openid"},
		Resource:             "https://api.example.com",
		Origin:               store.RefreshOriginCustomGrant,
		AuthTime:             now.Add(-time.Minute),
		ACR:                  "urn:acr:pwd",
		AMR:                  []string{"pwd", "otp"},
		AuthorizationDetails: []map[string]any{{"type": "payment", "amount": "100"}},
		AccessTokenExtra:     map[string]any{"act": map[string]any{"sub": "actor"}},
		ParentID:             parent,
		ExpiresAt:            now.Add(24 * time.Hour),
		CreatedAt:            now,
	}
}

func newGrant(now time.Time, id, sub, client string) *store.Grant {
	return &store.Grant{
		ID:        id,
		Subject:   sub,
		ClientID:  client,
		Scope:     []string{"openid"},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func newSession(now time.Time, id string) *store.Session {
	return &store.Session{
		ID:             id,
		Subject:        "sub",
		AuthTime:       now,
		AMR:            []string{"pwd"},
		ChooserGroupID: "cg-1",
		ExpiresAt:      now.Add(time.Hour),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

func newPAR(now time.Time, uri string) *store.PushedAuthRequest {
	return &store.PushedAuthRequest{
		URI:       uri,
		ClientID:  "client",
		RawParams: []byte(`{"client_id":"client"}`),
		ExpiresAt: now.Add(time.Minute),
		CreatedAt: now,
	}
}

func newInteraction(now time.Time, id string) *store.Interaction {
	return &store.Interaction{
		ID:        id,
		ClientID:  "client",
		Step:      "consent",
		RawState:  []byte(`{"step":"consent"}`),
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func strPtr(s string) *string { return &s }
