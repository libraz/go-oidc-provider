package pollgrant_test

import (
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/grants/pollgrant"
	"github.com/libraz/go-oidc-provider/op/store"
)

var (
	errNotPermitted = errors.New("not permitted")
	errNoSubject    = errors.New("no subject")
	errCnfMissing   = errors.New("cnf missing")
	errCnfMismatch  = errors.New("cnf mismatch")
	errScope        = errors.New("scope")
	errStatus       = errors.New("status")
)

var sentinels = pollgrant.Errors{
	NotPermitted:   errNotPermitted,
	SubjectMissing: errNoSubject,
	CnfMissing:     errCnfMissing,
	CnfMismatch:    errCnfMismatch,
	ScopeForbidden: errScope,
}

func TestAuthorize(t *testing.T) {
	t.Parallel()
	client := &store.Client{GrantTypes: []string{"g"}, Scopes: []string{"openid", "email"}}
	base := pollgrant.Record{Subject: "u", Scope: []string{"openid"}, Resource: []string{"https://rs"}}
	tests := []struct {
		name      string
		client    *store.Client
		rec       pollgrant.Record
		presented pollgrant.Presented
		statusErr error
		wantErr   error
		wantBind  string
	}{
		{"bearer", client, base, pollgrant.Presented{}, nil, nil, "bearer"},
		{"grant not registered wins over status", &store.Client{}, base, pollgrant.Presented{}, errStatus, errNotPermitted, ""},
		{"status", client, base, pollgrant.Presented{}, errStatus, errStatus, ""},
		{"no subject", client, pollgrant.Record{Scope: []string{"openid"}}, pollgrant.Presented{}, nil, errNoSubject, ""},
		{"dpop missing", client, withBinding(base, "jkt", ""), pollgrant.Presented{}, nil, errCnfMissing, ""},
		{"dpop mismatch", client, withBinding(base, "jkt", ""), pollgrant.Presented{DPoPJKT: "other"}, nil, errCnfMismatch, ""},
		{"dpop", client, withBinding(base, "jkt", ""), pollgrant.Presented{DPoPJKT: "jkt"}, nil, nil, "dpop"},
		{"both bound, only dpop presented", client, withBinding(base, "jkt", "x5t"), pollgrant.Presented{DPoPJKT: "jkt"}, nil, errCnfMissing, ""},
		{"both", client, withBinding(base, "jkt", "x5t"), pollgrant.Presented{DPoPJKT: "jkt", MTLSCertS256: "x5t"}, nil, nil, "dpop+mtls"},
		{"scope ceiling", client, pollgrant.Record{Subject: "u", Scope: []string{"admin"}}, pollgrant.Presented{}, nil, errScope, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := pollgrant.Authorize(tc.client, "g", tc.rec, tc.presented, tc.statusErr, sentinels)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err=%v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && got.SenderConstraint != tc.wantBind {
				t.Fatalf("binding=%q, want %q", got.SenderConstraint, tc.wantBind)
			}
		})
	}
}

func withBinding(r pollgrant.Record, jkt, x5t string) pollgrant.Record {
	r.DPoPJKT, r.MTLSCertS256 = jkt, x5t
	return r
}
