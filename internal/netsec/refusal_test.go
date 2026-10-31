package netsec_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/netsec"
)

func TestRefusalPredicates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		err        error
		denyListed bool
		refusal    bool
	}{
		{"private", netsec.ErrPrivateNetworkBlocked, true, true},
		{"metadata wrapped", fmt.Errorf("x: %w", netsec.ErrCloudMetadataBlocked), true, true},
		{"scheme", netsec.ErrSchemeNotAllowed, false, true},
		{"missing host", netsec.ErrMissingHost, false, true},
		{"other", errors.New("boom"), false, false},
		{"nil", nil, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := netsec.IsDenyListed(tc.err); got != tc.denyListed {
				t.Errorf("IsDenyListed = %v, want %v", got, tc.denyListed)
			}
			if got := netsec.IsRequestRefusal(tc.err); got != tc.refusal {
				t.Errorf("IsRequestRefusal = %v, want %v", got, tc.refusal)
			}
		})
	}
}
