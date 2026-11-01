// Package pollgrant holds the authorization gates the polling grants
// (device_code and CIBA) apply identically to an approved record: grant
// registration, subject presence, sender-constraint binding and the scope
// ceiling. Each grant supplies its own record projection and sentinels, so
// callers keep their package-level error identities.
package pollgrant

import (
	"slices"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Record is the grant-neutral projection of an approved polling record.
type Record struct {
	Subject      string
	Scope        []string
	Resource     []string
	AuthTime     time.Time
	DPoPJKT      string
	MTLSCertS256 string
}

// Presented is the sender-constraint material the polling /token request
// carried.
type Presented struct {
	DPoPJKT      string
	MTLSCertS256 string
}

// Errors names the sentinels a grant reports for each gate.
type Errors struct {
	NotPermitted   error
	SubjectMissing error
	CnfMissing     error
	CnfMismatch    error
	ScopeForbidden error
}

// Approval is the successful outcome of [Authorize].
type Approval struct {
	// Scope and Audience are freshly allocated.
	Scope    []string
	Audience []string
	Subject  string
	AuthTime time.Time
	// SenderConstraint is "dpop", "mtls", "dpop+mtls" or "bearer".
	SenderConstraint string
}

// Authorize applies the gates in order: the client must list grantType;
// statusErr (the grant's record-state sentinel, nil when approved) is
// reported next; the record must name a subject; every confirmation
// method the record committed to must be satisfied by the request; and the
// record's scope must stay within the client's registered scopes.
func Authorize(
	client *store.Client,
	grantType string,
	rec Record,
	presented Presented,
	statusErr error,
	errs Errors,
) (*Approval, error) {
	if !slices.Contains(client.GrantTypes, grantType) {
		return nil, errs.NotPermitted
	}
	if statusErr != nil {
		return nil, statusErr
	}
	if rec.Subject == "" {
		return nil, errs.SubjectMissing
	}
	binding, err := matchCnfBinding(rec, presented, errs)
	if err != nil {
		return nil, err
	}
	if !oidcscope.Subset(rec.Scope, client.Scopes) {
		return nil, errs.ScopeForbidden
	}
	return &Approval{
		Scope:            slices.Clone(rec.Scope),
		Audience:         slices.Clone(rec.Resource),
		Subject:          rec.Subject,
		AuthTime:         rec.AuthTime,
		SenderConstraint: binding,
	}, nil
}

// matchCnfBinding compares the binding stored on the record against the one
// the polling client presented and returns the binding label on success.
// Every confirmation method the record committed to is evaluated
// independently and all must hold (RFC 7800 §3): stopping at the first
// populated one would let a holder of the handle plus one matching key redeem
// a dually bound record without proving the other method, and the issued
// token would still carry a cnf member the OP never re-verified. An unbound
// record is the bearer flow; the request handler rejected that combination
// where the profile forbids it.
func matchCnfBinding(rec Record, presented Presented, errs Errors) (string, error) {
	methods := make([]string, 0, 2)
	if rec.DPoPJKT != "" {
		if presented.DPoPJKT == "" {
			return "", errs.CnfMissing
		}
		if presented.DPoPJKT != rec.DPoPJKT {
			return "", errs.CnfMismatch
		}
		methods = append(methods, "dpop")
	}
	if rec.MTLSCertS256 != "" {
		if presented.MTLSCertS256 == "" {
			return "", errs.CnfMissing
		}
		if presented.MTLSCertS256 != rec.MTLSCertS256 {
			return "", errs.CnfMismatch
		}
		methods = append(methods, "mtls")
	}
	if len(methods) == 0 {
		return "bearer", nil
	}
	return strings.Join(methods, "+"), nil
}
