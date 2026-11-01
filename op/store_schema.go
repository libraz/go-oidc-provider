package op

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// schemaCandidate is one store the configuration uses, with the label a
// schema failure is reported under.
type schemaCandidate struct {
	label string
	store any
}

// checkStoreState runs the construction-time reads of the store: the schema
// check first, so the subject-mode gate never reads a table that is missing.
func (c *config) checkStoreState(ctx context.Context) (commit func(context.Context) error, err error) {
	if err := c.validateStoreSchema(ctx); err != nil {
		return nil, err
	}
	return c.checkSubjectModeGate(ctx)
}

// validateStoreSchema asks every store the configuration uses, and that
// implements [store.SchemaValidator], to check its persistent schema, and
// joins the failures into one configuration error. It runs before the
// subject-mode gate, which reads Metadata and Grants, so a missing table
// there fails in the same shape as any other.
func (c *config) validateStoreSchema(ctx context.Context) error {
	if nilcheck.IsNil(c.store) {
		return nil
	}
	var errs []error
	checked := make([]any, 0, 16)
	for _, cand := range c.schemaCandidates() {
		if nilcheck.IsNil(cand.store) || schemaAlreadyChecked(checked, cand.store) {
			continue
		}
		checked = append(checked, cand.store)
		v, ok := cand.store.(store.SchemaValidator)
		if !ok {
			continue
		}
		if err := v.ValidateSchema(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", cand.label, err))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return newConfigurationError("store schema does not match this configuration", errors.Join(errs...))
}

// schemaCandidates lists the stores the configuration uses, in report
// order. Nil entries are left for the caller to skip.
func (c *config) schemaCandidates() []schemaCandidate {
	s := c.store
	out := []schemaCandidate{
		{"Clients", s.Clients()},
		{"Metadata", s.Metadata()},
		{"ConsumedJTIs", s.ConsumedJTIs()},
		{"AccessTokens", s.AccessTokens()},
		{"OpaqueAccessTokens", s.OpaqueAccessTokens()},
		{"GrantRevocations", s.GrantRevocations()},
		{"Grants", s.Grants()},
	}
	if slices.Contains(c.grants, grant.AuthorizationCode) {
		out = append(out, schemaCandidate{"AuthorizationCodes", s.AuthorizationCodes()})
	}
	if slices.Contains(c.grants, grant.RefreshToken) {
		out = append(out, schemaCandidate{"RefreshTokens", s.RefreshTokens()})
	}
	if grantsRequireAuthorizeEndpoint(c.grants) {
		out = append(out,
			schemaCandidate{"Sessions", s.Sessions()},
			schemaCandidate{"Interactions", s.Interactions()},
		)
	}
	if featureEnabled(c.features, feature.PAR) {
		out = append(out, schemaCandidate{"PushedAuthRequests", s.PushedAuthRequests()})
	}
	if c.dcr != nil {
		out = append(out,
			schemaCandidate{"InitialAccessTokens", s.InitialAccessTokens()},
			schemaCandidate{"RegistrationAccessTokens", s.RegistrationAccessTokens()},
		)
	}
	if c.deviceCodeGrantConfiguredOrEnabled() {
		out = append(out, schemaCandidate{"DeviceCodes", s.DeviceCodes()})
	}
	if c.cibaGrantConfiguredOrEnabled() {
		out = append(out, schemaCandidate{"CIBARequests", s.CIBARequests()})
	}
	if ssf, ok := s.(store.SharedSignalsStore); ok && c.sharedSignals {
		out = append(out,
			schemaCandidate{"SSFStreams", ssf.SSFStreams()},
			schemaCandidate{"SSFEvents", ssf.SSFEvents()},
		)
	}
	out = append(out, schemaCandidate{"user store", c.effectiveUserStore()})
	steps := c.loginFlowSteps()
	for _, step := range steps {
		out = append(out, stepSchemaStores(step)...)
	}
	if slices.ContainsFunc(steps, countsFailures) {
		out = append(out, schemaCandidate{"authn lockout store", resolveAuthnLockoutStore(c)})
	}
	return out
}

// stepSchemaStores returns the stores a built-in step reads and writes.
// Embedder-supplied steps, whose internals the library cannot inspect,
// return nil.
func stepSchemaStores(s Step) []schemaCandidate {
	switch step := s.(type) {
	case PrimaryPassword:
		return []schemaCandidate{{"LoginFlow PrimaryPassword.Store", step.Store}}
	case PrimaryPasskey:
		return []schemaCandidate{{"LoginFlow PrimaryPasskey.Store", step.Store}}
	case StepTOTP:
		return []schemaCandidate{{"LoginFlow StepTOTP.Store", step.Store}}
	case StepEmailOTP:
		return []schemaCandidate{
			{"LoginFlow StepEmailOTP.Store", step.Store},
			{"LoginFlow StepEmailOTP.Users", step.Users},
		}
	case StepRecoveryCode:
		return []schemaCandidate{{"LoginFlow StepRecoveryCode.Store", step.Store}}
	default:
		return nil
	}
}

// schemaAlreadyChecked reports whether v equals a store already checked.
// Values of a non-comparable dynamic type are never treated as seen,
// since comparing them panics; their check simply runs again.
func schemaAlreadyChecked(checked []any, v any) bool {
	if !reflect.ValueOf(v).Comparable() {
		return false
	}
	for _, prev := range checked {
		if reflect.ValueOf(prev).Comparable() && prev == v {
			return true
		}
	}
	return false
}
