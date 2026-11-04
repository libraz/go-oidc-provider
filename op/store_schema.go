package op

import (
	"context"
	"reflect"
	"slices"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/nilcheck"
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
	var errs schemaErrors
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
			errs = append(errs, schemaError{cand.label, err})
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return newConfigurationError("store schema does not match this configuration", errs)
}

// schemaError is one store's schema failure and the label it is reported under.
type schemaError struct {
	label string
	err   error
}

// schemaErrors joins per-store schema failures one labelled line each, like
// [errors.Join], except that a line several stores report — a shared
// remedy such as how to create missing tables — is printed once, last and
// unlabelled.
type schemaErrors []schemaError

func (e schemaErrors) Error() string {
	reports := make([][]string, len(e))
	seen := map[string]int{}
	for i, se := range e {
		reports[i] = strings.Split(se.err.Error(), "\n")
		for _, line := range slices.Compact(slices.Sorted(slices.Values(reports[i][1:]))) {
			seen[line]++
		}
	}
	var out, shared []string
	for i, lines := range reports {
		out = append(out, e[i].label+": "+lines[0])
		for _, line := range lines[1:] {
			switch {
			case seen[line] < 2:
				out = append(out, e[i].label+": "+line)
			case !slices.Contains(shared, line):
				shared = append(shared, line)
			}
		}
	}
	return strings.Join(append(out, shared...), "\n")
}

func (e schemaErrors) Unwrap() []error {
	out := make([]error, len(e))
	for i, se := range e {
		out[i] = se.err
	}
	return out
}

// schemaCandidates lists the stores the configuration uses, in report
// order. Nil entries are left for the caller to skip.
func (c *config) schemaCandidates() []schemaCandidate {
	s := c.store
	var out []schemaCandidate
	for _, row := range storeTableManifest {
		if row.when == nil || row.when(c) {
			out = append(out, schemaCandidate{row.label, row.store(s)})
		}
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
