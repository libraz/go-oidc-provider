package authn

import (
	"regexp"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// This file is the submission-validation responsibility within the
// authn package: the bounds the orchestrator applies to every
// [interaction.FormSubmission] before an [Authenticator] or an
// [Interaction] is allowed to read it. The declarative constraints on
// [interaction.FieldSpec] are the contract a prompt publishes to its
// Driver; enforcing them here is what makes that contract binding for a
// caller that never rendered the form.

// Submission-wide bounds. They apply on top of the per-field
// [interaction.FieldSpec] constraints and cover the entries a prompt
// did not declare.
const (
	// maxSubmissionValuesBytes caps the summed byte length of every key
	// and value in a submission. It mirrors the body ceiling the
	// built-in Drivers read up to, so a Driver that assembles the map
	// by some other route cannot hand the chain a larger payload than
	// the library's own parsers would have produced.
	maxSubmissionValuesBytes = 32 * 1024

	// maxSubmissionExtraFields is how many entries a submission may
	// carry beyond the prompt's declared field list. The allowance
	// exists because a server-rendered form round-trips transport
	// fields the prompt never declares — the CSRF token most notably —
	// and an embedder-supplied template may add hidden markers of its
	// own. It is deliberately small: what the bound buys is that a
	// caller cannot hand an [Authenticator] a map of thousands of keys
	// the prompt never asked for.
	maxSubmissionExtraFields = 4
)

// Byte ceilings applied to a [interaction.FieldSpec] that leaves MaxLen
// zero, which the type documents as "use the FieldKind default". Every
// built-in factor declares an explicit MaxLen; these exist so an
// embedder-supplied prompt that omits one is still bounded.
const (
	defaultMaxLenText     = 512
	defaultMaxLenPassword = 1024
	defaultMaxLenOTPCode  = 32
	defaultMaxLenEmail    = 320
	defaultMaxLenHidden   = 16 * 1024
)

// validateSubmission enforces the constraints the outstanding prompt
// declared against the values a client submitted. inputs is the
// persisted [State.ActiveInputs] copy of that prompt's field list, so
// the limits being applied are the ones the orchestrator itself
// published rather than anything the submission carries.
//
// A prompt that declares no inputs is informational: only the
// submission-wide bounds apply, because there is no declared field for
// a per-field rule to be about.
func validateSubmission(inputs []interaction.FieldSpec, values map[string]string) error {
	if err := checkSubmissionBounds(inputs, values); err != nil {
		return err
	}
	for _, spec := range inputs {
		value, ok := values[spec.Name]
		if !ok {
			if spec.Required {
				return ErrSubmissionRejected
			}
			continue
		}
		if err := checkFieldValue(spec, value); err != nil {
			return err
		}
	}
	return nil
}

// checkSubmissionBounds applies the field-count and total-size limits.
// Both are denial-of-service bounds rather than correctness ones: they
// cap what an [Authenticator] has to walk even when every individual
// value is within its own field's ceiling.
func checkSubmissionBounds(inputs []interaction.FieldSpec, values map[string]string) error {
	if len(values) > len(inputs)+maxSubmissionExtraFields {
		return ErrSubmissionRejected
	}
	total := 0
	for name, value := range values {
		total += len(name) + len(value)
		if total > maxSubmissionValuesBytes {
			return ErrSubmissionRejected
		}
	}
	return nil
}

// checkFieldValue applies one field's declared constraints to the value
// submitted under its name.
func checkFieldValue(spec interaction.FieldSpec, value string) error {
	if value == "" {
		// A required field must carry a value; an empty one is the
		// submission saying nothing was entered. An optional field
		// submitted empty is treated as omitted — a browser posts every
		// rendered input whether or not the user filled it in — so the
		// length and pattern rules do not apply to it.
		if spec.Required {
			return ErrSubmissionRejected
		}
		return nil
	}
	if len(value) > effectiveMaxLen(spec) {
		return ErrSubmissionRejected
	}
	if spec.MinLen > 0 && len(value) < spec.MinLen {
		return ErrSubmissionRejected
	}
	return checkFieldPattern(spec, value)
}

// checkFieldPattern applies [interaction.FieldSpec.Pattern] as a full
// match: the value must match end to end rather than merely contain a
// match. Go's regexp is unanchored by default, so a pattern such as
// "[0-9]{6}" would otherwise accept six digits buried in arbitrary
// input, which is the opposite of what a validation pattern declares.
// An already-anchored pattern is unaffected — ^ and $ match at the
// bounds of the text without the multi-line flag.
//
// A pattern that does not compile fails closed. It is embedder-supplied
// configuration, and the alternative — skipping the check — turns a typo
// in a regex into a silently unvalidated field.
func checkFieldPattern(spec interaction.FieldSpec, value string) error {
	if spec.Pattern == "" {
		return nil
	}
	re, err := regexp.Compile(`\A(?:` + spec.Pattern + `)\z`)
	if err != nil {
		return ErrSubmissionRejected
	}
	if !re.MatchString(value) {
		return ErrSubmissionRejected
	}
	return nil
}

// effectiveMaxLen resolves the byte ceiling for spec: its own MaxLen
// when declared, otherwise the default for its [interaction.FieldKind].
func effectiveMaxLen(spec interaction.FieldSpec) int {
	if spec.MaxLen > 0 {
		return spec.MaxLen
	}
	switch spec.Kind {
	case interaction.FieldText:
		return defaultMaxLenText
	case interaction.FieldPassword:
		return defaultMaxLenPassword
	case interaction.FieldOTPCode:
		return defaultMaxLenOTPCode
	case interaction.FieldEmail:
		return defaultMaxLenEmail
	case interaction.FieldHidden:
		return defaultMaxLenHidden
	default:
		// FieldKind is a closed set, so an unrecognised value is a
		// programming error rather than a forward-compatible extension.
		// Bound it like free-form text instead of leaving it unbounded.
		return defaultMaxLenText
	}
}

// stampActiveInputs records the field list of the prompt being emitted
// so the next submission is validated against the constraints this
// prompt actually declared. The slice is copied because it belongs to
// the [Authenticator] / [Interaction] that returned it, and the
// orchestrator must not observe a later mutation of a list it has
// already published.
func stampActiveInputs(st State, inputs []interaction.FieldSpec) State {
	st.ActiveInputs = append([]interaction.FieldSpec(nil), inputs...)
	return st
}
