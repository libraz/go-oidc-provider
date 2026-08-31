package op

import (
	"context"
	"errors"

	"github.com/libraz/go-oidc-provider/op/subject"
)

// catalogError pairs a public catalog sentinel with the sub-package
// error that produced it. Both branches are reported to [errors.Is] and
// [errors.As]: the sentinel so embedders can match the value the
// catalog documents (and so [IsServerError] finds an [*Error]), the
// cause so code already written against the
// [github.com/libraz/go-oidc-provider/op/subject] sentinels keeps
// matching. The catalog sentinels are compared by pointer identity, so
// a copy carrying the same Code and Description would not do.
type catalogError struct {
	sentinel *Error
	cause    error
}

// Error renders the sentinel followed by the underlying reason, the
// same shape [Error.Error] produces for a wrapped cause.
func (e *catalogError) Error() string {
	if e.cause == nil {
		return e.sentinel.Error()
	}
	return e.sentinel.Error() + ": " + e.cause.Error()
}

// Unwrap exposes both the catalog sentinel and the originating cause.
func (e *catalogError) Unwrap() []error { return []error{e.sentinel, e.cause} }

// bridgeSubjectError translates the failure modes of the built-in
// [SubjectGenerator] implementations onto the public error catalog.
// The subject sub-package cannot build the catalog values itself (op
// imports subject, not the other way round), so every op-side seam that
// surfaces a generator error runs it through this function; without the
// bridge the catalog entries name errors no caller can ever match.
//
// An error the function does not recognise is returned verbatim: a
// generator supplied through [WithSubjectGenerator] owns its own error
// values and the library does not rewrite them.
func bridgeSubjectError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, subject.ErrSectorUnresolved):
		return &catalogError{sentinel: ErrPairwiseSectorUnresolved, cause: err}
	case errors.Is(err, subject.ErrInvalidSectorURL):
		return &catalogError{
			sentinel: &Error{
				Code:        codeServerError,
				Description: "pairwise sector_identifier_uri is not a parseable URL",
			},
			cause: err,
		}
	case errors.Is(err, subject.ErrSaltTooShort):
		return &catalogError{sentinel: ErrPairwiseSaltTooShort, cause: err}
	case errors.Is(err, subject.ErrInputEmpty):
		return &catalogError{sentinel: ErrSubjectInputEmpty, cause: err}
	default:
		return err
	}
}

// bridgedSubjectGenerator decorates a [SubjectGenerator] so its errors
// reach the caller as catalog entries. Only generators the library
// builds itself are decorated — see [config.catalogSubjectGenerator].
type bridgedSubjectGenerator struct {
	inner SubjectGenerator
}

func (g bridgedSubjectGenerator) Generate(ctx context.Context, in SubjectGeneratorInput) (Subject, error) {
	sub, err := g.inner.Generate(ctx, in)
	if err != nil {
		return "", bridgeSubjectError(err)
	}
	return sub, nil
}

// catalogSubjectGenerator returns the effective [SubjectGenerator] with
// the library's own failure modes bridged onto the public catalog. It
// backs [Provider.SubjectGenerator], whose documented use is calling
// Generate from out-of-band tooling: that caller is outside the
// library, so it must see the documented errors.
//
// A generator supplied through [WithSubjectGenerator] is handed back
// verbatim. The value belongs to the embedder — it may carry a concrete
// type they assert on and error values they match themselves — so the
// library neither decorates it nor rewrites what it returns.
func (c *config) catalogSubjectGenerator() SubjectGenerator { //nolint:ireturn,nolintlint // sealed-sum interface return is the contract.
	gen := c.effectiveSubjectGenerator()
	if c.subjectGeneratorSource == "WithSubjectGenerator" {
		return gen
	}
	if isNilLike(gen) {
		return gen
	}
	return bridgedSubjectGenerator{inner: gen}
}
