package subject

import (
	"context"
	"errors"
)

// UUIDv7 returns the [Generator] that uses the supplied
// [GeneratorInput.InternalUserID] verbatim as the subject claim,
// falling back to [GeneratorInput.Federated.ExternalID] when the user
// authenticated through federation.
//
// The name reflects the v0.x convention where embedders generate
// stable UUIDv7 user identifiers upstream and pass them through as
// the OP-internal subject; the generator itself does not call
// uuid.NewV7() — it has no source of randomness and is purely
// projective. Returning a fresh value per call would break the
// determinism contract documented on [Generator].
//
// UUIDv7 is the v0.x default; it is wired implicitly when neither
// op.WithSubjectGenerator nor op.WithPairwiseSubject is supplied.
//
// # Returned errors
//
// Returns [ErrInputEmpty] when both InternalUserID and Federated are
// zero, and [ErrInputBothSet] when both are populated. The library
// renders both as a server-side configuration error: the issuance
// pipeline is expected to populate exactly one of the two fields
// before invoking the generator.
//
//nolint:ireturn // sealed-sum interface return is the contract; the projective generator carries no state.
func UUIDv7() Generator {
	return uuidv7Generator{}
}

// uuidv7Generator implements [Generator] for the passthrough
// strategy. It carries no state so a single value can be shared
// across every Provider; the library does not allocate per request.
type uuidv7Generator struct{}

func (uuidv7Generator) Generate(_ context.Context, in GeneratorInput) (Subject, error) {
	switch {
	case in.InternalUserID != "" && !in.Federated.IsZero():
		return "", ErrInputBothSet
	case in.InternalUserID != "":
		return Subject(in.InternalUserID), nil
	case !in.Federated.IsZero():
		return Subject(in.Federated.ExternalID), nil
	default:
		return "", ErrInputEmpty
	}
}

// ErrInputEmpty signals that a [GeneratorInput] carried neither an
// InternalUserID nor a Federated identifier. The op package wraps the
// sentinel into op.ErrSubjectInputEmpty for the public catalog.
var ErrInputEmpty = errors.New("subject: input has no InternalUserID and no Federated identifier")

// ErrInputBothSet signals that a [GeneratorInput] carried both an
// InternalUserID and a Federated identifier; the contract is
// "exactly one". The op package wraps the sentinel into a server-side
// configuration error for the public catalog.
var ErrInputBothSet = errors.New("subject: InternalUserID and Federated are mutually exclusive")
