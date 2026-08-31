package subject

import (
	"context"
	"errors"
)

// UUIDv7 returns the [Generator] that uses the supplied
// [GeneratorInput.InternalUserID] verbatim as the subject claim.
//
// The name reflects the convention it serves: embedders generate
// stable UUIDv7 user identifiers upstream and pass them through as
// the OP-internal subject. The generator itself does not call
// uuid.NewV7() — it has no source of randomness and is purely
// projective. Returning a fresh value per call would break the
// determinism contract documented on [Generator].
//
// UUIDv7 is the default; it is wired implicitly when neither
// op.WithSubjectGenerator nor op.WithPairwiseSubject is supplied.
//
// # Returned errors
//
// Returns [ErrInputEmpty] when InternalUserID is empty. The library
// renders it as a server-side configuration error: the issuance
// pipeline is expected to populate the field before invoking the
// generator.
func UUIDv7() Generator { //nolint:ireturn,nolintlint // sealed-sum interface return is the contract; the projective generator carries no state.
	return uuidv7Generator{}
}

// uuidv7Generator implements [Generator] for the passthrough
// strategy. It carries no state so a single value can be shared
// across every Provider; the library does not allocate per request.
type uuidv7Generator struct{}

func (uuidv7Generator) Generate(_ context.Context, in GeneratorInput) (Subject, error) {
	if in.InternalUserID == "" {
		return "", ErrInputEmpty
	}
	return Subject(in.InternalUserID), nil
}

// ErrInputEmpty signals that a [GeneratorInput] carried no
// InternalUserID. The op package bridges the sentinel onto
// op.ErrSubjectInputEmpty for the public catalog: an error surfaced by
// the issuance path or by op.Provider.SubjectGenerator matches both
// values under errors.Is.
var ErrInputEmpty = errors.New("subject: input has no InternalUserID")
