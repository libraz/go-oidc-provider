package op

import "github.com/libraz/go-oidc-provider/op/subject"

// Subject is the OP-internal identifier for an authenticated end user.
// It is the value the library writes into the "sub" claim of issued
// ID tokens and access JWTs. A Subject MUST NOT carry upstream
// identifiers verbatim; federated logins go through [FederatedSubject]
// before becoming a Subject.
//
// The canonical type definition lives in
// [github.com/libraz/go-oidc-provider/op/subject.Subject]; this is a
// re-export so user code can stay on the op-package surface while the
// op/subject sub-package owns the [SubjectGenerator] interface
// without an import cycle.
type Subject = subject.Subject

// FederatedSubject is the typed wrapper for an upstream identifier
// returned by an external IdP. It is the only way the library
// accepts an upstream "sub": resolving it to an internal [Subject]
// requires a [store.UserStore] that owns the (Provider, ExternalID)
// → Subject mapping.
//
// The wrapper exists so a string returned by Google or GitHub cannot
// be assigned to a [Subject] by mistake, even with implicit
// conversions. Re-exported from
// [github.com/libraz/go-oidc-provider/op/subject.FederatedSubject].
type FederatedSubject = subject.FederatedSubject

// SubjectGenerator computes the value the OP writes into the "sub"
// claim of issued ID tokens and JWT access tokens for an authenticated
// end-user. Re-exported from
// [github.com/libraz/go-oidc-provider/op/subject.Generator] so user
// code can stay on the op-package surface; see the canonical
// definition for the full contract (determinism, no surprise I/O,
// sector-scoped pairwise output).
type SubjectGenerator = subject.Generator

// SubjectGeneratorInput is the bundle the library hands to a
// [SubjectGenerator] at grant-creation time. Re-exported from
// [github.com/libraz/go-oidc-provider/op/subject.GeneratorInput].
type SubjectGeneratorInput = subject.GeneratorInput

// Identity is the bundle of subject-scoped facts the library needs
// to issue tokens and render UserInfo: the canonical [Subject], the
// authentication context the user satisfied, and the claim values
// keyed by claim name.
//
// Identity is constructed by the user's [interaction.Driver] after a
// successful authentication and consumed by the token endpoint and
// the /userinfo endpoint. It is never stored by the library.
type Identity struct {
	// Subject is the OP-internal "sub" value. It MUST be non-empty.
	Subject Subject

	// AuthenticationContext describes how the user authenticated. It
	// is optional; when set, the library copies AMR and ACR into ID
	// tokens.
	AuthenticationContext AuthContext

	// Claims is the map of claim name to claim value. The map MAY be
	// nil; only requested claims are released to a given client.
	Claims Claims
}

// defaultSubjectGenerator returns the [SubjectGenerator] the library
// installs implicitly when neither [WithSubjectGenerator] nor
// [WithPairwiseSubject] is supplied. It is the v0.x default
// (UUIDv7 passthrough) so embedders that do not opt into pairwise
// keep the historical behaviour where the OP-internal user
// identifier flows through to the "sub" claim verbatim.
func defaultSubjectGenerator() SubjectGenerator { //nolint:ireturn // sealed-sum interface return is the contract.
	return subject.UUIDv7()
}

// newPairwiseGeneratorFromSalt is the option-site bridge that
// constructs the pairwise [SubjectGenerator] from the salt the
// embedder supplied through [WithPairwiseSubject]. The function
// exists so the option keeps the pairwise constructor as an
// implementation detail rather than exposing it on the public
// op-package surface — pairwise selection is the [WithPairwiseSubject]
// call, not a generator handed to [WithSubjectGenerator].
func newPairwiseGeneratorFromSalt(salt []byte) SubjectGenerator { //nolint:ireturn // sealed-sum interface return is the contract.
	return subject.Pairwise(salt)
}

// AuthContext records authentication-method facts that flow into ID
// token claims (RFC 8176 amr, OpenID Connect Core 1.0 §2 acr). It is
// copied verbatim into tokens; ad-hoc fields are not exposed.
type AuthContext struct {
	// AMR is the list of authentication-method reference values per
	// RFC 8176. Order is significant: it MUST reflect the order the
	// user completed the methods.
	AMR []string

	// ACR is the authentication-context-class reference per OpenID
	// Connect Core 1.0 §5.5.1.1. Empty means the OP did not assert
	// one.
	ACR string

	// AuthTime is the wall-clock time at which the user completed
	// authentication, as a Unix timestamp. Zero means unknown; the
	// library omits the auth_time claim in that case.
	AuthTime int64
}
