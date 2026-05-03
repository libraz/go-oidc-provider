package op

// WithSubjectGenerator registers the [SubjectGenerator] the OP
// consults to compute the "sub" claim of issued ID tokens and JWT
// access tokens. The library ships two reference generators in the
// [github.com/libraz/go-oidc-provider/op/subject] sub-package:
// [subject.UUIDv7] (the v0.x default; passes InternalUserID through
// verbatim) and [subject.Pairwise] (OIDC Core 1.0 §8.1).
//
// Embedders running the pairwise strategy SHOULD prefer
// [WithPairwiseSubject] over composing [subject.Pairwise] manually:
// the helper enforces the salt length requirement and threads the
// salt onto the config so the dynamic-registration mount accepts
// "subject_type": "pairwise" on inbound RFC 7591 metadata. Calling
// WithSubjectGenerator with a [subject.Pairwise] value bypasses
// those flags and is rejected at construction time.
//
// At most one of [WithSubjectGenerator] and [WithPairwiseSubject]
// may be supplied per construction; the second invocation fails with
// a configuration error.
//
// Stable since v0.9.1.
func WithSubjectGenerator(g SubjectGenerator) Option {
	return optionFunc(func(c *config) error {
		if g == nil {
			return ErrSubjectGeneratorRequired
		}
		if c.subjectGenerator != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithSubjectGenerator conflicts with prior " + c.subjectGeneratorSource,
			}
		}
		c.subjectGenerator = g
		c.subjectGeneratorSource = "WithSubjectGenerator"
		return nil
	})
}

// WithPairwiseSubject enables the OIDC Core 1.0 §8.1 pairwise
// subject strategy. The supplied salt is hashed together with the
// requesting client's sector_identifier_uri host (or its single
// registered redirect_uri host, per OIDC Core 1.0 §5) and the
// OP-internal user identifier to derive a sub value that varies per
// sector but is deterministic for a given (sector, user) pair.
//
// # Salt requirements
//
// The salt MUST be at least 32 bytes / 256 bits. Embedders SHOULD
// supply the salt from a key-management system (KMS, HashiCorp Vault,
// AWS Secrets Manager); a salt baked into the source tree or a
// .env file is treated as low-trust by SOC tooling. Re-using the
// same salt across deployments is intentional — pairwise sub values
// are deterministic across processes that share the salt — but
// rotating the salt invalidates every previously-issued sub. The
// library does not support migration between salts and refuses to
// boot when grants exist that were issued under a different salt
// (enforced by the construction-time subject-mode immutability gate).
//
// # Migration semantics
//
// Switching from "public" subjects to pairwise (or vice versa) on a
// non-empty grant store is not supported. The library detects the
// transition at construction time and fails [New] with a clear
// configuration error so the operator can take the migration off
// the boot path before subjects start drifting in production.
//
// # Per-client opt-in
//
// Enabling the option does NOT force every client to receive
// pairwise subjects. Clients select the strategy through the
// "subject_type" field of their RFC 7591 dynamic-registration
// payload (or the equivalent statically-provisioned [store.Client]
// field). Without [WithPairwiseSubject] the dynamic-registration
// mount rejects "subject_type": "pairwise" with invalid_client_metadata
// per OIDC Core §2; with the option enabled it accepts pairwise
// requests and stores the choice on the client record.
//
// # Sector resolution
//
// Pairwise computation requires a stable sector identifier. The
// library prefers the client's sector_identifier_uri (fetched and
// validated against the listed redirect_uri set per OIDC Core §5)
// and falls back to the host of the single registered redirect_uri
// when the URI is empty. Clients that register more than one
// redirect host without a sector_identifier_uri produce an
// unresolvable sector and the issuance fails with a server error;
// operators MUST require sector_identifier_uri in that case.
//
// At most one of [WithPairwiseSubject] and [WithSubjectGenerator]
// may be supplied; the second invocation fails with a configuration
// error.
//
// Stable since v0.9.1.
func WithPairwiseSubject(salt []byte) Option {
	return optionFunc(func(c *config) error {
		if len(salt) < 32 {
			return ErrPairwiseSaltTooShort
		}
		if c.subjectGenerator != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithPairwiseSubject conflicts with prior " + c.subjectGeneratorSource,
			}
		}
		stored := make([]byte, len(salt))
		copy(stored, salt)
		c.pairwiseSalt = stored
		c.subjectGenerator = newPairwiseGeneratorFromSalt(stored)
		c.subjectGeneratorSource = "WithPairwiseSubject"
		return nil
	})
}

// effectiveSubjectGenerator returns the [SubjectGenerator] the
// issuance pipeline runs against. The value is the embedder-supplied
// generator when one of [WithSubjectGenerator] / [WithPairwiseSubject]
// was invoked, and the package-default UUIDv7 passthrough otherwise.
// The function exists so the wiring layer reads a single source of
// truth instead of branching on two config fields at every call site.
func (c *config) effectiveSubjectGenerator() SubjectGenerator { //nolint:ireturn,nolintlint // sealed-sum interface return is the contract.
	if c.subjectGenerator != nil {
		return c.subjectGenerator
	}
	return defaultSubjectGenerator()
}

// pairwiseEnabled reports whether [WithPairwiseSubject] was invoked.
// The dynamic-registration mount consults the value to decide whether
// "subject_type": "pairwise" is acceptable on inbound RFC 7591
// metadata; it is intentionally distinct from
// [config.subjectGenerator] != nil so an embedder who plumbs a custom
// non-pairwise generator through [WithSubjectGenerator] does not
// accidentally widen DCR acceptance.
func (c *config) pairwiseEnabled() bool {
	return c.pairwiseSalt != nil
}
