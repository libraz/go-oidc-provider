package op

import (
	"strconv"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

// SupportedEncryptionAlgs returns the closed v0.9.1 list of JWE `alg`
// values the OP can negotiate. The list is the union of every
// shipping alg across the five encryption targets (request_object,
// id_token, userinfo, JARM, introspection); embedders narrow it
// per-deployment via [WithSupportedEncryptionAlgs].
//
// The slice is freshly allocated on every call so callers cannot
// mutate the package-internal allow-list.
//
// Stable since v1.0.
func SupportedEncryptionAlgs() []string {
	algs := jose.AllowedJWEAlgs()
	out := make([]string, len(algs))
	for i, a := range algs {
		out[i] = a.String()
	}
	return out
}

// SupportedEncryptionEncs returns the closed v0.9.1 list of JWE `enc`
// values the OP can negotiate. As of v0.9.1 the set is `A128GCM` and
// `A256GCM`; symmetric AES-CBC-HS variants and `A192*` are
// intentionally excluded.
//
// Stable since v1.0.
func SupportedEncryptionEncs() []string {
	encs := jose.AllowedJWEEncs()
	out := make([]string, len(encs))
	for i, e := range encs {
		out[i] = e.String()
	}
	return out
}

// MaxKidlessEncryptionTrialKeys is the number of [EncryptionKeyset]
// entries the OP will trial-decrypt against when an inbound ciphertext
// omits `kid`, counted after the live-entry and key-type filters
// described on [WithEncryptionKeyset]. A ciphertext whose filtered
// candidate set is larger is refused.
//
// The bound is what keeps one attacker-supplied kid-less ciphertext
// from amplifying asymmetric decryptions across an arbitrarily large
// keyset, so it is deliberately small. It constrains only kid-less
// ciphertexts: a keyset of any size serves relying parties that send
// `kid`, which every RP the OP publishes a JWKS to is able to do.
//
// The canonical value lives in the JOSE layer; the name is exported
// here so the limit is reachable from the public API an embedder sizing
// a keyset actually reads.
const MaxKidlessEncryptionTrialKeys = jose.MaxKidlessTrialKeys

// WithEncryptionKeyset registers the JWKs the OP uses to decrypt
// inbound JWE — request objects on /authorize and /par, which are the
// only ciphertexts addressed to the OP itself. Outbound JWE (id_token /
// userinfo / JARM / introspection) does NOT use this keyset: those
// responses are encrypted to a key taken from the recipient client's
// JWKS, and work whether or not this option is supplied.
//
// Every entry MUST carry an asymmetric private key — *rsa.PrivateKey
// (>= 2048 bit) or *ecdsa.PrivateKey on P-256 / P-384 / P-521; other
// shapes cause [op.New] to fail at construction time.
//
// RFC 7517 §4.2 forbids the same key serving as both `use=sig` and
// `use=enc`. The library enforces the constraint structurally: the
// signing keyset is supplied through [WithKeyset] and lives in
// [Keyset]; the encryption keyset is supplied here and lives in
// [EncryptionKeyset]. The two slices are validated independently and
// MUST not overlap by kid (a duplicate kid across the two slices
// would be a configuration smell even if the underlying key
// material is distinct).
//
// Multiple keys allow rotation. An inbound ciphertext that names a
// `kid` routes straight to that entry. A ciphertext that omits one
// (RFC 7516 §4.1.6 makes `kid` OPTIONAL) is trial-decrypted in slice
// order against the entries that are still live and whose key type
// matches the protected-header `alg` — an RSA key for RSA-OAEP-256, an
// EC key for the ECDH-ES family. If more than
// [MaxKidlessEncryptionTrialKeys] entries survive that filter the
// ciphertext is refused outright rather than trialled against a prefix,
// because a result that depended on keyset order and size would turn a
// rotation into an intermittent, undiagnosable client error. Deployments
// holding more keys of one family than the cap admits therefore need
// their relying parties to send `kid`; [op.New] warns when the keyset is
// in that shape.
//
// The encryption keyset is OPTIONAL. Embedders who never accept an
// encrypted request object omit it, and the OP runs without inbound
// JWE: discovery omits `request_object_encryption_*_values_supported`
// and a decryption attempt fails with `invalid_request_object`. The
// outbound advertisements and the outbound encryption paths remain
// available.
//
// Stable since v1.0.
func WithEncryptionKeyset(ks EncryptionKeyset) Option {
	return optionFunc(func(c *config) error {
		if len(ks) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithEncryptionKeyset requires a non-empty keyset",
			}
		}
		c.encryptionKeyset = ks
		return nil
	})
}

// WithSupportedEncryptionAlgs narrows the JWE algorithms the OP will
// negotiate, below the v0.9.1 default ([SupportedEncryptionAlgs] /
// [SupportedEncryptionEncs]).
//
// The narrowing is enforced, not merely advertised. It reaches every
// JWE surface at once:
//
//   - the `*_encryption_alg_values_supported` /
//     `*_encryption_enc_values_supported` discovery lists;
//   - inbound decryption — a request object whose protected header
//     names an excluded alg or enc is rejected before any key is
//     touched, exactly as if the algorithm had never shipped;
//   - outbound encryption — a client registered for an excluded pair
//     gets no recipient, so no id_token / userinfo / JARM /
//     introspection response is encrypted with it;
//   - client registration — a dynamic registration or a static seed
//     declaring an excluded pair is rejected.
//
// Embedders cannot extend the allow-list — values outside the v0.9.1
// default are rejected at [op.New]. The option exists for
// deployments that want to mandate a stricter alg/enc subset
// (e.g. ECDH-ES + A256GCM only) without rebuilding the library.
//
// Either argument may be nil; a nil slice means "use the default".
// An empty (non-nil) slice means "no algs / encs at all", which
// disables JWE negotiation outright while still publishing the
// encryption keyset (a deliberate "advertise keys but negotiate
// nothing" posture is unusual but not forbidden).
//
// Stable since v1.0.
func WithSupportedEncryptionAlgs(algs, encs []string) Option {
	return optionFunc(func(c *config) error {
		if err := applyAlgNarrowing(c, algs); err != nil {
			return err
		}
		return applyEncNarrowing(c, encs)
	})
}

// applyAlgNarrowing validates the embedder-supplied alg subset and
// stores it on the config when non-nil. A nil slice leaves the
// default (the closed v0.9.1 allow-list) untouched; an empty
// non-nil slice records "permit no algs".
func applyAlgNarrowing(c *config, algs []string) error {
	if algs == nil {
		return nil
	}
	for _, a := range algs {
		if _, ok := jose.ParseJWEAlg(a); !ok {
			return &Error{
				Code: codeConfiguration,
				Description: "WithSupportedEncryptionAlgs received alg outside the v0.9.1 allow-list: " +
					a,
			}
		}
	}
	c.encryptionAlgsAllowed = append([]string(nil), algs...)
	c.encryptionAlgsAllowedSet = true
	return nil
}

// applyEncNarrowing mirrors [applyAlgNarrowing] for the JWE
// content-encryption half.
func applyEncNarrowing(c *config, encs []string) error {
	if encs == nil {
		return nil
	}
	for _, e := range encs {
		if _, ok := jose.ParseJWEEnc(e); !ok {
			return &Error{
				Code: codeConfiguration,
				Description: "WithSupportedEncryptionAlgs received enc outside the v0.9.1 allow-list: " +
					e,
			}
		}
	}
	c.encryptionEncsAllowed = append([]string(nil), encs...)
	c.encryptionEncsAllowedSet = true
	return nil
}

// effectiveEncryptionAlgs returns the alg slice every JWE surface
// works from: the discovery advertisement, the inbound decryption
// gate, the outbound recipient selection, and the client-registration
// validator. The embedder-supplied narrowing wins if it was explicitly
// set; otherwise the closed v0.9.1 default applies.
//
// The result does not depend on [WithEncryptionKeyset]. That keyset is
// what the OP decrypts *with*; the algorithms it can negotiate are a
// separate question, and outbound encryption answers it against the
// relying party's key rather than the OP's own.
func (c *config) effectiveEncryptionAlgs() []string {
	if c.encryptionAlgsAllowedSet {
		return append([]string(nil), c.encryptionAlgsAllowed...)
	}
	return SupportedEncryptionAlgs()
}

// effectiveEncryptionEncs mirrors [effectiveEncryptionAlgs] for the
// content-encryption half.
func (c *config) effectiveEncryptionEncs() []string {
	if c.encryptionEncsAllowedSet {
		return append([]string(nil), c.encryptionEncsAllowed...)
	}
	return SupportedEncryptionEncs()
}

// encryptionInboundEnabled reports whether the OP holds a decryption
// keyset, i.e. whether it can accept an encrypted request object. The
// discovery builder uses it to gate the
// `request_object_encryption_*_values_supported` arrays, which are the
// only ones that describe an inbound capability.
func (c *config) encryptionInboundEnabled() bool {
	return len(c.encryptionKeyset) > 0
}

// inboundEncryptionAlgs narrows [config.effectiveEncryptionAlgs] to the
// algs some entry of [WithEncryptionKeyset] can actually decrypt with.
// It answers only the `request_object_encryption_alg_values_supported`
// advertisement; every other encryption family negotiates against the
// relying party's key and is unaffected by which keys the OP itself
// holds.
//
// An encrypted request object is addressed to the OP, so an advertised
// alg the OP has no key family for is an offer no RP can take up: it
// selects a recipient absent from the OP's JWKS, and the request object
// it constructs anyway is refused as invalid_request_object with
// nothing in the response naming the cause. The membership test is
// [jose.KeyMatchesJWEAlg], the same predicate the decrypt path applies,
// so the advertisement cannot drift from what decryption accepts.
//
// Retirement deadlines are deliberately not consulted. The discovery
// document is built once at construction while an entry can retire at
// any point afterwards, so gating on NotAfter here would only freeze
// whatever the clock happened to read during [op.New]; the runtime
// gates live in [keys.EncryptionSet].
func (c *config) inboundEncryptionAlgs() []string {
	if len(c.encryptionKeyset) == 0 {
		return nil
	}
	advertised := c.effectiveEncryptionAlgs()
	out := make([]string, 0, len(advertised))
	for _, raw := range advertised {
		alg, ok := jose.ParseJWEAlg(raw)
		if !ok {
			continue
		}
		for _, k := range c.encryptionKeyset {
			if jose.KeyMatchesJWEAlg(k.PrivateKey, alg) {
				out = append(out, raw)
				break
			}
		}
	}
	return out
}

// jwePolicy converts the embedder's narrowing into the value every JWE
// surface enforces. A half that was never narrowed stays nil, which
// [jose.JWEPolicy] reads as "the library allow-list, unmodified"; a
// narrowed half becomes a non-nil slice, so an explicitly empty
// narrowing permits nothing rather than collapsing back to the default.
//
// Values are re-parsed rather than cast: the option layer already
// rejected anything outside the allow-list, so a parse failure here
// would mean the two gates had drifted, and dropping the value is the
// fail-closed answer.
func (c *config) jwePolicy() jose.JWEPolicy {
	var p jose.JWEPolicy
	if c.encryptionAlgsAllowedSet {
		p.Algs = make([]jose.JWEAlg, 0, len(c.encryptionAlgsAllowed))
		for _, raw := range c.encryptionAlgsAllowed {
			if alg, ok := jose.ParseJWEAlg(raw); ok {
				p.Algs = append(p.Algs, alg)
			}
		}
	}
	if c.encryptionEncsAllowedSet {
		p.Encs = make([]jose.JWEEnc, 0, len(c.encryptionEncsAllowed))
		for _, raw := range c.encryptionEncsAllowed {
			if enc, ok := jose.ParseJWEEnc(raw); ok {
				p.Encs = append(p.Encs, enc)
			}
		}
	}
	return p
}

// warnEncryptionKidlessTrialCap reports a keyset holding more keys of
// one JWE family than [MaxKidlessEncryptionTrialKeys] admits. Every
// kid-less ciphertext addressed to that family is refused there, so a
// deployment that staged a long HSM rotation would see every kid-less
// encrypted request object fail as invalid_request_object with nothing
// in the response, the logs, or the option surface naming the cap as
// the cause.
//
// Reported rather than rejected because the shape is legitimate: an OP
// whose relying parties all send `kid` — which is every RP that reads
// the OP's JWKS — runs on such a keyset with no failure at all. The cap
// only decides what happens when `kid` is absent, so refusing to
// construct would break working deployments to prevent a problem they
// do not have.
//
// The check runs on the configured slice rather than on the built
// [keys.EncryptionSet] and so ignores NotAfter: a deadline that has not
// been reached yet still leaves the entry live, and one that has is a
// key the operator is about to remove anyway. Counting every entry
// makes the warning depend on the configuration rather than on the
// instant [op.New] happened to run.
func (c *config) warnEncryptionKidlessTrialCap() {
	if len(c.encryptionKeyset) == 0 {
		return
	}
	perFamily := map[string]int{}
	for _, k := range c.encryptionKeyset {
		for _, alg := range jose.AllowedJWEAlgs() {
			if jose.KeyMatchesJWEAlg(k.PrivateKey, alg) {
				perFamily[familyLabel(alg)]++
				break
			}
		}
	}
	for _, family := range []string{"RSA", "EC"} {
		count := perFamily[family]
		if count <= MaxKidlessEncryptionTrialKeys {
			continue
		}
		c.logger.Warn(
			"WithEncryptionKeyset holds "+strconv.Itoa(count)+" "+family+" keys, above the "+
				strconv.Itoa(MaxKidlessEncryptionTrialKeys)+"-key kid-less trial cap, so every "+
				"encrypted request object whose protected header omits kid is refused as "+
				"invalid_request_object; require relying parties to send kid, or hold fewer "+
				"keys of this family",
			"option", "WithEncryptionKeyset",
			"family", family,
			"keys", count,
			"cap", MaxKidlessEncryptionTrialKeys,
		)
	}
}

// familyLabel names the key family a JWE alg is served by, for the
// operator-facing warning [warnEncryptionKidlessTrialCap] emits. The
// trial cap applies per family because [jose.Decrypt] filters candidates
// by key type before trialling any of them.
func familyLabel(alg jose.JWEAlg) string {
	if alg == jose.JWEAlgRSAOAEP256 {
		return "RSA"
	}
	return "EC"
}

// validateEncryptionKeyset enforces the kid-disjoint invariant
// between the signing keyset and the encryption keyset (RFC 7517
// §4.2 use=sig / use=enc separation). The two slices are validated
// independently, but a kid collision would mean the same identifier
// appears in JWKS twice (once with use=sig, once with use=enc) which
// is a configuration smell even if the underlying material is
// disjoint.
func (c *config) validateEncryptionKeyset() error {
	if len(c.encryptionKeyset) == 0 {
		return nil
	}
	signingKids := make(map[string]struct{}, len(c.keyset))
	for _, k := range c.keyset {
		signingKids[k.KeyID] = struct{}{}
	}
	for i, k := range c.encryptionKeyset {
		if isNilLike(k.PrivateKey) {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithEncryptionKeyset: entry " + strconv.Itoa(i) + " PrivateKey is nil",
			}
		}
		if _, dup := signingKids[k.KeyID]; dup {
			return &Error{
				Code: codeConfiguration,
				Description: "WithEncryptionKeyset kid " + k.KeyID +
					" collides with a kid in WithKeyset (RFC 7517 §4.2 forbids the same kid for use=sig and use=enc)",
			}
		}
	}
	return nil
}
