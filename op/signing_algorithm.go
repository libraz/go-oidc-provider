package op

// SigningAlgorithm is the JWS algorithm the OP signs every token it issues
// with: ID Tokens, JWT access tokens, signed UserInfo, JARM responses,
// logout tokens, JWT introspection responses, ID-JAGs and SSF SETs. An OP
// issues with exactly one algorithm, so there is no per-client choice and
// no negotiation; client metadata naming a different algorithm is refused
// at registration.
//
// Stable since v1.5.
type SigningAlgorithm string

const (
	// AlgES256 is ECDSA on P-256 with SHA-256 (RFC 7518 §3.4). It is the
	// algorithm an OP issues with when [WithSigningAlgorithm] is not
	// supplied, and the active [Keyset] entry must be an ECDSA P-256 key.
	//
	// Stable since v1.5.
	AlgES256 SigningAlgorithm = "ES256"

	// AlgRS256 is RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 §3.3), the
	// algorithm OpenID Connect Core §15.1 makes mandatory to implement.
	// The active [Keyset] entry must be an RSA key of 2048 bits or more.
	// No FAPI profile permits it, so combining it with one fails [New].
	//
	// Stable since v1.5.
	AlgRS256 SigningAlgorithm = "RS256"
)

// WithSigningAlgorithm selects the algorithm the OP issues every JWS with.
// Without the option the OP issues ES256. The value must be [AlgES256] or
// [AlgRS256] exactly; anything else fails [New].
//
// The choice fixes what the active [Keyset] entry must be, and is what
// discovery advertises in the id_token, userinfo, authorization and
// introspection *_signing_alg_values_supported lists and what dynamic
// registration fills in when a client omits id_token_signed_response_alg.
// Keyset entries behind the active one may be of the other algorithm's
// key type while an OP moves between algorithms, provided each sets
// [SigningKey.NotAfter]: the OP keeps verifying the tokens they signed
// until that deadline but never signs with them.
//
// [AlgRS256] is refused under [profile.FAPI2Baseline],
// [profile.FAPI2MessageSigning] and [profile.FAPICIBA], because FAPI 2.0
// Security Profile §5.4.1 allows only PS256, ES256 and EdDSA.
//
// Stable since v1.5.
func WithSigningAlgorithm(alg SigningAlgorithm) Option {
	return optionFunc(func(c *config) error {
		if err := c.claimOnce("WithSigningAlgorithm"); err != nil {
			return err
		}
		if alg != AlgES256 && alg != AlgRS256 {
			return newConfigurationError("WithSigningAlgorithm: unsupported algorithm \""+string(alg)+
				"\"; use AlgES256 or AlgRS256", nil)
		}
		c.signingAlg = alg
		return nil
	})
}

// issuingAlg returns the algorithm the OP issues with, resolving the
// unset value to [AlgES256].
func (c *config) issuingAlg() SigningAlgorithm {
	if c.signingAlg == "" {
		return AlgES256
	}
	return c.signingAlg
}
