package jarm

import (
	"errors"
	"fmt"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// DefaultExpiry is the default lifetime applied to a JARM JWT when
// [Signer.Expiry] is unset. The JARM specification §4.1 caps the value
// at 10 minutes; 60 seconds is well within that bound and matches the
// authorization-code TTL the OP issues on the same flow, so the JARM
// envelope and the code it carries become unredeemable together.
const DefaultExpiry = 60 * time.Second

// Payload is the claim bundle [Signer.Sign] serialises into a JARM JWT.
// It carries the success-path code / state pair and the error-path
// triple in the same struct so callers can populate the relevant
// fields and zero the rest.
type Payload struct {
	// Issuer becomes the "iss" claim. It MUST equal the OP's discovery
	// "issuer" value; the verifier on the RP side compares the two.
	Issuer string

	// Audience becomes the "aud" claim. JARM mandates the requesting
	// client_id; the package accepts a plain string and the encoder
	// emits it in single-string form per RFC 7519 §4.1.3.
	Audience string

	// ExpiresAt is the absolute expiry encoded as the "exp" claim. A
	// zero value is rejected by [Signer.Sign]; the caller is expected
	// to obtain the value from a deterministic [timex.Clock].
	ExpiresAt time.Time

	// State becomes the "state" claim. An empty value omits the claim.
	State string

	// Code becomes the "code" claim on the success path. Empty is
	// permitted and signals "this is an error response".
	Code string

	// Error becomes the "error" claim on the error path. Empty is
	// permitted and signals "this is a success response". The OAuth
	// wire codes (invalid_request, invalid_scope, ...) are the only
	// values the caller should populate.
	Error string

	// ErrorDescription becomes the "error_description" claim. Omitted
	// when empty.
	ErrorDescription string

	// ErrorURI becomes the "error_uri" claim. Omitted when empty.
	ErrorURI string
}

// Signer encapsulates the OP's signing key and the issuer the encoded
// JWTs identify. Construct it once at startup with [NewSigner]; the
// value is immutable and safe for concurrent use.
type Signer struct {
	key    tokens.SigningKey
	alg    josev4.SignatureAlgorithm
	issuer string
	clock  timex.Clock
	expiry time.Duration
}

// SignerConfig is the parameter bundle for [NewSigner]. The shape
// mirrors the verifier configs in internal/dpop / internal/mtls so
// embedders see a uniform style across the protocol packages.
type SignerConfig struct {
	// Key is the active OP signing key. Required. The package signs
	// with the same key that mints id_tokens and JWT access tokens.
	Key tokens.SigningKey

	// Issuer is the absolute issuer URL stamped as the "iss" claim.
	// Required.
	Issuer string

	// Clock supplies the wall-clock reading for the "iat" and "nbf"
	// claims on every signed response, and for the "exp" computation
	// inside [Signer.SignDefault]. A nil value falls back to
	// [timex.SystemClock]. The lower-level [Signer.Sign] entry point
	// takes the absolute "exp" from the caller but still stamps
	// iat / nbf from this clock.
	Clock timex.Clock

	// Expiry overrides [DefaultExpiry] for [Signer.SignDefault]. Zero
	// or negative falls back to the default. Values that exceed the
	// JARM specification's 10-minute ceiling are accepted by this
	// package; an embedder that needs spec-compliant capping should
	// clamp before construction.
	Expiry time.Duration
}

// NewSigner builds a [*Signer] from cfg. It returns an error when a
// required field is missing or when the supplied key cannot be mapped
// onto a project-allowed JWS algorithm; the embedder fails fast at
// startup rather than at the first response.
func NewSigner(cfg SignerConfig) (*Signer, error) {
	if cfg.Key.Signer == nil {
		return nil, errors.New("jarm: NewSigner requires Key.Signer")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("jarm: NewSigner requires Issuer")
	}
	alg, err := deriveJWSAlgorithm(cfg.Key)
	if err != nil {
		return nil, err
	}
	clock := cfg.Clock
	if clock == nil {
		clock = timex.SystemClock
	}
	expiry := cfg.Expiry
	if expiry <= 0 {
		expiry = DefaultExpiry
	}
	return &Signer{
		key:    cfg.Key,
		alg:    alg,
		issuer: cfg.Issuer,
		clock:  clock,
		expiry: expiry,
	}, nil
}

// deriveJWSAlgorithm picks the JWS "alg" header for a [tokens.SigningKey]
// based on the public key shape. The library signs with ECDSA P-256
// only, and internal/keys.NewSet rejects every other key shape on
// construction, so a key reaching this function MUST be a P-256 ECDSA
// key. Delegating to [jose.KeyShape] keeps the
// alg/key matrix in one place — the wrapper here surfaces "unknown key
// shape" as a fail-fast [ErrEncode] at [NewSigner] time rather than
// silently returning ES256 for the wrong key, while preserving the
// internal/jose [jose.ErrUnsupportedKeyShape] sentinel for callers that
// want the structural identity. The "alg" returned is the JWS
// SIGNATURE algorithm — JARM does not encrypt the response, so the
// FAPI 2.0 RSA-OAEP key-encryption discussion does not apply here.
func deriveJWSAlgorithm(key tokens.SigningKey) (josev4.SignatureAlgorithm, error) {
	pub := key.Signer.Public()
	alg, _, _, ok := jose.KeyShape(pub)
	if !ok {
		return "", fmt.Errorf("%w: %w: key type %T (the OP signs with ECDSA P-256 only; see internal/keys.NewSet)", ErrEncode, jose.ErrUnsupportedKeyShape, pub)
	}
	if alg != string(josev4.ES256) {
		return "", fmt.Errorf("%w: %w: alg %q is not ES256 (the OP signs with ECDSA P-256 only)", ErrEncode, jose.ErrUnsupportedKeyShape, alg)
	}
	return josev4.ES256, nil
}

// Issuer returns the issuer string this signer stamps onto every JWT.
// Callers use it to decide whether to override [Payload.Issuer] (in
// practice they should not).
func (s *Signer) Issuer() string { return s.issuer }

// Sign serialises p as an ES256-signed compact JWS. The function
// validates that Issuer / Audience / ExpiresAt are set; on the success
// path Code is also required; on the error path Error is required.
//
// The clock decides "iat" and "nbf"; only "exp" comes from the
// caller, which has already computed the absolute expiry the JWT
// carries. Use [Signer.SignDefault] to delegate that computation too
// — a caller that passes an expiry earlier than the injected clock's
// reading produces a JWT whose exp precedes its nbf.
func (s *Signer) Sign(p Payload) (string, error) {
	if err := validatePayload(p); err != nil {
		return "", err
	}
	issuer := p.Issuer
	if issuer == "" {
		issuer = s.issuer
	}
	now := s.clock.Now().UTC()
	// "nbf" is set equal to "iat" so JARM consumers running under
	// FAPI 2.0 Message Signing §5.6 can apply a uniform nbf-or-fail
	// rule. RFC 9101 / draft-ietf-oauth-jwsreq
	// neither mandate nbf on response objects nor forbid it; pinning
	// the value to iat keeps the wire shape compatible with relaxed
	// consumers while satisfying strict ones.
	iat := now.Unix()
	claims := map[string]any{
		"iss": issuer,
		"aud": p.Audience,
		"exp": p.ExpiresAt.UTC().Unix(),
		"iat": iat,
		"nbf": iat,
	}
	if p.State != "" {
		// "state" is carried as a signed claim; the JWS signature already
		// binds it, so no separate s_hash is emitted. JARM / FAPI 2.0
		// Message Signing §5.6 do not define s_hash in the authorization
		// response, and emitting it trips conformance "unexpected
		// parameter" checks.
		claims["state"] = p.State
	}
	if p.Code != "" {
		claims["code"] = p.Code
	}
	if p.Error != "" {
		claims["error"] = p.Error
	}
	if p.ErrorDescription != "" {
		claims["error_description"] = p.ErrorDescription
	}
	if p.ErrorURI != "" {
		claims["error_uri"] = p.ErrorURI
	}
	signer, err := newSigner(s.key, s.alg)
	if err != nil {
		return "", err
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrEncode, err)
	}
	return out, nil
}

// SignDefault is the convenience wrapper that fills in [Payload.Issuer]
// from the signer and [Payload.ExpiresAt] from the configured clock and
// expiry duration. Callers that need a non-default expiry compute it
// themselves and call [Signer.Sign].
func (s *Signer) SignDefault(p Payload) (string, error) {
	if p.Issuer == "" {
		p.Issuer = s.issuer
	}
	if p.ExpiresAt.IsZero() {
		p.ExpiresAt = s.clock.Now().Add(s.expiry)
	}
	return s.Sign(p)
}

// validatePayload returns an error when the payload fails the JARM
// minimum-claim invariants: iss / aud / exp must be set, and at least
// one of code / error must be non-empty.
func validatePayload(p Payload) error {
	if p.Audience == "" {
		return fmt.Errorf("%w: audience required", ErrEncode)
	}
	if p.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: expires_at required", ErrEncode)
	}
	if p.Code == "" && p.Error == "" {
		return fmt.Errorf("%w: either code or error required", ErrEncode)
	}
	if p.Code != "" && p.Error != "" {
		return fmt.Errorf("%w: code and error are mutually exclusive", ErrEncode)
	}
	return nil
}

// newSigner builds the [josev4.Signer] used by [Signer.Sign]. The
// algorithm is supplied by the caller (already derived from the key
// shape at [NewSigner] construction time via [deriveJWSAlgorithm]) so
// runtime never reads a stale ES256 default for an RSA / Ed25519 key.
// The configuration mirrors [tokens.newSigner] so both
// endpoints emit JWTs with identical "kid" / "typ" / "alg" headers;
// the duplication is preferred over importing the unexported helper. The
// returned interface is intentional: josev4.Signer is the third-party
// package's contract for stateful JWS signing.
func newSigner(key tokens.SigningKey, alg josev4.SignatureAlgorithm) (josev4.Signer, error) {
	sk := josev4.SigningKey{
		Algorithm: alg,
		Key: josev4.JSONWebKey{
			Key:       key.Signer,
			KeyID:     key.KeyID,
			Algorithm: string(alg),
			Use:       "sig",
		},
	}
	opts := (&josev4.SignerOptions{}).WithType("JWT")
	signer, err := josev4.NewSigner(sk, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: build signer: %w", ErrEncode, err)
	}
	return signer, nil
}
