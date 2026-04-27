package backchannel

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// EventID is the URI registered by OpenID Connect Back-Channel Logout
// 1.0 §2.4 as the sole member of the Logout Token's `events` claim.
// RPs key on this exact string to recognise a back-channel logout
// notification.
const EventID = "http://schemas.openid.net/event/backchannel-logout"

// TokenType is the JWT `typ` header the spec mandates (§2.4). RPs are
// permitted to reject any token whose typ is not "logout+jwt", which
// distinguishes a logout token from an id_token at signature-
// verification time.
//
//nolint:gosec // G101 false positive: this is a JWT typ header, not a credential.
const TokenType = "logout+jwt"

// idLength is the entropy in bytes for the JWT identifier (jti). 16
// random bytes (128 bits) is well above the spec's "unique" threshold
// and matches the [internal/sessions.IDLength] sizing for OP-issued
// identifiers.
const idLength = 16

// SigningKey carries the ES256 signing material used to mint Logout
// Tokens. The struct mirrors [internal/tokens.SigningKey]; the
// duplication keeps the back-channel package free of the larger
// id_token / access_token transitive deps.
type SigningKey struct {
	// KeyID becomes the JWS "kid" header. RPs use it to pick the
	// public key when their JWKS cache holds multiple OP keys.
	KeyID string

	// Signer is the private key. The package only signs with ES256;
	// non-ECDSA keys fail at signer construction.
	Signer crypto.Signer
}

// LogoutClaims is the OpenID Connect Back-Channel Logout 1.0 §2.4
// claim set. The struct intentionally exposes only the spec-defined
// fields; the package refuses to mint tokens that carry custom
// claims because RPs that strictly validate logout tokens will reject
// anything they do not recognise.
type LogoutClaims struct {
	// Issuer is the OP's canonical issuer URL. Required.
	Issuer string

	// Audience is the client_id of the RP that registered the
	// backchannel_logout_uri. Required; the spec disallows multi-aud
	// logout tokens because a logout token is sent to one RP at a
	// time.
	Audience string

	// IssuedAt is the seconds-since-epoch the OP minted the token.
	// Required.
	IssuedAt int64

	// ExpiresAt is the seconds-since-epoch the token stops being
	// honoured. The spec recommends a short window (a couple of
	// minutes); the orchestrator picks the value.
	ExpiresAt int64

	// Subject identifies the end-user whose session is ending.
	// Either Subject or SessionID (or both) MUST be populated; the
	// signer rejects an empty pair.
	Subject string

	// SessionID is the OP's session identifier. The OP emits it
	// whenever the client registered backchannel_logout_session_required
	// or whenever the active session has a stable id (always the case
	// in this library). RPs identify their local session by sub, sid,
	// or both.
	SessionID string

	// JTI is the unique JWT identifier. The signer fills it in when
	// empty; callers normally leave it zero so the random source is
	// consistent across mint sites.
	JTI string
}

// SignLogoutToken serialises claims as an ES256-signed compact JWS
// with header typ="logout+jwt". The function rejects the token shapes
// the spec forbids:
//
//   - no Subject AND no SessionID (§2.4 requires at least one);
//   - empty Issuer or Audience (the RP cannot validate either way);
//   - non-positive IssuedAt or ExpiresAt (the OP's clock is required).
//
// Errors carry a wrapped sentinel so callers can branch cleanly; on
// success the function returns the compact-serialised JWS string.
func SignLogoutToken(key SigningKey, claims LogoutClaims) (string, error) {
	if key.Signer == nil {
		return "", errors.New("backchannel: SigningKey has nil Signer")
	}
	if claims.Issuer == "" {
		return "", errors.New("backchannel: claims.Issuer is empty")
	}
	if claims.Audience == "" {
		return "", errors.New("backchannel: claims.Audience is empty")
	}
	if claims.IssuedAt <= 0 || claims.ExpiresAt <= 0 {
		return "", errors.New("backchannel: claims.IssuedAt and ExpiresAt are required")
	}
	if claims.ExpiresAt <= claims.IssuedAt {
		return "", errors.New("backchannel: claims.ExpiresAt must be after IssuedAt")
	}
	if claims.Subject == "" && claims.SessionID == "" {
		return "", errors.New("backchannel: at least one of claims.Subject or claims.SessionID is required")
	}
	jti := claims.JTI
	if jti == "" {
		var err error
		jti, err = randomJTI()
		if err != nil {
			return "", err
		}
	}
	signer, err := newSigner(key)
	if err != nil {
		return "", err
	}
	payload := map[string]any{
		"iss": claims.Issuer,
		"aud": claims.Audience,
		"iat": claims.IssuedAt,
		"exp": claims.ExpiresAt,
		"jti": jti,
		"events": map[string]any{
			EventID: map[string]any{},
		},
	}
	if claims.Subject != "" {
		payload["sub"] = claims.Subject
	}
	if claims.SessionID != "" {
		payload["sid"] = claims.SessionID
	}
	out, err := jwt.Signed(signer).Claims(payload).Serialize()
	if err != nil {
		return "", fmt.Errorf("backchannel: serialise logout token: %w", err)
	}
	return out, nil
}

// newSigner builds the [josev4.Signer] used by [SignLogoutToken]. The
// header carries typ="logout+jwt" so a permissive RP that accepts both
// id_token and logout_token shapes still routes the JWS through the
// correct verification path. The kid is set to key.KeyID so a key
// rotation that retires old material does not break in-flight RP
// verification.
func newSigner(key SigningKey) (josev4.Signer, error) { //nolint:ireturn // wraps third-party josev4.Signer
	sk := josev4.SigningKey{
		Algorithm: josev4.ES256,
		Key: josev4.JSONWebKey{
			Key:       key.Signer,
			KeyID:     key.KeyID,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		},
	}
	opts := (&josev4.SignerOptions{}).WithType(TokenType)
	signer, err := josev4.NewSigner(sk, opts)
	if err != nil {
		return nil, fmt.Errorf("backchannel: build signer: %w", err)
	}
	return signer, nil
}

// randomJTI returns a base64url-encoded random identifier suitable
// for the JWT `jti` claim. The entropy source is crypto/rand; a
// failure is propagated rather than retried because a non-functional
// RNG is a fatal OP condition.
func randomJTI() (string, error) {
	buf := make([]byte, idLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("backchannel: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
