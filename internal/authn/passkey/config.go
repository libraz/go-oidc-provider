package passkey

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/libraz/go-oidc-provider/internal/timex"
)

// defaultSessionTTL is the lifetime stamped on every [Session] when the
// caller does not override it via [Config.SessionTTL]. Five minutes
// matches the underlying library default and is long enough that a
// human-paced registration flow (read prompt, touch authenticator,
// confirm) finishes comfortably while keeping the replay window narrow.
const defaultSessionTTL = 5 * time.Minute

// ErrInvalidConfig is returned by [New] when the supplied [Config] is
// missing required fields or carries conflicting values. The error is
// intentionally surfaced at startup time so a misconfigured deployment
// fails before the first registration attempt.
var ErrInvalidConfig = errors.New("passkey: invalid configuration")

// Config carries the Relying Party identity bound into every
// registration and assertion ceremony. The struct mirrors the small
// subset of [webauthn.Config] the library actually exposes today;
// fields that v1.0 deliberately fixes (AttestationPreference,
// AuthenticatorSelection, EncodeUserIDAsString) are NOT surfaced. See
// the package godoc for the rationale.
type Config struct {
	// RPID is the Relying Party Identifier — typically the OP's
	// effective domain (for example "id.example.com" but never a URL
	// or port). It is bound into the credential at registration time
	// and matched at assertion time; changing it invalidates every
	// previously registered credential. Required.
	RPID string

	// RPDisplayName is the human-readable label shown by the user
	// agent during the ceremony (for example "Example Identity"). It
	// has no security effect but every spec-compliant authenticator
	// requires it. Required.
	RPDisplayName string

	// RPOrigins is the list of fully-qualified origins permitted to
	// initiate ceremonies (for example "https://id.example.com").
	// Cross-origin iframe flows MAY require additional entries;
	// embedders SHOULD enumerate every public-facing origin they
	// terminate TLS on. Required to be non-empty.
	RPOrigins []string

	// SessionTTL is the absolute lifetime stamped on the [Session]
	// returned from BeginRegistration / BeginLogin. A zero value
	// falls back to [defaultSessionTTL] (five minutes). Embedders
	// MAY shorten the value to tighten the replay window but SHOULD
	// NOT lengthen it past a few minutes: the cookie that ferries the
	// session is encrypted, but a longer TTL widens the window in
	// which a stolen browser could complete a hijacked ceremony.
	SessionTTL time.Duration
}

// Verifier is the package's high-level façade. Construct one via [New]
// and reuse it for the lifetime of the process; the underlying
// [webauthn.WebAuthn] is built once and shared across goroutines.
//
// The zero value is not usable: callers MUST go through [New] so the
// configuration is validated up front.
//
// Verifier is immutable after construction and safe for concurrent use.
type Verifier struct {
	// Clock supplies the wall-clock reading used to stamp Session
	// expiry and to validate that a presented Session has not yet
	// expired. A nil value falls back to [timex.SystemClock]. Tests
	// inject a deterministic [timex.ClockFunc] so the expiry stamp is
	// reproducible.
	Clock timex.Clock

	// SessionTTL is the absolute Session lifetime. It is set from
	// [Config.SessionTTL] in [New]; callers SHOULD treat the field as
	// read-only.
	SessionTTL time.Duration

	// wa is the underlying webauthn instance, built once in [New].
	wa *webauthn.WebAuthn
}

// New constructs a [Verifier] from cfg. It validates the required
// fields, builds the underlying [webauthn.WebAuthn], and wires the
// fixed-policy choices (AttestationPreference = none, defaulted
// AuthenticatorSelection) the package documents.
//
// The function returns [ErrInvalidConfig] (wrapped via [fmt.Errorf]
// with %w) when RPID or RPDisplayName is empty or RPOrigins is empty.
// Validation is intentionally surfaced as a startup error rather than a
// per-request one: an OP that boots without a valid passkey config
// should refuse to start, not silently downgrade to "no passkey".
func New(cfg Config) (*Verifier, error) {
	if cfg.RPID == "" {
		return nil, fmt.Errorf("%w: RPID is required", ErrInvalidConfig)
	}
	if cfg.RPDisplayName == "" {
		return nil, fmt.Errorf("%w: RPDisplayName is required", ErrInvalidConfig)
	}
	if len(cfg.RPOrigins) == 0 {
		return nil, fmt.Errorf("%w: at least one RPOrigin is required", ErrInvalidConfig)
	}
	ttl := cfg.SessionTTL
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}

	waCfg := &webauthn.Config{
		RPID:                  cfg.RPID,
		RPDisplayName:         cfg.RPDisplayName,
		RPOrigins:             append([]string(nil), cfg.RPOrigins...),
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		},
		// EncodeUserIDAsString is left at the library default
		// (false). The user handle round-trips through the JSON as a
		// base64url-encoded string per the W3C WebAuthn convention
		// for BufferSource fields; SPAs decode it through the
		// standard PublicKeyCredential.parseCreationOptionsFromJSON
		// helpers. Setting the flag would skip the encoding and
		// produce a raw UTF-8 string that older browser libraries
		// would mishandle.
		Timeouts: webauthn.TimeoutsConfig{
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    ttl,
				TimeoutUVD: ttl,
			},
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    ttl,
				TimeoutUVD: ttl,
			},
		},
	}

	wa, err := webauthn.New(waCfg)
	if err != nil {
		return nil, fmt.Errorf("%w: build webauthn: %w", ErrInvalidConfig, err)
	}
	return &Verifier{
		SessionTTL: ttl,
		wa:         wa,
	}, nil
}

// clock returns the verifier's [timex.Clock], defaulting to
// [timex.SystemClock] when the field is nil.
func (v *Verifier) clock() timex.Clock {
	if v.Clock == nil {
		return timex.SystemClock
	}
	return v.Clock
}
