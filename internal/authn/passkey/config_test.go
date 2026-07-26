package passkey_test

import (
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
)

func validConfig() passkey.Config {
	return passkey.Config{
		RPID:          "id.example.com",
		RPDisplayName: "Example Identity",
		RPOrigins:     []string{"https://id.example.com"},
	}
}

func TestNew_HappyPath(t *testing.T) {
	t.Parallel()

	v, err := passkey.New(validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v == nil {
		t.Fatal("New returned nil verifier")
	}
	if v.SessionTTL != passkey.DefaultSessionTTLForTest {
		t.Errorf("SessionTTL=%v want %v (default)", v.SessionTTL, passkey.DefaultSessionTTLForTest)
	}
}

func TestNew_RejectsEmptyRPID(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.RPID = ""
	_, err := passkey.New(cfg)
	if !errors.Is(err, passkey.ErrInvalidConfig) {
		t.Fatalf("err=%v want ErrInvalidConfig", err)
	}
}

func TestNew_RejectsEmptyRPDisplayName(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.RPDisplayName = ""
	_, err := passkey.New(cfg)
	if !errors.Is(err, passkey.ErrInvalidConfig) {
		t.Fatalf("err=%v want ErrInvalidConfig", err)
	}
}

func TestNew_RejectsNilRPOrigins(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.RPOrigins = nil
	_, err := passkey.New(cfg)
	if !errors.Is(err, passkey.ErrInvalidConfig) {
		t.Fatalf("err=%v want ErrInvalidConfig", err)
	}
}

func TestNew_RejectsEmptyRPOrigins(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.RPOrigins = []string{}
	_, err := passkey.New(cfg)
	if !errors.Is(err, passkey.ErrInvalidConfig) {
		t.Fatalf("err=%v want ErrInvalidConfig", err)
	}
}

func TestNew_DefaultsSessionTTL(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.SessionTTL = 0
	v, err := passkey.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v.SessionTTL != passkey.DefaultSessionTTLForTest {
		t.Errorf("SessionTTL=%v want %v", v.SessionTTL, passkey.DefaultSessionTTLForTest)
	}
}

func TestNew_HonoursExplicitSessionTTL(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.SessionTTL = 90 * time.Second
	v, err := passkey.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v.SessionTTL != 90*time.Second {
		t.Errorf("SessionTTL=%v want 90s", v.SessionTTL)
	}
}

func TestNew_NegativeSessionTTLFallsBackToDefault(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.SessionTTL = -1 * time.Minute
	v, err := passkey.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v.SessionTTL != passkey.DefaultSessionTTLForTest {
		t.Errorf("SessionTTL=%v want default %v", v.SessionTTL, passkey.DefaultSessionTTLForTest)
	}
}

// TestNew_RejectsOriginNotSuffixOfRPID asserts the L-PASSKEY rule that
// every RPOrigin's host must equal RPID or be a dotted suffix of it.
func TestNew_RejectsOriginNotSuffixOfRPID(t *testing.T) {
	t.Parallel()

	for _, origin := range []string{
		"https://other-example.com",
		"https://badexample.com",
		"https://idxexample.com",
	} {
		t.Run(origin, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig()
			cfg.RPOrigins = []string{origin}
			_, err := passkey.New(cfg)
			if !errors.Is(err, passkey.ErrInvalidConfig) {
				t.Errorf("origin=%s err=%v want ErrInvalidConfig", origin, err)
			}
		})
	}
}

// TestNew_AcceptsOriginEqualOrSuffix asserts the happy paths that the
// L-PASSKEY suffix check must NOT reject.
func TestNew_AcceptsOriginEqualOrSuffix(t *testing.T) {
	t.Parallel()

	for _, origin := range []string{
		"https://id.example.com",
		"https://login.id.example.com",
		"https://id.example.com:8443",
		"http://localhost:3000",
		"http://127.0.0.1:8080",
	} {
		t.Run(origin, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig()
			cfg.RPOrigins = []string{origin}
			if _, err := passkey.New(cfg); err != nil {
				t.Errorf("origin=%s err=%v want nil", origin, err)
			}
		})
	}
}

// TestNew_RejectsHTTPNonLoopback asserts plain http origins outside
// the loopback exception are rejected.
func TestNew_RejectsHTTPNonLoopback(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.RPOrigins = []string{"http://id.example.com"}
	if _, err := passkey.New(cfg); !errors.Is(err, passkey.ErrInvalidConfig) {
		t.Errorf("err=%v want ErrInvalidConfig", err)
	}
}

// TestNew_RejectsMalformedAAGUID asserts the allowlist parser
// surfaces typos at construction time rather than silently widening
// policy.
func TestNew_RejectsMalformedAAGUID(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{
		"not-a-uuid",
		"00000000-0000-0000-0000",
		"FBFC3007-154E-4ECC-8C0B-6E020557D7BD-extra",
	} {
		t.Run(bad, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig()
			cfg.AAGUIDAllowlist = []string{bad}
			if _, err := passkey.New(cfg); !errors.Is(err, passkey.ErrInvalidConfig) {
				t.Errorf("entry=%q err=%v want ErrInvalidConfig", bad, err)
			}
		})
	}
}

// TestAAGUIDAllowed_EmptyAllowlistAcceptsAll asserts the open-policy
// fall-back: an unconfigured allowlist accepts every AAGUID, including
// the all-zero "no AAGUID provided" sentinel real authenticators emit.
func TestAAGUIDAllowed_EmptyAllowlistAcceptsAll(t *testing.T) {
	t.Parallel()

	v, err := passkey.New(validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !v.AAGUIDAllowed(make([]byte, 16)) {
		t.Error("empty allowlist rejected all-zero AAGUID")
	}
	if !v.AAGUIDAllowed([]byte{0xfb, 0xfc, 0x30, 0x07, 0x15, 0x4e, 0x4e, 0xcc, 0x8c, 0x0b, 0x6e, 0x02, 0x05, 0x57, 0xd7, 0xbd}) {
		t.Error("empty allowlist rejected a populated AAGUID")
	}
}

// TestAAGUIDAllowed_ConfiguredAllowlistGates asserts the closed-policy
// branch: a populated allowlist accepts matching AAGUIDs and rejects
// every other.
func TestAAGUIDAllowed_ConfiguredAllowlistGates(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.AAGUIDAllowlist = []string{"FBFC3007-154E-4ECC-8C0B-6E020557D7BD"}
	cfg.AttestationPreference = protocol.PreferDirectAttestation
	v, err := passkey.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	allowed := []byte{0xfb, 0xfc, 0x30, 0x07, 0x15, 0x4e, 0x4e, 0xcc, 0x8c, 0x0b, 0x6e, 0x02, 0x05, 0x57, 0xd7, 0xbd}
	if !v.AAGUIDAllowed(allowed) {
		t.Errorf("AAGUIDAllowed(allowed)=false want true")
	}
	denied := make([]byte, 16)
	if v.AAGUIDAllowed(denied) {
		t.Errorf("AAGUIDAllowed(zero)=true want false")
	}
	// AAGUID values shorter than 16 bytes never match a non-empty
	// allowlist — production authenticators always emit 16 bytes.
	if v.AAGUIDAllowed([]byte{0x01}) {
		t.Errorf("AAGUIDAllowed(short)=true want false")
	}
}

// TestNew_RejectsUnsupportedAttestationPreference asserts the verifier
// rejects "indirect" and "enterprise" — v1.0 supports "none" /
// "direct" only.
func TestNew_RejectsUnsupportedAttestationPreference(t *testing.T) {
	t.Parallel()

	for _, pref := range []string{"indirect", "enterprise", "bogus"} {
		t.Run(pref, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig()
			cfg.AttestationPreference = protocol.ConveyancePreference(pref)
			if _, err := passkey.New(cfg); !errors.Is(err, passkey.ErrInvalidConfig) {
				t.Errorf("pref=%q err=%v want ErrInvalidConfig", pref, err)
			}
		})
	}
}

// TestNew_TimeoutsEnforceFalse asserts H-E6: the library hard-codes
// Timeouts.Enforce=false on both the registration and login configs
// so the upstream library's wall-clock timeout path never executes
// (the OP drives freshness through [timex.Clock] and zeroes Expires
// before invoking the upstream Validate path).
func TestNew_TimeoutsEnforceFalse(t *testing.T) {
	t.Parallel()
	v, err := passkey.New(validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wa := v.WebauthnForTest()
	if wa == nil {
		t.Fatal("WebauthnForTest returned nil")
	}
	cfg := wa.Config
	if cfg == nil {
		t.Fatal("webauthn.WebAuthn.Config is nil")
	}
	if cfg.Timeouts.Registration.Enforce {
		t.Errorf("Timeouts.Registration.Enforce = true, want false (H-E6)")
	}
	if cfg.Timeouts.Login.Enforce {
		t.Errorf("Timeouts.Login.Enforce = true, want false (H-E6)")
	}
	// Timeout values are still populated so the user agent renders
	// a sensible UX; the library just does not enforce them.
	if cfg.Timeouts.Registration.Timeout == 0 {
		t.Error("Timeouts.Registration.Timeout = 0, want non-zero")
	}
	if cfg.Timeouts.Login.Timeout == 0 {
		t.Error("Timeouts.Login.Timeout = 0, want non-zero")
	}
}
