package passkey_test

import (
	"errors"
	"testing"
	"time"

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
