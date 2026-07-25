//go:build example

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/op"
)

// config is everything the process reads from its environment, resolved
// once at startup so no handler reaches for os.Getenv later.
type config struct {
	Issuer   string
	OPAddr   string
	RPAddr   string
	RPBase   string
	ClientID string

	RedirectURI string
	MySQLDSN    string
	RedisDSN    string

	// Insecure relaxes the checks that assume TLS: it admits the textual
	// "localhost" host and lets the Redis adapter speak plaintext. It is
	// on for the loopback demo and off everywhere else.
	Insecure bool

	StartupTimeout time.Duration

	// Keyset, CookieKey and MFAKey are generated fresh at every start.
	// Restarting invalidates every issued token, session, and sealed TOTP
	// secret, which is correct for a demonstration and wrong for anything
	// else: a deployment loads this material from a secret manager.
	Keyset    op.Keyset
	CookieKey []byte
	MFAKey    []byte
}

func loadConfig() (config, error) {
	cfg := config{
		OPAddr:         env("OP_ADDR", "0.0.0.0:8080"),
		RPAddr:         env("RP_ADDR", "0.0.0.0:9090"),
		ClientID:       env("CLIENT_ID", "sample-rp"),
		StartupTimeout: 60 * time.Second,
	}
	cfg.Issuer = env("ISSUER", "http://127.0.0.1:8080")
	cfg.RPBase = env("RP_BASE", "http://127.0.0.1:9090")
	cfg.RedirectURI = cfg.RPBase + "/callback"
	cfg.Insecure = !strings.HasPrefix(cfg.Issuer, "https://")

	cfg.MySQLDSN = env("MYSQL_DSN", mysqlDSNFromParts())
	cfg.RedisDSN = env("REDIS_DSN", "redis://127.0.0.1:6379/0")

	keys, err := generateKeys()
	if err != nil {
		return config{}, err
	}
	cfg.Keyset, cfg.CookieKey, cfg.MFAKey = keys.set, keys.cookie, keys.mfa
	return cfg, nil
}

type startupKeys struct {
	set    op.Keyset
	cookie []byte
	mfa    []byte
}

// generateKeys mints the signing key and the two symmetric keys. The
// signing key is ECDSA P-256 because the OP signs with ES256 and only
// ES256; any other curve is rejected at construction.
func generateKeys() (startupKeys, error) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return startupKeys{}, fmt.Errorf("generate signing key: %w", err)
	}
	cookie := make([]byte, 32)
	if _, err := rand.Read(cookie); err != nil {
		return startupKeys{}, fmt.Errorf("generate cookie key: %w", err)
	}
	mfa := make([]byte, 32)
	if _, err := rand.Read(mfa); err != nil {
		return startupKeys{}, fmt.Errorf("generate mfa key: %w", err)
	}
	return startupKeys{
		set:    op.Keyset{{KeyID: "sample-1", Signer: signer}},
		cookie: cookie,
		mfa:    mfa,
	}, nil
}

// mysqlDSNFromParts assembles a DSN from the individual variables the
// compose file sets, so a developer can override one piece without
// restating the whole string.
func mysqlDSNFromParts() string {
	return fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true&charset=utf8mb4&loc=UTC",
		env("MYSQL_USER", "sample"),
		env("MYSQL_PASS", "sample"),
		env("MYSQL_HOST", "127.0.0.1:3306"),
		env("MYSQL_DB", "sample"),
	)
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
