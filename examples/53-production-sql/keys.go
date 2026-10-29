//go:build example

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/libraz/go-oidc-provider/op"
)

// The key directory holds one file per key, and the file name decides the
// key's role. Production mounts it from a secret store (a Kubernetes
// Secret, a Vault agent sink) and reloads with SIGHUP after a rotation.
//
// The retiring cookie key must stay listed after the active one for as
// long as sessions sealed with it are alive: drop it and every signed-in
// user is logged out. Rotation is "mv cookie.key cookie-retiring.key",
// write a new cookie.key, SIGHUP. Signing keys rotate the same way, and
// signing-retiring.pem stays until the tokens it signed have expired.
const (
	signingKeyFile         = "signing.pem"
	retiringSigningKeyFile = "signing-retiring.pem"
	cookieKeyFile          = "cookie.key"
	retiringCookieKeyFile  = "cookie-retiring.key"
)

// ensureKeys generates a first key set when dir is empty or missing. It
// runs at start-up only: a reload never mints keys, so an emptied
// directory fails the reload instead of logging every user out.
func ensureKeys(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read key directory: %w", err)
	}
	if len(entries) > 0 {
		return nil
	}
	if err := generateKeys(dir); err != nil {
		return fmt.Errorf("generate keys in %s: %w", dir, err)
	}
	return nil
}

// loadKeys reads the key directory. The kid is the RFC 7638 thumbprint
// of the key, so every replica that mounts the same file publishes the
// same kid.
func loadKeys(dir string) (op.Keyset, [][]byte, error) {
	keyset, err := op.LoadKeyset(existing(dir, signingKeyFile, retiringSigningKeyFile)...)
	if err != nil {
		return nil, nil, err
	}
	cookieKeys, err := op.LoadSymmetricKeys(existing(dir, cookieKeyFile, retiringCookieKeyFile)...)
	if err != nil {
		return nil, nil, err
	}
	return keyset, cookieKeys, nil
}

// existing returns the paths of the named files present in dir, in the
// order given: active first, retiring after.
func existing(dir string, names ...string) []string {
	paths := make([]string, 0, len(names))
	for _, name := range names {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			paths = append(paths, path)
		}
	}
	return paths
}

// generateKeys writes a P-256 PKCS#8 signing key and two 32-byte cookie
// keys as hex. On a first boot the "retiring" cookie key has nothing to
// retire; it is there to show the slot a rotation fills. The same
// files can be made by hand with "openssl genpkey -algorithm EC
// -pkeyopt ec_paramgen_curve:P-256" and "openssl rand -hex 32".
func generateKeys(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	if err := writeSecret(filepath.Join(dir, signingKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return err
	}
	for _, name := range []string{cookieKeyFile, retiringCookieKeyFile} {
		if err := writeSecret(filepath.Join(dir, name), []byte(hex.EncodeToString(randomBytes(32))+"\n")); err != nil {
			return err
		}
	}
	log.Printf("generated a signing key and two cookie keys in %s", dir)
	return nil
}

// writeSecret creates path readable by the owner only and never
// overwrites an existing key.
func writeSecret(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error.
	return b
}
