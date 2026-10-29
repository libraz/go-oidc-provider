package clientauth_test

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/store"
)

type previousState int

const (
	prevAbsent previousState = iota
	prevActive
	prevExpired
	prevHashWithoutExpiry
)

type presentedSecret int

const (
	presentCurrent presentedSecret = iota
	presentPrevious
	presentWrong
)

type secretEncoding int

const (
	encArgon2id secretEncoding = iota
	encHighEntropy
)

// previousSecretFixture is one client with a current and a previous
// secret in a single stored encoding, plus the verifier that reads it.
type previousSecretFixture struct {
	current, previous         string
	currentHash, previousHash string
	verifier                  clientauth.SecretVerifier
}

func newPreviousSecretFixture(t *testing.T, enc secretEncoding) previousSecretFixture {
	t.Helper()
	switch enc {
	case encArgon2id:
		v := smallArgon2id()
		f := previousSecretFixture{current: "current-secret-value", previous: "previous-secret-value", verifier: v}
		var err error
		if f.currentHash, err = v.Hash(f.current); err != nil {
			t.Fatalf("Hash current: %v", err)
		}
		if f.previousHash, err = v.Hash(f.previous); err != nil {
			t.Fatalf("Hash previous: %v", err)
		}
		return f
	case encHighEntropy:
		f := previousSecretFixture{verifier: clientauth.HighEntropy{}}
		var err error
		if f.current, f.currentHash, err = clientauth.NewHighEntropySecret(); err != nil {
			t.Fatalf("NewHighEntropySecret current: %v", err)
		}
		if f.previous, f.previousHash, err = clientauth.NewHighEntropySecret(); err != nil {
			t.Fatalf("NewHighEntropySecret previous: %v", err)
		}
		return f
	default:
		t.Fatalf("unknown encoding %d", enc)
		return previousSecretFixture{}
	}
}

// TestVerifyClient_PreviousSecret covers the method x presented x
// previous_state x encoding space at strength 2. The expired rows put
// the expiry exactly at Now, so the boundary instant itself is pinned as
// outside the window.
func TestVerifyClient_PreviousSecret(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

	type outcome int
	const (
		reject outcome = iota
		acceptCurrent
		acceptPrevious
	)

	rows := []struct {
		name      string
		method    clientauth.Method
		presented presentedSecret
		state     previousState
		enc       secretEncoding
		zeroNow   bool
		want      outcome
	}{
		{"row01", clientauth.MethodSecretBasic, presentWrong, prevExpired, encHighEntropy, false, reject},
		{"row02", clientauth.MethodSecretBasic, presentPrevious, prevHashWithoutExpiry, encArgon2id, false, reject},
		{"row03", clientauth.MethodSecretBasic, presentCurrent, prevActive, encHighEntropy, false, acceptCurrent},
		{"row04", clientauth.MethodSecretPost, presentWrong, prevHashWithoutExpiry, encHighEntropy, false, reject},
		{"row05", clientauth.MethodSecretBasic, presentCurrent, prevAbsent, encArgon2id, false, acceptCurrent},
		{"row06", clientauth.MethodSecretPost, presentPrevious, prevExpired, encArgon2id, false, reject},
		{"row07", clientauth.MethodSecretPost, presentWrong, prevActive, encArgon2id, false, reject},
		{"row08", clientauth.MethodSecretPost, presentWrong, prevAbsent, encHighEntropy, false, reject},
		{"row09", clientauth.MethodSecretPost, presentCurrent, prevAbsent, encHighEntropy, false, acceptCurrent},
		{"row10", clientauth.MethodSecretBasic, presentCurrent, prevExpired, encHighEntropy, false, acceptCurrent},
		{"row11", clientauth.MethodSecretBasic, presentPrevious, prevHashWithoutExpiry, encHighEntropy, false, reject},
		{"row12", clientauth.MethodSecretPost, presentPrevious, prevActive, encHighEntropy, false, acceptPrevious},
		{"row13", clientauth.MethodSecretPost, presentCurrent, prevHashWithoutExpiry, encArgon2id, false, acceptCurrent},
		{"m1", clientauth.MethodSecretBasic, presentPrevious, prevActive, encArgon2id, false, acceptPrevious},
		{"m2", clientauth.MethodSecretBasic, presentPrevious, prevActive, encArgon2id, true, reject},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()

			f := newPreviousSecretFixture(t, row.enc)
			client := &store.Client{
				ID:                      "client-1",
				SecretHash:              f.currentHash,
				TokenEndpointAuthMethod: string(row.method),
			}
			switch row.state {
			case prevAbsent:
			case prevActive:
				client.PreviousSecretHash = f.previousHash
				client.PreviousSecretExpiresAt = now.Add(time.Hour)
			case prevExpired:
				client.PreviousSecretHash = f.previousHash
				client.PreviousSecretExpiresAt = now
			case prevHashWithoutExpiry:
				client.PreviousSecretHash = f.previousHash
			}

			var secret string
			switch row.presented {
			case presentCurrent:
				secret = f.current
			case presentPrevious:
				secret = f.previous
			case presentWrong:
				secret = f.current + "-wrong"
			}

			form := url.Values{}
			basicID, basicSecret := "", ""
			if row.method == clientauth.MethodSecretBasic {
				basicID, basicSecret = "client-1", secret
			} else {
				form.Set("client_id", "client-1")
				form.Set("client_secret", secret)
			}
			creds, err := clientauth.Parse(newPostRequest(t, form, basicID, basicSecret))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if creds.Method != row.method {
				t.Fatalf("parsed method=%v want %v", creds.Method, row.method)
			}
			before := *creds

			opts := clientauth.VerifyOpts{SecretVerifier: f.verifier, Now: now}
			if row.zeroNow {
				opts.Now = time.Time{}
			}
			verified, err := clientauth.VerifyClient(context.Background(), creds, client, opts)

			if *creds != before {
				t.Errorf("VerifyClient mutated credentials: %+v -> %+v", before, *creds)
			}
			switch row.want {
			case reject:
				if !errors.Is(err, clientauth.ErrCredentialsInvalid) {
					t.Fatalf("err=%v want ErrCredentialsInvalid", err)
				}
				if verified != (clientauth.Verified{}) {
					t.Errorf("verified=%+v want zero on rejection", verified)
				}
			case acceptCurrent, acceptPrevious:
				if err != nil {
					t.Fatalf("VerifyClient: %v", err)
				}
				want := clientauth.Verified{Method: row.method, PreviousSecret: row.want == acceptPrevious}
				if verified != want {
					t.Errorf("verified=%+v want %+v", verified, want)
				}
			}
		})
	}
}
