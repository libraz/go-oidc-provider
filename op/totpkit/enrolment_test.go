package totpkit_test

import (
	"bytes"
	"encoding/base32"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/totpkit"
)

// newCodec constructs a fresh codec under a random key for tests.
func newCodec(t *testing.T) *totpkit.Codec {
	t.Helper()
	c, err := totpkit.NewCodec(newKey(t))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	return c
}

// TestNewEnrolment_Roundtrip pins the contract that the sealed
// SecretCiphertext on the returned Pending opens cleanly under the
// same codec when the Subject is supplied as AAD. Without this
// property the verify path could not consume a confirmed record.
func TestNewEnrolment_Roundtrip(t *testing.T) {
	t.Parallel()

	codec := newCodec(t)
	pending, err := totpkit.NewEnrolment(codec, "user-alice", "Example", "alice@example.com")
	if err != nil {
		t.Fatalf("NewEnrolment: %v", err)
	}
	if pending.Record == nil {
		t.Fatal("Pending.Record is nil")
	}
	got, err := codec.Open(pending.Record.SecretCiphertext, []byte("user-alice"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(got) != 20 {
		t.Errorf("decrypted secret len=%d want 20", len(got))
	}
}

// TestNewEnrolment_DistinctSecrets verifies two consecutive
// enrolments under the same codec / subject produce different
// plaintexts (entropy gate) AND different ciphertexts (nonce
// freshness). Sharing either would mean the secret generator or the
// AEAD nonce is broken.
func TestNewEnrolment_DistinctSecrets(t *testing.T) {
	t.Parallel()

	codec := newCodec(t)
	a, err := totpkit.NewEnrolment(codec, "user-alice", "Example", "alice@example.com")
	if err != nil {
		t.Fatalf("NewEnrolment a: %v", err)
	}
	b, err := totpkit.NewEnrolment(codec, "user-alice", "Example", "alice@example.com")
	if err != nil {
		t.Fatalf("NewEnrolment b: %v", err)
	}

	if bytes.Equal(a.Record.SecretCiphertext, b.Record.SecretCiphertext) {
		t.Error("two enrolments produced identical ciphertexts (nonce reuse?)")
	}

	plainA, err := codec.Open(a.Record.SecretCiphertext, []byte("user-alice"))
	if err != nil {
		t.Fatalf("Open a: %v", err)
	}
	plainB, err := codec.Open(b.Record.SecretCiphertext, []byte("user-alice"))
	if err != nil {
		t.Fatalf("Open b: %v", err)
	}
	if bytes.Equal(plainA, plainB) {
		t.Error("two enrolments produced identical plaintext secrets (entropy?)")
	}
}

// TestNewEnrolment_SecretLength pins the 20-byte (160-bit) secret
// size required by RFC 6238 §5.1 for a SHA-1 HMAC. Authenticator
// apps decode the SecretBase32 field; if the size drifts the QR
// code becomes incompatible.
func TestNewEnrolment_SecretLength(t *testing.T) {
	t.Parallel()

	codec := newCodec(t)
	pending, err := totpkit.NewEnrolment(codec, "user-alice", "Example", "alice@example.com")
	if err != nil {
		t.Fatalf("NewEnrolment: %v", err)
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(pending.SecretBase32)
	if err != nil {
		t.Fatalf("base32 decode: %v", err)
	}
	if len(decoded) != 20 {
		t.Errorf("decoded len=%d want 20", len(decoded))
	}
}

// TestNewEnrolment_OTPAuthURIShape parses the OTPAuth URI and
// asserts every field an authenticator app reads matches the
// RFC 6238 / Key URI Format default profile.
func TestNewEnrolment_OTPAuthURIShape(t *testing.T) {
	t.Parallel()

	codec := newCodec(t)
	pending, err := totpkit.NewEnrolment(codec, "user-alice", "Example", "alice@example.com")
	if err != nil {
		t.Fatalf("NewEnrolment: %v", err)
	}
	u, err := url.Parse(pending.OTPAuthURI)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if u.Scheme != "otpauth" {
		t.Errorf("scheme=%q want otpauth", u.Scheme)
	}
	if u.Host != "totp" {
		t.Errorf("host=%q want totp", u.Host)
	}
	if !strings.Contains(u.Path, "Example") || !strings.Contains(u.Path, "alice@example.com") {
		t.Errorf("path=%q does not embed issuer/account label", u.Path)
	}
	q := u.Query()
	if got := q.Get("algorithm"); got != "SHA1" {
		t.Errorf("algorithm=%q want SHA1", got)
	}
	if got := q.Get("digits"); got != "6" {
		t.Errorf("digits=%q want 6", got)
	}
	if got := q.Get("period"); got != "30" {
		t.Errorf("period=%q want 30", got)
	}
	if got := q.Get("issuer"); got != "Example" {
		t.Errorf("issuer=%q want Example", got)
	}
	if got := q.Get("secret"); got != pending.SecretBase32 {
		t.Errorf("secret=%q want %q", got, pending.SecretBase32)
	}
}

// TestNewEnrolment_URIEscapesSpecials checks that issuer / account
// labels containing characters with reserved semantics in URIs
// (space, colon, '@') survive parsing through PathUnescape.
func TestNewEnrolment_URIEscapesSpecials(t *testing.T) {
	t.Parallel()

	codec := newCodec(t)
	pending, err := totpkit.NewEnrolment(codec, "user-alice", "Example Corp", "user:name@example.com")
	if err != nil {
		t.Fatalf("NewEnrolment: %v", err)
	}
	u, err := url.Parse(pending.OTPAuthURI)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	rawLabel := strings.TrimPrefix(u.EscapedPath(), "/")
	label, err := url.PathUnescape(rawLabel)
	if err != nil {
		t.Fatalf("PathUnescape: %v", err)
	}
	if label != "Example Corp:user:name@example.com" {
		t.Errorf("label=%q want Example Corp:user:name@example.com", label)
	}
	if got := u.Query().Get("issuer"); got != "Example Corp" {
		t.Errorf("issuer=%q want Example Corp", got)
	}
}

// TestNewEnrolment_URIHandlesUnicode verifies non-ASCII issuer and
// account values round-trip through the URI without corruption.
// Authenticator apps typically render the decoded form, so the
// query "issuer" field MUST decode back to the original string.
func TestNewEnrolment_URIHandlesUnicode(t *testing.T) {
	t.Parallel()

	codec := newCodec(t)
	pending, err := totpkit.NewEnrolment(codec, "user-alice", "例の会社", "花子@example.com")
	if err != nil {
		t.Fatalf("NewEnrolment: %v", err)
	}
	u, err := url.Parse(pending.OTPAuthURI)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if got := u.Query().Get("issuer"); got != "例の会社" {
		t.Errorf("issuer=%q want 例の会社", got)
	}
	rawLabel := strings.TrimPrefix(u.EscapedPath(), "/")
	label, err := url.PathUnescape(rawLabel)
	if err != nil {
		t.Fatalf("PathUnescape: %v", err)
	}
	if !strings.Contains(label, "例の会社") || !strings.Contains(label, "花子@example.com") {
		t.Errorf("label=%q does not embed unicode issuer/account", label)
	}
}

// TestNewEnrolment_AADBindsSubject pins the cross-user replay
// defence: a Pending built for subject A cannot be opened under
// subject B because the GCM tag rejects the AAD mismatch. The same
// property holds at verify time; testing it here keeps the contract
// pinned at the construction boundary too.
func TestNewEnrolment_AADBindsSubject(t *testing.T) {
	t.Parallel()

	codec := newCodec(t)
	pending, err := totpkit.NewEnrolment(codec, "user-alice", "Example", "alice@example.com")
	if err != nil {
		t.Fatalf("NewEnrolment: %v", err)
	}
	if _, err := codec.Open(pending.Record.SecretCiphertext, []byte("user-bob")); !errors.Is(err, totpkit.ErrDecrypt) {
		t.Errorf("Open with mismatched aad: err=%v want ErrDecrypt", err)
	}
}

// TestNewEnrolment_RejectsEmptyIssuer pins the input-validation
// contract: an authenticator app rendered with an empty issuer
// shows an unlabelled account, which confuses users. The package
// refuses the construction so the misconfiguration surfaces at the
// embedder boundary.
func TestNewEnrolment_RejectsEmptyIssuer(t *testing.T) {
	t.Parallel()

	codec := newCodec(t)
	for _, issuer := range []string{"", "   "} {
		_, err := totpkit.NewEnrolment(codec, "user-alice", issuer, "alice@example.com")
		if !errors.Is(err, totpkit.ErrInvalidIssuer) {
			t.Errorf("issuer=%q err=%v want ErrInvalidIssuer", issuer, err)
		}
	}
}

// TestNewEnrolment_RejectsEmptyAccount pins the same contract on
// the account label.
func TestNewEnrolment_RejectsEmptyAccount(t *testing.T) {
	t.Parallel()

	codec := newCodec(t)
	for _, account := range []string{"", "   "} {
		_, err := totpkit.NewEnrolment(codec, "user-alice", "Example", account)
		if !errors.Is(err, totpkit.ErrInvalidAccount) {
			t.Errorf("account=%q err=%v want ErrInvalidAccount", account, err)
		}
	}
}

// TestNewEnrolment_RejectsEmptySubject is the safety-critical
// counterpart: the subject is bound as AAD into the GCM tag, and an
// empty AAD lets a row exfiltrated from one enrolment row decrypt
// under any other empty-subject row. The package refuses the
// construction so the bug surfaces immediately.
func TestNewEnrolment_RejectsEmptySubject(t *testing.T) {
	t.Parallel()

	codec := newCodec(t)
	_, err := totpkit.NewEnrolment(codec, "", "Example", "alice@example.com")
	if !errors.Is(err, totpkit.ErrInvalidSubject) {
		t.Errorf("err=%v want ErrInvalidSubject", err)
	}
}

// TestNewEnrolment_NilCodec covers the explicit nil-guard so a
// programming mistake at the controller boundary surfaces as a
// configuration sentinel rather than a nil-pointer panic.
func TestNewEnrolment_NilCodec(t *testing.T) {
	t.Parallel()

	_, err := totpkit.NewEnrolment(nil, "user-alice", "Example", "alice@example.com")
	if !errors.Is(err, totpkit.ErrCodecRequired) {
		t.Errorf("err=%v want ErrCodecRequired", err)
	}
}
