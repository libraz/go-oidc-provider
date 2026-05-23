package dpop_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/dpop"
)

// spyEmitter captures every [audit.Event] the verifier emits. The
// helper exists so the AllowLooseMethodCase test can assert on the
// emission shape without dragging in the production slog handler.
type spyEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (s *spyEmitter) Emit(_ context.Context, ev audit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *spyEmitter) Events() []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]audit.Event, len(s.events))
	copy(out, s.events)
	return out
}

// The dpop_test package shares helpers with proof_test.go (signKey,
// newVerifier, fixedClock, mustParseURL, etc.). The cases in this file
// focus on the high-level Verify entry point: HTM/HTU mismatch, iat
// window enforcement, replay detection, and the optional ath binding
// (RFC 9449 §4.3).

func TestVerify_HTMMismatch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(now), "")
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "GET",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofHTMMismatch) {
		t.Fatalf("err=%v want ErrProofHTMMismatch", err)
	}
}

func TestVerify_HTUMismatch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(now), "")
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/userinfo"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofHTUMismatch) {
		t.Fatalf("err=%v want ErrProofHTUMismatch", err)
	}
}

func TestVerify_IatTooOld(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	stale := now.Add(-2 * time.Minute)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(stale), "")
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofIatWindow) {
		t.Fatalf("err=%v want ErrProofIatWindow", err)
	}
}

func TestVerify_IatTooFuture(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	future := now.Add(5 * time.Minute)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(future), "")
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofIatWindow) {
		t.Fatalf("err=%v want ErrProofIatWindow", err)
	}
}

func TestVerify_Replay(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(now), "")
	v := newVerifier(t, now)

	if _, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	}); err != nil {
		t.Fatalf("first Verify: %v", err)
	}

	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofReplayed) {
		t.Fatalf("err=%v want ErrProofReplayed", err)
	}
}

func TestVerify_JTIExpiryAnchoredToProofIAT(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	iat := now.Add(-30 * time.Second)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(iat), "")
	jtis := &captureJTIStore{}
	v, err := dpop.NewVerifier(dpop.VerifierConfig{
		JTIs:      jtis,
		Clock:     fixedClock{now: now},
		IatWindow: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := iat.Add(time.Minute)
	if !jtis.expiresAt.Equal(want) {
		t.Fatalf("jti expiresAt=%s want %s", jtis.expiresAt, want)
	}
}

func TestVerify_ATHRequired(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(now), "")
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
		AccessToken: "opaque-access-token",
	})
	if !errors.Is(err, dpop.ErrProofATHMismatch) {
		t.Fatalf("err=%v want ErrProofATHMismatch", err)
	}
}

func TestVerify_ATHMismatch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	claims := goodClaims(now)
	claims["ath"] = base64.RawURLEncoding.EncodeToString(sha256.New().Sum([]byte("wrong")))
	raw := signProof(t, key, claims, "")
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
		AccessToken: "opaque-access-token",
	})
	if !errors.Is(err, dpop.ErrProofATHMismatch) {
		t.Fatalf("err=%v want ErrProofATHMismatch", err)
	}
}

func TestVerify_ATHHappyPath(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	const accessToken = "opaque-access-token"
	claims := goodClaims(now)
	claims["ath"] = dpop.AccessTokenHash(accessToken)
	raw := signProof(t, key, claims, "")
	v := newVerifier(t, now)
	out, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
		AccessToken: accessToken,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.JKT == "" {
		t.Errorf("JKT must be populated on ath success")
	}
}

func TestNewVerifier_RequiresJTIs(t *testing.T) {
	t.Parallel()
	if _, err := dpop.NewVerifier(dpop.VerifierConfig{}); err == nil {
		t.Fatal("NewVerifier without JTIs must error")
	}
}

// TestVerify_HTUUnderTrustedProxy mirrors the request shape produced by
// [op.wrapWithTrustedProxy] when the OP terminates TLS at a reverse
// proxy: the standard-library r.URL has Scheme=="https" (rewritten
// from XFP) and an empty Host, r.Host carries the externally-visible
// authority, and r.TLS is nil (the OP itself sees a plaintext hop
// from the proxy). The verifier MUST treat the proxy-rewritten URL as
// canonical so the proof's "htu" claim matches even though the OP
// process did not terminate TLS itself.
func TestVerify_HTUUnderTrustedProxy(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	claims := goodClaims(now)
	claims["htu"] = "https://op.example.com/oidc/token"
	raw := signProof(t, key, claims, "")

	v := newVerifier(t, now)
	// r.URL on the inbound proxy hop has Scheme rewritten to https
	// and an empty Host; r.Host carries the rewritten authority.
	u := mustParseURL(t, "https://op.example.com/oidc/token")
	u.Host = "" // mirror the std-library shape after Clone.URL.Scheme rewrite
	if _, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         u,
		Host:        "op.example.com",
		TLS:         false, // proxy terminated TLS; r.TLS is nil at the OP.
	}); err != nil {
		t.Fatalf("Verify under proxy chain: %v", err)
	}
}

// TestVerify_HTUDefaultPortNormalisation pins the RFC 3986 §3.2.3
// behaviour: a proof that spells "https://op.example/oidc/token:443"
// or "https://op.example:443/oidc/token" matches a request URL that
// omits the default port, and vice versa. Without normalisation the
// proof-vs-request comparison is byte-for-byte and rejects spec-
// conformant inputs that differ only in the elided default-port
// presentation.
func TestVerify_HTUDefaultPortNormalisation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name    string
		htu     string
		request string
	}{
		{"proof_with_default_port", "https://op.example.com:443/oidc/token", "https://op.example.com/oidc/token"},
		{"request_with_default_port", "https://op.example.com/oidc/token", "https://op.example.com:443/oidc/token"},
		{"http_default_port", "http://op.example.com/oidc/token", "http://op.example.com:80/oidc/token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := newES256Key(t)
			claims := goodClaims(now)
			claims["htu"] = tc.htu
			raw := signProof(t, key, claims, "")

			v := newVerifier(t, now)
			u := mustParseURL(t, tc.request)
			tls := u.Scheme == "https"
			if _, err := v.Verify(context.Background(), dpop.VerifyInput{
				ProofHeader: raw,
				Method:      "POST",
				URL:         u,
				TLS:         tls,
			}); err != nil {
				t.Fatalf("Verify htu=%q request=%q: %v", tc.htu, tc.request, err)
			}
		})
	}
}

// TestVerify_HTUNonDefaultPortPreserved is the negative companion to
// [TestVerify_HTUDefaultPortNormalisation]: a proof that pins a non-
// default port (":8443") MUST NOT match a request URL whose port
// differs. The default-port stripper is conservative; only ":80" /
// ":443" fold away.
func TestVerify_HTUNonDefaultPortPreserved(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	claims := goodClaims(now)
	claims["htu"] = "https://op.example.com:8443/oidc/token"
	raw := signProof(t, key, claims, "")

	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example.com/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofHTUMismatch) {
		t.Fatalf("err=%v want ErrProofHTUMismatch (custom port must not fold)", err)
	}
}

// TestVerify_LooseMethodCaseEmitsAudit pins the B5 contract: when the
// verifier was constructed with [VerifierConfig.AllowLooseMethodCase]
// AND a proof's "htm" differed from the request method only in ASCII
// case, the verifier admits the proof AND emits a warn-level audit
// event so SOC tooling can spot the bridge while the responsible RP
// library is fixed.
func TestVerify_LooseMethodCaseEmitsAudit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	claims := goodClaims(now)
	claims["htm"] = "post" // lower-case htm; request below carries POST.
	raw := signProof(t, key, claims, "")

	spy := &spyEmitter{}
	v, err := dpop.NewVerifier(dpop.VerifierConfig{
		JTIs:                 newMemJTIStore(),
		Clock:                fixedClock{now: now},
		AllowLooseMethodCase: true,
		Emitter:              spy,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	}); err != nil {
		t.Fatalf("Verify (loose mode): %v", err)
	}
	events := spy.Events()
	if len(events) != 1 {
		t.Fatalf("emitter received %d events, want 1: %+v", len(events), events)
	}
	ev := events[0]
	if ev.Name != dpop.AuditEventLooseMethodCaseAdmitted {
		t.Errorf("event name=%q want %q", ev.Name, dpop.AuditEventLooseMethodCaseAdmitted)
	}
	if ev.Level != audit.LevelWarn {
		t.Errorf("event level=%v want LevelWarn", ev.Level)
	}
	if got := ev.Extras["htm"]; got != "post" {
		t.Errorf("extras.htm=%v want \"post\"", got)
	}
	if got := ev.Extras["request_method"]; got != "POST" {
		t.Errorf("extras.request_method=%v want \"POST\"", got)
	}
}

// TestVerify_LooseMethodCaseSilentOnMatch is the negative companion:
// when the proof's htm matches the request method byte-for-byte (the
// canonical RFC 9449 §4.3 shape), the verifier MUST NOT emit the
// loose-mode audit event even when AllowLooseMethodCase is set.
func TestVerify_LooseMethodCaseSilentOnMatch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(now), "")

	spy := &spyEmitter{}
	v, err := dpop.NewVerifier(dpop.VerifierConfig{
		JTIs:                 newMemJTIStore(),
		Clock:                fixedClock{now: now},
		AllowLooseMethodCase: true,
		Emitter:              spy,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	}); err != nil {
		t.Fatalf("Verify (strict-shape proof): %v", err)
	}
	if events := spy.Events(); len(events) != 0 {
		t.Errorf("expected zero audit events for byte-equal htm match, got: %+v", events)
	}
}

// TestVerify_StrictModeRejectsLoose is the foundation guarantee: with
// AllowLooseMethodCase off (the default), a case-mismatched proof is
// rejected outright. The audit emitter is consulted only on the loose-
// admit path; the strict path produces ErrProofHTMMismatch with no
// emission.
func TestVerify_StrictModeRejectsLoose(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	claims := goodClaims(now)
	claims["htm"] = "post"
	raw := signProof(t, key, claims, "")

	spy := &spyEmitter{}
	v, err := dpop.NewVerifier(dpop.VerifierConfig{
		JTIs:    newMemJTIStore(),
		Clock:   fixedClock{now: now},
		Emitter: spy,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	_, verr := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(verr, dpop.ErrProofHTMMismatch) {
		t.Fatalf("err=%v want ErrProofHTMMismatch", verr)
	}
	if events := spy.Events(); len(events) != 0 {
		t.Errorf("strict-mode rejection must not emit audit, got: %+v", events)
	}
}

func TestAccessTokenHash_Stable(t *testing.T) {
	t.Parallel()
	a := dpop.AccessTokenHash("abc")
	b := dpop.AccessTokenHash("abc")
	if a != b {
		t.Errorf("hash diverged: %q vs %q", a, b)
	}
	if dpop.AccessTokenHash("abc") == dpop.AccessTokenHash("abd") {
		t.Errorf("collision on tiny input")
	}
}
