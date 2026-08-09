package keys_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/keys"
)

func mustECDSAKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	return priv
}

func TestNewSet_AcceptsSingleKey(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	set, err := keys.NewSet([]keys.Entry{{KeyID: "sig-1", Signer: priv}})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	if got := set.Active().KeyID; got != "sig-1" {
		t.Errorf("Active().KeyID=%q want sig-1", got)
	}
	jwks := set.JWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("JWKS keys=%d want 1", len(jwks.Keys))
	}
	if jwks.Keys[0].KeyID != "sig-1" {
		t.Errorf("kid=%q want sig-1", jwks.Keys[0].KeyID)
	}
	if jwks.Keys[0].Algorithm != "ES256" {
		t.Errorf("alg=%q want ES256", jwks.Keys[0].Algorithm)
	}
	if jwks.Keys[0].Use != "sig" {
		t.Errorf("use=%q want sig", jwks.Keys[0].Use)
	}
}

func TestNewSet_RejectsEmptyAndDuplicate(t *testing.T) {
	t.Parallel()

	_, err := keys.NewSet(nil)
	if !errors.Is(err, keys.ErrInvalidKey) {
		t.Errorf("nil entries: err=%v want ErrInvalidKey", err)
	}

	priv := mustECDSAKey(t)
	_, err = keys.NewSet([]keys.Entry{
		{KeyID: "k", Signer: priv},
		{KeyID: "k", Signer: priv},
	})
	if !errors.Is(err, keys.ErrInvalidKey) {
		t.Errorf("duplicate kid: err=%v want ErrInvalidKey", err)
	}
}

func TestNewSet_RejectsBadShape(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}

	cases := []struct {
		name  string
		entry keys.Entry
	}{
		{"empty kid", keys.Entry{KeyID: "", Signer: priv}},
		{"nil signer", keys.Entry{KeyID: "x", Signer: nil}},
		{"non-p256", keys.Entry{KeyID: "x", Signer: rsaPriv}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := keys.NewSet([]keys.Entry{tc.entry})
			if !errors.Is(err, keys.ErrInvalidKey) {
				t.Errorf("err=%v want ErrInvalidKey", err)
			}
		})
	}
}

func TestSet_FindReturnsEntryByKeyID(t *testing.T) {
	t.Parallel()

	priv1 := mustECDSAKey(t)
	priv2 := mustECDSAKey(t)
	set, err := keys.NewSet([]keys.Entry{
		{KeyID: "active", Signer: priv1},
		{KeyID: "retiring", Signer: priv2},
	})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}

	got, ok := set.Find(context.Background(), "retiring")
	if !ok {
		t.Fatal("Find(retiring) ok=false, want true")
	}
	if got.KeyID != "retiring" {
		t.Errorf("Find(retiring).KeyID=%q want retiring", got.KeyID)
	}
	if got.Signer != priv2 {
		t.Error("Find(retiring) returned the wrong Signer")
	}

	if got, ok := set.Find(context.Background(), "active"); !ok || got.KeyID != "active" {
		t.Errorf("Find(active)=(%+v,%v) want active key", got, ok)
	}
}

func TestSet_FindReturnsFalseForUnknownKeyID(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	set, err := keys.NewSet([]keys.Entry{{KeyID: "active", Signer: priv}})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	got, ok := set.Find(context.Background(), "missing")
	if ok {
		t.Errorf("Find(missing) ok=true want false (got=%+v)", got)
	}
	if got.KeyID != "" || got.Signer != nil {
		t.Errorf("Find(missing) returned non-zero Entry=%+v", got)
	}

	if _, ok := set.Find(context.Background(), ""); ok {
		t.Error("Find(\"\") ok=true want false for empty kid lookup")
	}
}

// TestSet_FindIsPureStringEquality_NoPathTraversal pins the
// structural property that [Set.Find] is byte-equal-on-the-key-id and
// does NOT interpret the input as a path, URL, or any other indirect
// reference. Tracks the JWT "kid" header injection class popularised
// by PortSwigger's "JWT authentication bypass via kid header path
// traversal" lab (no single CVE; the attack pattern appears in
// libraries that map "kid" onto a filesystem read or a database query
// without sanitisation, then trust the byte content of whatever
// resource was returned as a verification key).
//
// Defence in this codebase: [Set.Find] iterates the entries slice
// and compares "kid" with `==` on the string. There is no string
// trimming, no canonicalisation, no Unicode folding, no path or URL
// resolution — and entries are populated only at construction time
// from a Go-typed [Entry] struct, never from attacker bytes. The
// test uses a representative set of attacker shapes and asserts
// every one returns ok=false. A regression that introduced lookup
// transformation (or, worst case, a filesystem read) would surface
// as one of these probes succeeding.
//
// Tracks: RFC 7517 §4.5 ("kid" is OPAQUE — implementations MUST NOT
// interpret it), RFC 8725 §2.7 (algorithm and key selection MUST
// trust only the verifier's local store).
func TestSet_FindIsPureStringEquality_NoPathTraversal(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	set, err := keys.NewSet([]keys.Entry{{KeyID: "rotating-key-1", Signer: priv}})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}

	probes := []string{
		"../rotating-key-1",
		"../../etc/passwd",
		"rotating-key-1/../",
		"rotating-key-1/../../rotating-key-1",
		"./rotating-key-1",
		"/rotating-key-1",
		"\\rotating-key-1",
		"rotating-key-1\\..",
		"rotating-key-1\x00",
		"rotating-key-1\x00.tampered",
		"\x00rotating-key-1",
		"rotating-key-1\n",
		"rotating-key-1\r\n",
		"rotating-key-1\t",
		"rotating-key-1 ", // trailing space
		" rotating-key-1", // leading space
		"ROTATING-KEY-1",  // case-variant: kid is case-sensitive
		"Rotating-Key-1",
		"rotating-key-1#frag",
		"rotating-key-1?query",
		"file://rotating-key-1",
		"https://attacker.example/rotating-key-1",
		"rotating-key-1\x7f",   // DEL
		"rotating-key-1\u200b", // zero-width space
		"rotating-key-1\uFEFF", // BOM (U+FEFF)
		"rotating‐key‐-1",      // Unicode hyphen homoglyph (U+2010)
	}
	for _, kid := range probes {
		t.Run("kid="+kid, func(t *testing.T) {
			t.Parallel()
			got, ok := set.Find(context.Background(), kid)
			if ok {
				t.Fatalf("Find(%q) ok=true; lookup MUST be byte-equal on kid (got Entry=%+v)", kid, got)
			}
			if got.KeyID != "" || got.Signer != nil {
				t.Fatalf("Find(%q) returned non-zero Entry=%+v on miss", kid, got)
			}
		})
	}
}

func TestSet_JWKSIsDefensiveCopy(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	set, err := keys.NewSet([]keys.Entry{{KeyID: "k", Signer: priv}})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	a := set.JWKS()
	b := set.JWKS()
	a.Keys[0].KeyID = "tampered"
	if b.Keys[0].KeyID != "k" {
		t.Errorf("JWKS shared mutable state: second view kid=%q", b.Keys[0].KeyID)
	}
	if got := set.JWKS().Keys[0].KeyID; got != "k" {
		t.Errorf("set view mutated: kid=%q", got)
	}
}

// TestSet_Find_RejectsRetiredKey pins the retirement gate: an [Entry] whose
// [Entry.NotAfter] has elapsed by the configured clock reading MUST
// surface as a [Set.Find] miss, even though the kid still matches a
// physical entry. The retirement gate is the audit anchor for the
// "rotation-after-leak token forge" attempt — an attacker who captured
// the old private key before the rotation reuses the same kid against
// the OP, hoping to ride past the JWKS grace window.
func TestSet_Find_RejectsRetiredKey(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	deadline := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	set, err := keys.NewSet(
		[]keys.Entry{
			{KeyID: "active", Signer: priv},
			{KeyID: "retiring", Signer: priv, NotAfter: deadline},
		},
		keys.WithClock(func() time.Time { return deadline.Add(time.Second) }),
	)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	got, ok := set.Find(context.Background(), "retiring")
	if ok {
		t.Fatalf("Find(retiring) ok=true after deadline; want false (got=%+v)", got)
	}
	if got.KeyID != "" || got.Signer != nil {
		t.Fatalf("Find(retiring) returned non-zero Entry on retirement reject: %+v", got)
	}
	// The active key must remain reachable: retirement is per-entry,
	// not per-set.
	if got, ok := set.Find(context.Background(), "active"); !ok || got.KeyID != "active" {
		t.Errorf("Find(active)=(%+v,%v) want active key", got, ok)
	}
}

// TestSet_Find_AcceptsKeyBeforeNotAfter pins the boundary opposite to
// [TestSet_Find_RejectsRetiredKey]: a retiring entry MUST verify until
// the configured clock reaches the deadline. The comparison is "now <
// NotAfter", so a clock reading strictly before the deadline keeps the
// kid reachable; reaching the deadline (or stepping past it) flips the
// gate. The two tests pin both edges of the boundary so a future
// regression that swaps the comparator surfaces.
func TestSet_Find_AcceptsKeyBeforeNotAfter(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	deadline := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"one nanosecond before deadline", deadline.Add(-time.Nanosecond), true},
		{"one second before deadline", deadline.Add(-time.Second), true},
		{"exactly at deadline", deadline, false},
		{"one nanosecond after deadline", deadline.Add(time.Nanosecond), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			set, err := keys.NewSet(
				[]keys.Entry{
					{KeyID: "retiring", Signer: priv, NotAfter: deadline},
				},
				keys.WithClock(func() time.Time { return tc.now }),
			)
			if err != nil {
				t.Fatalf("NewSet: %v", err)
			}
			got, ok := set.Find(context.Background(), "retiring")
			if ok != tc.want {
				t.Fatalf("Find(retiring) ok=%v want %v (now=%v deadline=%v)", ok, tc.want, tc.now, deadline)
			}
			if !ok && (got.KeyID != "" || got.Signer != nil) {
				t.Fatalf("Find returned non-zero Entry on miss: %+v", got)
			}
		})
	}
}

// TestSet_Find_NotifiesObserverOnRetiredKid pins that the observer
// configured through [WithRetiredKidObserver] is fired exactly once on
// every Find call that rejects a retired kid, and that the kid value
// it receives matches the one the caller looked up. The observer is
// the audit anchor: the OP wires the slog emitter behind it so SOC
// tooling sees [op.AuditKeyRetiredKidPresented] for every rejection.
//
// Unknown-kid lookups MUST NOT trigger the observer — the rotation
// audit signal would lose meaning if an attacker probing arbitrary
// kid strings could amplify it.
func TestSet_Find_NotifiesObserverOnRetiredKid(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	deadline := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	var calls atomic.Int64
	var lastKid atomic.Value
	set, err := keys.NewSet(
		[]keys.Entry{
			{KeyID: "active", Signer: priv},
			{KeyID: "retiring", Signer: priv, NotAfter: deadline},
		},
		keys.WithClock(func() time.Time { return deadline.Add(time.Hour) }),
		keys.WithRetiredKidObserver(func(_ context.Context, kid string) {
			calls.Add(1)
			lastKid.Store(kid)
		}),
	)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}

	if _, ok := set.Find(context.Background(), "retiring"); ok {
		t.Fatal("Find(retiring) should reject after deadline")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("observer call count=%d want 1", got)
	}
	if got, _ := lastKid.Load().(string); got != "retiring" {
		t.Errorf("observer kid=%q want retiring", got)
	}

	// Active and unknown kids must not trigger the observer.
	if _, ok := set.Find(context.Background(), "active"); !ok {
		t.Fatal("Find(active) should still succeed")
	}
	if _, ok := set.Find(context.Background(), "never-existed"); ok {
		t.Fatal("Find(never-existed) should miss")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("observer fired beyond retired path: count=%d want 1", got)
	}
}

// TestSet_Find_NoObserverDoesNotPanic guards the defensive nil-guard
// inside [Set.Find]: a Set built without [WithRetiredKidObserver] MUST
// still reject retired kids cleanly without dereferencing the absent
// callback. The observer is optional (the discard sink is the
// caller-side default), and a regression that drops the nil-check
// would crash the request hot path.
func TestSet_Find_NoObserverDoesNotPanic(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	deadline := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	set, err := keys.NewSet(
		[]keys.Entry{{KeyID: "retiring", Signer: priv, NotAfter: deadline}},
		keys.WithClock(func() time.Time { return deadline.Add(time.Hour) }),
	)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	if _, ok := set.Find(context.Background(), "retiring"); ok {
		t.Fatal("retired kid was admitted")
	}
}

// TestSet_Find_ZeroNotAfterNeverRetires pins the back-compat contract:
// an [Entry] left at the zero-value [Entry.NotAfter] never retires, no
// matter how far the clock advances. Embedders that have not opted
// into rotation deadlines see the original behaviour unchanged.
func TestSet_Find_ZeroNotAfterNeverRetires(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	farFuture := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	set, err := keys.NewSet(
		[]keys.Entry{{KeyID: "evergreen", Signer: priv}},
		keys.WithClock(func() time.Time { return farFuture }),
	)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	if _, ok := set.Find(context.Background(), "evergreen"); !ok {
		t.Fatal("zero-NotAfter entry MUST never retire")
	}
}

// TestSet_JWKS_AdvertisesRetiredEntries pins the asymmetry RFC 7517
// §4.5 prescribes for graceful rotation: a retired kid is rejected on
// verification but stays in the published JWKS so RP caches that have
// not yet refreshed continue to see the public key. Pulling the kid
// out of JWKS the moment the gate flips would strand RPs whose cache
// TTL has not elapsed; the audit warning on the verification side
// already covers the post-deadline forge attempt.
func TestSet_JWKS_AdvertisesRetiredEntries(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	deadline := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	set, err := keys.NewSet(
		[]keys.Entry{
			{KeyID: "active", Signer: priv},
			{KeyID: "retired", Signer: priv, NotAfter: deadline},
		},
		keys.WithClock(func() time.Time { return deadline.Add(24 * time.Hour) }),
	)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	jwks := set.JWKS()
	kids := make(map[string]bool, len(jwks.Keys))
	for _, k := range jwks.Keys {
		kids[k.KeyID] = true
	}
	if !kids["active"] || !kids["retired"] {
		t.Fatalf("JWKS view dropped a key: %v", kids)
	}
}

// correlationKeyType is the key under which the observer-context tests
// stash a marker value. A dedicated unexported type keeps the lookup
// collision-free, as [context.WithValue] requires.
type correlationKeyType struct{}

// TestSet_Find_ObserverReceivesCallerContext pins that the retired-kid
// notification carries the context the caller passed to [keys.Set.Find]
// rather than a detached one. The assertion reads a marker value back
// out of the observed context: asserting only that the context is
// non-nil would pass against [context.Background] and would therefore
// not detect the very defect this pins — an audit event that reaches
// the embedder's sink with no request id and no trace span, leaving an
// operator unable to answer "who presented the retired kid, and on
// which request".
func TestSet_Find_ObserverReceivesCallerContext(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	deadline := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	var observed atomic.Value
	set, err := keys.NewSet(
		[]keys.Entry{{KeyID: "retiring", Signer: priv, NotAfter: deadline}},
		keys.WithClock(func() time.Time { return deadline.Add(time.Hour) }),
		keys.WithRetiredKidObserver(func(ctx context.Context, _ string) {
			marker, _ := ctx.Value(correlationKeyType{}).(string)
			observed.Store(marker)
		}),
	)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}

	ctx := context.WithValue(context.Background(), correlationKeyType{}, "request-7")
	if _, ok := set.Find(ctx, "retiring"); ok {
		t.Fatal("Find(retiring) should reject after deadline")
	}
	got, _ := observed.Load().(string)
	if got != "request-7" {
		t.Fatalf("observer context marker=%q want request-7 — the caller's context did not reach the observer", got)
	}
}
