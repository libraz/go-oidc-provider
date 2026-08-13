package subject_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/subject"
)

// fixedSalt returns a deterministic 32-byte slice the tests share so
// expected values can be precomputed and reproduced.
func fixedSalt() []byte {
	salt := make([]byte, subject.MinSaltLength)
	for i := range salt {
		salt[i] = byte(i)
	}
	return salt
}

func TestPairwise_DerivationMatchesSpec(t *testing.T) {
	t.Parallel()
	salt := fixedSalt()
	g := subject.Pairwise(salt)
	got, err := g.Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: "user-1",
		Client: &store.Client{
			ID:                  "client-a",
			SectorIdentifierURI: "https://sector.example/redirects.json",
		},
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	h := sha256.New()
	_, _ = h.Write(salt)
	_, _ = h.Write([]byte{':'})
	_, _ = h.Write([]byte("sector.example"))
	_, _ = h.Write([]byte{':'})
	_, _ = h.Write([]byte("user-1"))
	want := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	if string(got) != want {
		t.Fatalf("Generate returned %q, want %q", got, want)
	}
}

func TestPairwise_DeterministicAcrossManyCalls(t *testing.T) {
	t.Parallel()
	salt := fixedSalt()
	g := subject.Pairwise(salt)
	in := subject.GeneratorInput{
		InternalUserID: "user-property",
		Client: &store.Client{
			ID:                  "client-prop",
			SectorIdentifierURI: "https://prop.example",
		},
	}
	first, err := g.Generate(context.Background(), in)
	if err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	const iterations = 10_000
	for i := range iterations {
		out, err := g.Generate(context.Background(), in)
		if err != nil {
			t.Fatalf("iter %d Generate: %v", i, err)
		}
		if out != first {
			t.Fatalf("iter %d returned %q, want %q", i, out, first)
		}
	}
}

func TestPairwise_DifferentSectorsProduceDifferentSubjects(t *testing.T) {
	t.Parallel()
	salt := fixedSalt()
	g := subject.Pairwise(salt)
	left, err := g.Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: "shared-user",
		Client: &store.Client{
			ID:                  "client-left",
			SectorIdentifierURI: "https://left.example",
		},
	})
	if err != nil {
		t.Fatalf("left Generate: %v", err)
	}
	right, err := g.Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: "shared-user",
		Client: &store.Client{
			ID:                  "client-right",
			SectorIdentifierURI: "https://right.example",
		},
	})
	if err != nil {
		t.Fatalf("right Generate: %v", err)
	}
	if left == right {
		t.Fatalf("expected distinct sub values across sectors, got %q for both", left)
	}
}

func TestPairwise_DifferentSaltsProduceDifferentSubjects(t *testing.T) {
	t.Parallel()
	saltA := fixedSalt()
	saltB := append([]byte(nil), saltA...)
	saltB[0] ^= 0xff
	gA := subject.Pairwise(saltA)
	gB := subject.Pairwise(saltB)
	in := subject.GeneratorInput{
		InternalUserID: "salt-rotate-user",
		Client: &store.Client{
			ID:                  "client-rotate",
			SectorIdentifierURI: "https://rotate.example",
		},
	}
	a, err := gA.Generate(context.Background(), in)
	if err != nil {
		t.Fatalf("gA Generate: %v", err)
	}
	b, err := gB.Generate(context.Background(), in)
	if err != nil {
		t.Fatalf("gB Generate: %v", err)
	}
	if a == b {
		t.Fatalf("salt change did not affect subject (got %q for both)", a)
	}
}

func TestPairwise_ShortSaltSurfacesAtRequestTime(t *testing.T) {
	t.Parallel()
	g := subject.Pairwise(make([]byte, subject.MinSaltLength-1))
	_, err := g.Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: "user-1",
		Client: &store.Client{
			ID:                  "client-a",
			SectorIdentifierURI: "https://sector.example",
		},
	})
	if !errors.Is(err, subject.ErrSaltTooShort) {
		t.Fatalf("Generate err = %v, want %v", err, subject.ErrSaltTooShort)
	}
}

func TestPairwise_MissingClientIsServerError(t *testing.T) {
	t.Parallel()
	g := subject.Pairwise(fixedSalt())
	_, err := g.Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: "user-1",
	})
	if !errors.Is(err, subject.ErrSectorUnresolved) {
		t.Fatalf("Generate err = %v, want %v", err, subject.ErrSectorUnresolved)
	}
}

func TestPairwise_RedirectURIFallback(t *testing.T) {
	t.Parallel()
	g := subject.Pairwise(fixedSalt())
	out, err := g.Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: "fallback-user",
		Client: &store.Client{
			ID:           "client-fallback",
			RedirectURIs: []string{"https://only.example/cb"},
		},
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if string(out) == "" {
		t.Fatalf("expected non-empty subject, got empty")
	}
}

func TestPairwise_MultipleRedirectHostsAreUnresolved(t *testing.T) {
	t.Parallel()
	g := subject.Pairwise(fixedSalt())
	_, err := g.Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: "user-1",
		Client: &store.Client{
			ID: "client-multi",
			RedirectURIs: []string{
				"https://a.example/cb",
				"https://b.example/cb",
			},
		},
	})
	if !errors.Is(err, subject.ErrSectorUnresolved) {
		t.Fatalf("Generate err = %v, want %v", err, subject.ErrSectorUnresolved)
	}
}

// TestPairwise_DistinctUserIDsDoNotCollideWithinASector pins the half
// of upstream-collision resistance the generator owns. The generator
// takes InternalUserID verbatim, so an embedder serving users from more
// than one upstream is the party that has to make the identifier say
// which upstream a user came from; what the generator guarantees in
// return is that two identifiers which do differ never project onto one
// subject for the same sector.
func TestPairwise_DistinctUserIDsDoNotCollideWithinASector(t *testing.T) {
	t.Parallel()
	g := subject.Pairwise(fixedSalt())
	c := &store.Client{
		ID:                  "client-fed",
		SectorIdentifierURI: "https://fed.example",
	}
	googleSub, err := g.Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: "google:shared-id",
		Client:         c,
	})
	if err != nil {
		t.Fatalf("google Generate: %v", err)
	}
	githubSub, err := g.Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: "github:shared-id",
		Client:         c,
	})
	if err != nil {
		t.Fatalf("github Generate: %v", err)
	}
	if googleSub == githubSub {
		t.Fatalf("distinct user identifiers produced the same sub within one sector")
	}
}

func TestPairwise_SectorURLHostIsLowercased(t *testing.T) {
	t.Parallel()
	g := subject.Pairwise(fixedSalt())
	upper, err := g.Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: "case-user",
		Client: &store.Client{
			ID:                  "client-upper",
			SectorIdentifierURI: "https://SECTOR.EXAMPLE",
		},
	})
	if err != nil {
		t.Fatalf("upper Generate: %v", err)
	}
	lower, err := g.Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: "case-user",
		Client: &store.Client{
			ID:                  "client-lower",
			SectorIdentifierURI: "https://sector.example",
		},
	})
	if err != nil {
		t.Fatalf("lower Generate: %v", err)
	}
	if upper != lower {
		t.Fatalf("sector host case affected output: upper=%q lower=%q", upper, lower)
	}
}

// TestPairwise_SectorURLPortIsIgnored pins OIDC Core 1.0 §8.1: the
// sector is the sector_identifier_uri's host component, not its
// authority (host:port). A sector_identifier_uri that only differs
// from another by an explicit port MUST resolve to the same sector
// and therefore the same pairwise subject.
func TestPairwise_SectorURLPortIsIgnored(t *testing.T) {
	t.Parallel()
	g := subject.Pairwise(fixedSalt())
	withPort, err := g.Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: "port-user",
		Client: &store.Client{
			ID:                  "client-port",
			SectorIdentifierURI: "https://sector.example:8443/redirects.json",
		},
	})
	if err != nil {
		t.Fatalf("withPort Generate: %v", err)
	}
	withoutPort, err := g.Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: "port-user",
		Client: &store.Client{
			ID:                  "client-no-port",
			SectorIdentifierURI: "https://sector.example/redirects.json",
		},
	})
	if err != nil {
		t.Fatalf("withoutPort Generate: %v", err)
	}
	if withPort != withoutPort {
		t.Fatalf("sector port affected output: withPort=%q withoutPort=%q", withPort, withoutPort)
	}
}

func TestPairwise_OutputIsBase64URLNoPad(t *testing.T) {
	t.Parallel()
	out, err := subject.Pairwise(fixedSalt()).Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: "user-format",
		Client: &store.Client{
			ID:                  "client-format",
			SectorIdentifierURI: "https://format.example",
		},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	s := string(out)
	if strings.ContainsAny(s, "+/=") {
		t.Fatalf("subject %q contains non-URL-safe characters", s)
	}
	// SHA-256 → 32 bytes → 43 chars base64url-no-pad.
	if len(s) != 43 {
		t.Fatalf("subject length = %d, want 43", len(s))
	}
}
