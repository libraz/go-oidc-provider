package op_test

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/subject"
)

// pairwiseTestSalt returns a salt long enough for the option-site
// validator. The bytes are deterministic so a failure replays
// identically across runs.
func pairwiseTestSalt() []byte {
	salt := make([]byte, subject.MinSaltLength)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	return salt
}

// TestProviderSubjectGenerator_UnresolvedSectorMatchesCatalog drives the
// path [Provider.SubjectGenerator]'s own documentation recommends —
// admin tooling and audit reports calling Generate out of band — with a
// pairwise client that registers two redirect hosts and no
// sector_identifier_uri. OIDC Core 1.0 §5 leaves the sector
// underdetermined there, and the embedder's only actionable diagnosis is
// [op.ErrPairwiseSectorUnresolved], so that is what errors.Is must find.
func TestProviderSubjectGenerator_UnresolvedSectorMatchesCatalog(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	provider, err := op.New(append(validBaseOptsWithStore(t, st),
		op.WithPairwiseSubject(pairwiseTestSalt()),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}

	gen := provider.SubjectGenerator()
	if gen == nil {
		t.Fatal("SubjectGenerator returned nil for a pairwise provider")
	}
	sub, err := gen.Generate(context.Background(), op.SubjectGeneratorInput{
		InternalUserID: "user-63",
		Client: &store.Client{
			ID:          "multi-host-rp",
			SubjectType: "pairwise",
			RedirectURIs: []string{
				"https://alpha.example.com/cb",
				"https://beta.example.com/cb",
			},
		},
	})
	if err == nil {
		t.Fatalf("Generate returned sub=%q for an unresolvable sector, want an error", sub)
	}
	if !errors.Is(err, op.ErrPairwiseSectorUnresolved) {
		t.Errorf("errors.Is(err, op.ErrPairwiseSectorUnresolved) = false for %v", err)
	}
	if !errors.Is(err, subject.ErrSectorUnresolved) {
		t.Errorf("the originating sentinel left the chain: %v", err)
	}
	if !op.IsServerError(err) {
		t.Errorf("op.IsServerError(err) = false; an unresolvable sector is an operator fault: %v", err)
	}
	// The description is the diagnosis the catalog promises; an embedder
	// logging the error must be told what to configure.
	if !errors.Is(err, op.ErrPairwiseSectorUnresolved) || err.Error() == "" {
		t.Errorf("error carries no operator-readable message: %v", err)
	}
}

// TestProviderSubjectGenerator_EmptyInputMatchesCatalog covers the other
// built-in generator: the default passthrough refuses an empty
// InternalUserID, and [op.ErrSubjectInputEmpty] is the entry naming it.
func TestProviderSubjectGenerator_EmptyInputMatchesCatalog(t *testing.T) {
	t.Parallel()

	provider, err := op.New(validBaseOpts(t)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	_, err = provider.SubjectGenerator().Generate(context.Background(), op.SubjectGeneratorInput{})
	if err == nil {
		t.Fatal("Generate accepted an empty InternalUserID")
	}
	if !errors.Is(err, op.ErrSubjectInputEmpty) {
		t.Errorf("errors.Is(err, op.ErrSubjectInputEmpty) = false for %v", err)
	}
	if !op.IsServerError(err) {
		t.Errorf("op.IsServerError(err) = false for %v", err)
	}
}

// verbatimErrGenerator is an embedder-supplied [op.SubjectGenerator]
// whose failure is its own value, not one of the library's.
type verbatimErrGenerator struct{ err error }

func (g verbatimErrGenerator) Generate(context.Context, op.SubjectGeneratorInput) (op.Subject, error) {
	return "", g.err
}

// TestProviderSubjectGenerator_CustomGeneratorReturnedVerbatim pins the
// boundary of the bridging: a generator supplied through
// [op.WithSubjectGenerator] belongs to the embedder. The Provider hands
// back the same value — so a caller can still assert on its concrete
// type — and does not rewrite the errors it returns.
func TestProviderSubjectGenerator_CustomGeneratorReturnedVerbatim(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("embedder: directory is unreachable")
	custom := verbatimErrGenerator{err: sentinel}
	provider, err := op.New(append(validBaseOptsNoAuthn(t),
		fixtureAuthenticator(),
		op.WithSubjectGenerator(custom),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}

	got := provider.SubjectGenerator()
	if _, ok := got.(verbatimErrGenerator); !ok {
		t.Fatalf("SubjectGenerator returned %T, want the embedder's own value back", got)
	}
	_, genErr := got.Generate(context.Background(), op.SubjectGeneratorInput{InternalUserID: "u"})
	if !errors.Is(genErr, sentinel) {
		t.Errorf("embedder error was rewritten: %v", genErr)
	}
}
