package op

import (
	"context"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/subject"
)

// projectorSalt returns a 32-byte salt the option-site validator
// accepts. The bytes are deterministic so test failures replay
// identically across runs.
func projectorSalt() []byte {
	salt := make([]byte, subject.MinSaltLength)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	return salt
}

// TestBuildSubjectProjector_PairwisePerClientDispatch pins the OIDC
// Core 1.0 §8 invariant that an OP with [WithPairwiseSubject] active
// MUST issue pairwise sub values only to clients whose
// [store.Client.SubjectType] is "pairwise"; clients registered as
// "public" (or with the field empty, which RFC 7591 §2 / the
// registration endpoint default to "public") MUST receive the
// non-pairwise sub. The test drives the projector — the closure the
// authorize handler invokes at code emission — so the assertion
// covers the production code path rather than the bare generator
// available through [Provider.SubjectGenerator].
func TestBuildSubjectProjector_PairwisePerClientDispatch(t *testing.T) {
	t.Parallel()
	cfg := &config{
		pairwiseSalt:     projectorSalt(),
		subjectGenerator: newPairwiseGeneratorFromSalt(projectorSalt()),
	}
	projector := buildSubjectProjector(cfg)

	publicClient := &store.Client{
		ID:           "public-client",
		SubjectType:  "public",
		RedirectURIs: []string{"https://public.example.com/cb"},
	}
	pairwiseClient := &store.Client{
		ID:           "pairwise-client",
		SubjectType:  "pairwise",
		RedirectURIs: []string{"https://pairwise.example.com/cb"},
	}
	emptySubjectTypeClient := &store.Client{
		ID:           "empty-subject-type",
		RedirectURIs: []string{"https://empty.example.com/cb"},
	}

	const internalUser = "user-internal-42"
	ctx := context.Background()

	publicSub, err := projector(ctx, internalUser, publicClient)
	if err != nil {
		t.Fatalf("projector(public): %v", err)
	}
	if publicSub != internalUser {
		t.Fatalf("public client sub = %q, want passthrough %q", publicSub, internalUser)
	}

	emptySub, err := projector(ctx, internalUser, emptySubjectTypeClient)
	if err != nil {
		t.Fatalf("projector(empty subject_type): %v", err)
	}
	if emptySub != internalUser {
		t.Fatalf("empty-subject_type client sub = %q, want passthrough %q (default treats empty as public)", emptySub, internalUser)
	}

	pairwiseSub, err := projector(ctx, internalUser, pairwiseClient)
	if err != nil {
		t.Fatalf("projector(pairwise): %v", err)
	}
	if pairwiseSub == internalUser {
		t.Fatalf("pairwise client sub = %q, want hashed value distinct from raw %q", pairwiseSub, internalUser)
	}
	if pairwiseSub == publicSub {
		t.Fatalf("pairwise client sub == public client sub (%q); pairwise dispatch failed", pairwiseSub)
	}
}

// TestBuildSubjectProjector_PairwiseDeterminismWithinSector pins the
// OIDC Core 1.0 §8.1 determinism property: two pairwise clients that
// resolve to the same sector (same SectorIdentifierURI host) MUST
// receive the same sub for a given internal user. This is the privacy
// contract that lets a multi-RP product family correlate users across
// its own brands without leaking the underlying identifier.
func TestBuildSubjectProjector_PairwiseDeterminismWithinSector(t *testing.T) {
	t.Parallel()
	cfg := &config{
		pairwiseSalt:     projectorSalt(),
		subjectGenerator: newPairwiseGeneratorFromSalt(projectorSalt()),
	}
	projector := buildSubjectProjector(cfg)

	clientA := &store.Client{
		ID:                  "rp-a",
		SubjectType:         "pairwise",
		SectorIdentifierURI: "https://sector.example.com/sector.json",
		RedirectURIs:        []string{"https://rp-a.example.com/cb"},
	}
	clientB := &store.Client{
		ID:                  "rp-b",
		SubjectType:         "pairwise",
		SectorIdentifierURI: "https://sector.example.com/sector.json",
		RedirectURIs:        []string{"https://rp-b.example.com/cb"},
	}

	ctx := context.Background()
	subA, err := projector(ctx, "user-7", clientA)
	if err != nil {
		t.Fatalf("projector(rp-a): %v", err)
	}
	subB, err := projector(ctx, "user-7", clientB)
	if err != nil {
		t.Fatalf("projector(rp-b): %v", err)
	}
	if subA != subB {
		t.Fatalf("same-sector pairwise sub differed: rp-a=%q rp-b=%q", subA, subB)
	}
}

// TestBuildSubjectProjector_PairwisePrivacyAcrossSectors pins the
// OIDC Core 1.0 §8.1 privacy property: two pairwise clients in
// distinct sectors MUST receive different sub values for the same
// internal user. This is what stops an RP in sector A from
// correlating its users with an RP in sector B.
func TestBuildSubjectProjector_PairwisePrivacyAcrossSectors(t *testing.T) {
	t.Parallel()
	cfg := &config{
		pairwiseSalt:     projectorSalt(),
		subjectGenerator: newPairwiseGeneratorFromSalt(projectorSalt()),
	}
	projector := buildSubjectProjector(cfg)

	tenantA := &store.Client{
		ID:           "tenant-a",
		SubjectType:  "pairwise",
		RedirectURIs: []string{"https://tenant-a.example.com/cb"},
	}
	tenantB := &store.Client{
		ID:           "tenant-b",
		SubjectType:  "pairwise",
		RedirectURIs: []string{"https://tenant-b.example.com/cb"},
	}

	ctx := context.Background()
	subA, err := projector(ctx, "user-9", tenantA)
	if err != nil {
		t.Fatalf("projector(tenant-a): %v", err)
	}
	subB, err := projector(ctx, "user-9", tenantB)
	if err != nil {
		t.Fatalf("projector(tenant-b): %v", err)
	}
	if subA == subB {
		t.Fatalf("cross-sector pairwise sub matched (%q); privacy property violated", subA)
	}
}

// TestBuildSubjectProjector_CustomGeneratorBypassesDispatch pins the
// custom-generator contract: when an embedder supplies a
// [SubjectGenerator] through [WithSubjectGenerator], the projector
// hands every client to that generator without inspecting
// [store.Client.SubjectType]. Embedders who need bespoke per-client
// dispatch own the routing inside their generator.
func TestBuildSubjectProjector_CustomGeneratorBypassesDispatch(t *testing.T) {
	t.Parallel()

	stub := &recordingGenerator{}
	cfg := &config{
		subjectGenerator:       stub,
		subjectGeneratorSource: "WithSubjectGenerator",
	}
	projector := buildSubjectProjector(cfg)

	clients := []*store.Client{
		{ID: "c-public", SubjectType: "public"},
		{ID: "c-pairwise", SubjectType: "pairwise"},
		{ID: "c-empty"},
	}
	ctx := context.Background()
	for i, c := range clients {
		if _, err := projector(ctx, "user-x", c); err != nil {
			t.Fatalf("projector(%s): %v", c.ID, err)
		}
		if got := len(stub.seenIDs); got != i+1 {
			t.Fatalf("after client %s: stub call count = %d, want %d", c.ID, got, i+1)
		}
	}
	want := []string{"c-public", "c-pairwise", "c-empty"}
	for i, id := range want {
		if stub.seenIDs[i] != id {
			t.Fatalf("stub call %d saw client %q, want %q", i, stub.seenIDs[i], id)
		}
	}
}

// TestBuildSubjectProjector_DefaultPathPassthrough pins the v0.x
// default: without any subject option every client receives the
// UUIDv7 passthrough regardless of [store.Client.SubjectType].
// This preserves backwards compatibility for embedders who never
// touched the subject options.
func TestBuildSubjectProjector_DefaultPathPassthrough(t *testing.T) {
	t.Parallel()
	cfg := &config{}
	projector := buildSubjectProjector(cfg)

	cases := []*store.Client{
		{ID: "c1", SubjectType: "public"},
		{ID: "c2", SubjectType: "pairwise"},
		{ID: "c3"},
	}
	ctx := context.Background()
	for _, c := range cases {
		got, err := projector(ctx, "user-default", c)
		if err != nil {
			t.Fatalf("projector(%s): %v", c.ID, err)
		}
		if got != "user-default" {
			t.Fatalf("client %s got sub=%q, want passthrough user-default", c.ID, got)
		}
	}
}

// recordingGenerator is a stub [SubjectGenerator] that records the
// client IDs it was invoked against. The custom-generator dispatch
// test uses it to assert that the projector hands every client to the
// embedder-supplied generator without per-client routing.
type recordingGenerator struct {
	seenIDs []string
}

func (r *recordingGenerator) Generate(_ context.Context, in subject.GeneratorInput) (subject.Subject, error) {
	id := ""
	if in.Client != nil {
		id = in.Client.ID
	}
	r.seenIDs = append(r.seenIDs, id)
	return subject.Subject("stub-" + id), nil
}
