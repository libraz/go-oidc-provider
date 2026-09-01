package main

import (
	"strings"
	"testing"
)

// row builds a minimal in-scope row carrying one behaviour sentence.
func row(id, behaviour string) *Row {
	return &Row{ID: id, Severity: "P0", Spec: "s", Behaviour: behaviour, Status: "active"}
}

// TestInferShapeReadsPresenceByDefault pins the conservative direction:
// a row the patterns cannot read counts as presence, so an unreadable
// row makes a file look thinner rather than richer.
func TestInferShapeReadsPresenceByDefault(t *testing.T) {
	t.Parallel()
	cases := []string{
		"The issued ID Token MUST include auth_time as numeric epoch seconds.",
		"Mandatory fields MUST be present: issuer, authorization_endpoint, token_endpoint.",
		"The response MUST NOT carry a cnf claim.",
		"Some sentence with no signal whatsoever.",
	}
	for _, behaviour := range cases {
		if got := row("X-001", behaviour).InferShape(); got != ShapePresence {
			t.Errorf("InferShape(%q) = %q, want presence", behaviour, got)
		}
	}
}

// TestInferShapeRecognisesValueOrderIdentity covers the phrasings the
// catalog actually uses, so a genuinely value-shaped row is not
// miscounted as presence and does not need a redundant declaration.
func TestInferShapeRecognisesValueOrderIdentity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		behaviour string
		want      Shape
	}{
		{"iss equals the OP's configured Issuer Identifier.", ShapeValue},
		{"GET and POST MUST behave identically when form_post is selected.", ShapeValue},
		{"All other payload fields match the standard non-pairwise case.", ShapeValue},
		{"The payload MUST be rendered as escaped text only.", ShapeValue},
		{"The refresh token MUST NOT be reused after rotation.", ShapeOrder},
		{"The code is consumed before the token response is assembled.", ShapeOrder},
		{"The access token MUST be bound to the same client that requested it.", ShapeIdentity},
	}
	for _, c := range cases {
		if got := row("X-001", c.behaviour).InferShape(); got != c.want {
			t.Errorf("InferShape(%q) = %q, want %q", c.behaviour, got, c.want)
		}
	}
}

// TestInferShapeHonoursAnExplicitDeclaration keeps the escape hatch
// working for prose the patterns cannot read — the case TFJ-028 and
// RMO-002 are in.
func TestInferShapeHonoursAnExplicitDeclaration(t *testing.T) {
	t.Parallel()
	r := row("X-001", "A sentence with no signal whatsoever.")
	r.Shape = string(ShapeValue)
	if got := r.InferShape(); got != ShapeValue {
		t.Errorf("InferShape ignored the declared shape, got %q", got)
	}
	if !r.ShapeDeclared() {
		t.Error("ShapeDeclared reported false for a row that declares one")
	}
}

// TestCheckShapesFlagsAPresenceOnlyFile is the case the gate exists
// for: every row says a claim appears, so an implementation that emits
// every claim with the wrong contents satisfies the file while coverage
// reads 100%.
func TestCheckShapesFlagsAPresenceOnlyFile(t *testing.T) {
	t.Parallel()
	cat := &Catalog{Files: []*FeatureFile{{
		Feature: "thin",
		Rows: []*Row{
			row("T-001", "The ID Token MUST include auth_time."),
			row("T-002", "The ID Token MUST include acr."),
			row("T-003", "The ID Token MUST include amr."),
		},
	}}}
	got := CheckShapes(cat)
	if len(got) != 1 {
		t.Fatalf("CheckShapes returned %d violations %v, want exactly 1", len(got), got)
	}
	if got[0].Feature != "thin" || got[0].InScope != 3 {
		t.Errorf("violation = %+v, want thin/3", got[0])
	}
}

// TestCheckShapesAcceptsOneValueRow keeps the gate at the threshold it
// claims: the demand is that a file say *something* beyond presence,
// not that it be mostly value-shaped.
func TestCheckShapesAcceptsOneValueRow(t *testing.T) {
	t.Parallel()
	cat := &Catalog{Files: []*FeatureFile{{
		Feature: "thin",
		Rows: []*Row{
			row("T-001", "The ID Token MUST include auth_time."),
			row("T-002", "The ID Token MUST include acr."),
			row("T-003", "auth_time equals the time the credential chain ran."),
		},
	}}}
	if got := CheckShapes(cat); len(got) != 0 {
		t.Errorf("one value row should clear the gate, got %v", got)
	}
}

// TestCheckShapesIgnoresOutOfScopeRows stops a file from diluting its
// own profile: an out-of-scope row asserts nothing, so counting it
// would let a file pass by declaring rows away.
func TestCheckShapesIgnoresOutOfScopeRows(t *testing.T) {
	t.Parallel()
	valueRow := row("T-004", "auth_time equals the time the credential chain ran.")
	valueRow.Status = "out-of-scope"
	valueRow.OutOfScopeReason = "not shipped"
	cat := &Catalog{Files: []*FeatureFile{{
		Feature: "thin",
		Rows: []*Row{
			row("T-001", "The ID Token MUST include auth_time."),
			row("T-002", "The ID Token MUST include acr."),
			row("T-003", "The ID Token MUST include amr."),
			valueRow,
		},
	}}}
	got := CheckShapes(cat)
	if len(got) != 1 {
		t.Fatalf("an out-of-scope value row must not clear the gate, got %v", got)
	}
	if got[0].InScope != 3 {
		t.Errorf("in-scope count = %d, want 3 (the out-of-scope row excluded)", got[0].InScope)
	}
}

// TestCheckShapesRespectsTheFloor keeps a two-row file from being
// judged on a ratio that says more about its size than its rows.
func TestCheckShapesRespectsTheFloor(t *testing.T) {
	t.Parallel()
	cat := &Catalog{Files: []*FeatureFile{{
		Feature: "tiny",
		Rows: []*Row{
			row("T-001", "The response MUST include a token."),
			row("T-002", "The response MUST include a scope."),
		},
	}}}
	if got := CheckShapes(cat); len(got) != 0 {
		t.Errorf("a file below the row floor should not be judged, got %v", got)
	}
}

// TestCheckShapesHonoursAnExemption allows a file that genuinely can
// only assert presence, provided the decision is written down.
func TestCheckShapesHonoursAnExemption(t *testing.T) {
	t.Parallel()
	cat := &Catalog{Files: []*FeatureFile{{
		Feature:           "thin",
		ShapeExemptReason: "Every row is a discovery advertisement whose value is the embedder's.",
		Rows: []*Row{
			row("T-001", "The document MUST include a."),
			row("T-002", "The document MUST include b."),
			row("T-003", "The document MUST include c."),
		},
	}}}
	if got := CheckShapes(cat); len(got) != 0 {
		t.Errorf("a recorded exemption should clear the gate, got %v", got)
	}
}

// TestCheckStaleExemptionsFlagsAnOutgrownReason closes the other
// direction, so an exemption does not outlive the condition it
// described and read as still true to the next person.
func TestCheckStaleExemptionsFlagsAnOutgrownReason(t *testing.T) {
	t.Parallel()
	cat := &Catalog{Files: []*FeatureFile{{
		Feature:           "grown",
		ShapeExemptReason: "Nothing here can pin a value.",
		Rows: []*Row{
			row("T-001", "The document MUST include a."),
			row("T-002", "The document MUST include b."),
			row("T-003", "iss equals the configured issuer."),
		},
	}}}
	got := checkStaleExemptions(cat)
	if len(got) != 1 || got[0] != "grown" {
		t.Fatalf("checkStaleExemptions = %v, want [grown]", got)
	}
}

// TestProfileOrdersThinnestFirst pins the report's purpose: the file at
// the top is the one whose coverage number says least.
func TestProfileOrdersThinnestFirst(t *testing.T) {
	t.Parallel()
	cat := &Catalog{Files: []*FeatureFile{
		{Feature: "rich", Rows: []*Row{
			row("R-001", "iss equals the configured issuer."),
			row("R-002", "sub equals the pairwise identifier."),
		}},
		{Feature: "thin", Rows: []*Row{
			row("T-001", "The document MUST include a."),
			row("T-002", "The document MUST include b."),
		}},
	}}
	got := Profile(cat)
	if len(got) != 2 {
		t.Fatalf("Profile returned %d entries, want 2", len(got))
	}
	if got[0].File.Feature != "thin" {
		t.Errorf("Profile put %q first, want the thinnest file", got[0].File.Feature)
	}
	if got[0].Ratio() != 0 || got[1].Ratio() != 1 {
		t.Errorf("ratios = %v / %v, want 0 and 1", got[0].Ratio(), got[1].Ratio())
	}
}

// TestValidateRejectsAnUnknownShape stops a misspelled value from being
// read as its own shape and quietly changing a file's profile.
func TestValidateRejectsAnUnknownShape(t *testing.T) {
	t.Parallel()
	r := row("T-001", "Something happens.")
	r.Shape = "valeu"
	got := validateRowContent("t.yaml rows (T-001)", r)
	if len(got) != 1 {
		t.Fatalf("validateRowContent = %v, want exactly one problem", got)
	}
	if !strings.Contains(got[0], "valeu") {
		t.Errorf("problem does not name the bad value: %q", got[0])
	}
}

// TestValidateAcceptsEveryDeclaredShape keeps the enum and the
// validator from drifting apart.
func TestValidateAcceptsEveryDeclaredShape(t *testing.T) {
	t.Parallel()
	for shape := range validShapes {
		r := row("T-001", "Something happens.")
		r.Shape = string(shape)
		if got := validateRowContent("t.yaml rows (T-001)", r); len(got) != 0 {
			t.Errorf("shape %q rejected: %v", shape, got)
		}
	}
}
