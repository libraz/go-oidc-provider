package registrationendpoint

import (
	"fmt"
	"strings"
	"testing"
)

// RFC 7591 §2 requires the OP to ignore metadata it does not understand,
// and an unauthenticated caller can drive /register on an open
// deployment. "Ignore" has to mean the decoder skips those members, not
// that a second pass materialises every one of them and the result is
// dropped later: the body is attacker-sized up to the endpoint's cap, so
// a per-member cost there is a per-member cost the caller chooses.
//
// The rule is checked by the shape of the cost rather than by counting
// parses, because a parse leaves no other trace: both passes read the
// same buffer and neither is visible from the outside.

// unmodelledMemberBody returns a registration body carrying n members the
// OP does not model, alongside one it does.
func unmodelledMemberBody(n int) string {
	var b strings.Builder
	b.WriteString(`{"redirect_uris":["https://rp.example/cb"]`)
	for i := range n {
		fmt.Fprintf(&b, `,"x_unmodelled_%d":"value-%d"`, i, i)
	}
	b.WriteString("}")
	return b.String()
}

// TestParseClientMetadata_DoesNotMaterialiseUnmodelledMembers pins that
// parsing cost does not scale with the number of members the OP has no
// field for.
//
//nolint:paralleltest // testing.AllocsPerRun pins GOMAXPROCS and panics when called from a parallel test.
func TestParseClientMetadata_DoesNotMaterialiseUnmodelledMembers(t *testing.T) {
	const extraMembers = 200

	none := unmodelledMemberBody(0)
	many := unmodelledMemberBody(extraMembers)

	// Both bodies must actually parse, or the measurement below is timing
	// an error path rather than a decode.
	for name, body := range map[string]string{"none": none, "many": many} {
		if _, _, err := parseClientMetadataWithExtras(strings.NewReader(body)); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
	}

	baseline := testing.AllocsPerRun(50, func() {
		_, _, _ = parseClientMetadataWithExtras(strings.NewReader(none))
	})
	loaded := testing.AllocsPerRun(50, func() {
		_, _, _ = parseClientMetadataWithExtras(strings.NewReader(many))
	})

	// One allocation per unmodelled member is the signature of a pass that
	// keeps them; skipping them costs a constant handful for the larger
	// buffer. The bound sits an order of magnitude below the per-member
	// slope so it does not encode how encoding/json buffers its input.
	if delta := loaded - baseline; delta >= extraMembers {
		t.Errorf("parsing a body with %d unmodelled members cost %v allocations against %v for none "+
			"(delta %v): the parser is materialising members it does not model, so an "+
			"attacker-sized body is charged per member",
			extraMembers, loaded, baseline, delta)
	}
}
