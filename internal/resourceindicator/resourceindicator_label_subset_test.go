package resourceindicator_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/resourceindicator"
)

func TestSubsetLabelCanonicalisesBothSides(t *testing.T) {
	t.Parallel()

	if !resourceindicator.SubsetLabel(
		[]string{"HTTPS://API.EXAMPLE/foo/", "https://other.example/"},
		[]string{"https://api.example/foo", "HTTPS://OTHER.EXAMPLE"},
	) {
		t.Fatal("SubsetLabel rejected equivalent canonical resources")
	}
	if resourceindicator.SubsetLabel(
		[]string{"https://api.example", "https://extra.example"},
		[]string{"https://api.example"},
	) {
		t.Fatal("SubsetLabel accepted an audience broader than allowed")
	}
	if !resourceindicator.SubsetLabel(nil, []string{"https://api.example"}) {
		t.Fatal("empty want should be a subset")
	}
}
