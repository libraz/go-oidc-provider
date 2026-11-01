package httpx_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

// TestAtEOF_ClassifiesTrailingBytes pins the helper every trailing-data
// guard shares: whitespace alone is the end of the document, anything
// else, including a stray closing delimiter, is not.
func TestAtEOF_ClassifiesTrailingBytes(t *testing.T) {
	t.Parallel()

	for body, want := range map[string]bool{
		`["x"]`:      true,
		"[\"x\"] \n": true,
		`["x"]]`:     false,
		`{"a":1}}`:   false,
		`{"a":1}]`:   false,
		`{"a":1}{}`:  false,
	} {
		dec := json.NewDecoder(strings.NewReader(body))
		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("%q: first Decode: %v", body, err)
		}
		if got := httpx.AtEOF(dec); got != want {
			t.Errorf("%q: AtEOF=%v want %v", body, got, want)
		}
	}
}
