package jose_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

func TestDecodeAudience(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		raw     string
		want    []string
		wantErr bool
	}{
		{"absent", "", nil, false},
		{"null", "null", nil, false},
		{"empty string", `""`, nil, false},
		{"single", `"rp"`, []string{"rp"}, false},
		{"array", `["a","b"]`, []string{"a", "b"}, false},
		{"empty array", `[]`, nil, false},
		{"array keeps empty element", `["a",""]`, []string{"a", ""}, false},
		{"number", `5`, nil, true},
		{"object", `{}`, nil, true},
		{"mixed array", `["a",5]`, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := jose.DecodeAudience(json.RawMessage(tc.raw))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsTypJWT(t *testing.T) {
	t.Parallel()
	for typ, want := range map[string]bool{"JWT": true, "jwt": true, "Jwt": true, "at+jwt": false, "": false, "JWT ": false} {
		if got := jose.IsTypJWT(typ); got != want {
			t.Errorf("IsTypJWT(%q) = %v, want %v", typ, got, want)
		}
	}
}
