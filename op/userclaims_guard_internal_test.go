package op

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func TestClaimValueIs(t *testing.T) {
	t.Parallel()

	type label string
	type postal struct {
		Locality string `json:"locality"`
	}
	str := "x"
	cases := []struct {
		name string
		kind claimKind
		v    any
		want bool
	}{
		{"string", claimString, "a", true},
		{"named string", claimString, label("a"), true},
		{"pointer to string", claimString, &str, true},
		{"int as string", claimString, 1, false},
		{"nil as string", claimString, nil, false},
		{"bool", claimBool, true, true},
		{"TINYINT as bool", claimBool, int64(1), false},
		{"string as bool", claimBool, "false", false},
		{"int64 number", claimNumber, int64(1), true},
		{"float number", claimNumber, 1.5, true},
		{"json.Number", claimNumber, json.Number("12"), true},
		{"time.Time as number", claimNumber, time.Unix(0, 0), false},
		{"string as number", claimNumber, "12", false},
		{"map object", claimObject, map[string]any{"locality": "x"}, true},
		{"string map object", claimObject, map[string]string{"locality": "x"}, true},
		{"struct object", claimObject, postal{Locality: "x"}, true},
		{"time.Time as object", claimObject, time.Unix(0, 0), false},
		{"string as object", claimObject, "1 Main St", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := claimValueIs(tc.kind, tc.v); got != tc.want {
				t.Fatalf("claimValueIs(%v, %#v) = %v, want %v", tc.kind, tc.v, got, tc.want)
			}
		})
	}
}

// TestClaimTypeGuard_DropsAndWarnsOnce pins that a mistyped standard claim
// is left out, that custom and well-typed claims pass, that the backing
// map is not mutated, and that the warning fires once per claim name.
func TestClaimTypeGuard_DropsAndWarnsOnce(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backend := inmem.New()
	claims := map[string]any{
		"email":          "a@example.com",
		"email_verified": int64(0),
		"tenant":         int64(7),
	}
	backend.PutUser(ctx, &store.User{Subject: "u1", Claims: claims})

	var buf bytes.Buffer
	g := newClaimTypeGuard(backend.Users(), slog.New(slog.NewTextHandler(&buf, nil)))
	for range 2 {
		u, err := g.FindBySubject(ctx, "u1")
		if err != nil {
			t.Fatalf("FindBySubject: %v", err)
		}
		if _, ok := u.Claims["email_verified"]; ok {
			t.Fatalf("mistyped email_verified released: %v", u.Claims)
		}
		if u.Claims["email"] != "a@example.com" || u.Claims["tenant"] != int64(7) {
			t.Fatalf("well-typed or custom claim lost: %v", u.Claims)
		}
	}
	if _, ok := claims["email_verified"]; !ok {
		t.Fatal("guard mutated the store's claim map")
	}
	out := buf.String()
	if got := strings.Count(out, "level=WARN"); got != 1 {
		t.Fatalf("WARN lines = %d, want 1; got:\n%s", got, out)
	}
	if !strings.Contains(out, "claim=email_verified") || !strings.Contains(out, "go_type=int64") {
		t.Fatalf("warning does not name the claim and type; got:\n%s", out)
	}
}

func TestClaimTypeGuard_PassesNotFound(t *testing.T) {
	t.Parallel()

	g := newClaimTypeGuard(inmem.New().Users(), nil)
	if _, err := g.FindBySubject(context.Background(), "missing"); err == nil {
		t.Fatal("FindBySubject found a subject that does not exist")
	}
}
