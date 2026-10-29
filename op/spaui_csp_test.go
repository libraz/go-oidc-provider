package op_test

import (
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

func TestSPAUICSP(t *testing.T) {
	t.Parallel()

	rejected := map[string]string{
		"comma":        "default-src 'self', script-src 'self'",
		"control char": "default-src 'self'\x00",
		"newline":      "default-src 'self'\nscript-src 'self'",
		"form-action":  "default-src 'self'; form-action 'self'",
	}
	for name, csp := range rejected {
		t.Run("rejects "+name, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOpts(t),
				op.WithSPAUI(op.SPAUI{LoginMount: "/login", ContentSecurityPolicy: csp}),
			)...)
			if err == nil {
				t.Fatalf("expected op.New to reject ContentSecurityPolicy %q", csp)
			}
			if !strings.Contains(err.Error(), "ContentSecurityPolicy") {
				t.Errorf("err = %v, want it to name ContentSecurityPolicy", err)
			}
		})
	}

	t.Run("empty uses the default", func(t *testing.T) {
		t.Parallel()
		if _, err := op.New(append(validBaseOpts(t),
			op.WithSPAUI(op.SPAUI{LoginMount: "/login"}),
		)...); err != nil {
			t.Fatalf("op.New with empty ContentSecurityPolicy: %v", err)
		}
	})

	t.Run("valid custom value", func(t *testing.T) {
		t.Parallel()
		if _, err := op.New(append(validBaseOpts(t),
			op.WithSPAUI(op.SPAUI{
				LoginMount:            "/login",
				ContentSecurityPolicy: "default-src 'self'; frame-ancestors 'none'",
			}),
		)...); err != nil {
			t.Fatalf("op.New with a valid custom policy: %v", err)
		}
	})
}
