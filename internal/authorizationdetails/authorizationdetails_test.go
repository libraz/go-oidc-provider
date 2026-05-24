package authorizationdetails_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorizationdetails"
	"github.com/libraz/go-oidc-provider/op/store"
)

func acceptAll() map[string]authorizationdetails.Validator {
	return map[string]authorizationdetails.Validator{
		"payment_initiation":  func(context.Context, map[string]any, *store.Client) error { return nil },
		"account_information": func(context.Context, map[string]any, *store.Client) error { return nil },
	}
}

func TestCheck_AcceptsRegisteredTypes(t *testing.T) {
	t.Parallel()
	raw := `[{"type":"payment_initiation","actions":["read"]},{"type":"account_information"}]`
	got, err := authorizationdetails.Check(context.Background(), raw, &store.Client{ID: "c"}, acceptAll())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d elements want 2", len(got))
	}
	if got[0]["type"] != "payment_initiation" {
		t.Errorf("element[0].type=%v", got[0]["type"])
	}
}

func TestCheck_RejectsUnknownType(t *testing.T) {
	t.Parallel()
	_, err := authorizationdetails.Check(context.Background(), `[{"type":"unregistered"}]`, nil, acceptAll())
	if !errors.Is(err, authorizationdetails.ErrUnknownType) {
		t.Fatalf("err=%v want ErrUnknownType", err)
	}
}

func TestCheck_StructuralRejections(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		raw  string
		want error
	}{
		"not array (object)": {`{"type":"payment_initiation"}`, authorizationdetails.ErrNotArray},
		"not array (string)": {`"x"`, authorizationdetails.ErrNotArray},
		"trailing garbage":   {`[{"type":"payment_initiation"}] junk`, authorizationdetails.ErrNotArray},
		"json null":          {`null`, authorizationdetails.ErrNotArray},
		"empty array":        {`[]`, authorizationdetails.ErrEmpty},
		"null element":       {`[null]`, authorizationdetails.ErrElementNotObject},
		"scalar element":     {`[123]`, authorizationdetails.ErrNotArray},
		"type missing":       {`[{"actions":["read"]}]`, authorizationdetails.ErrTypeMissing},
		"type not string":    {`[{"type":42}]`, authorizationdetails.ErrTypeMissing},
		"type empty string":  {`[{"type":""}]`, authorizationdetails.ErrTypeMissing},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := authorizationdetails.Check(context.Background(), tc.raw, nil, acceptAll())
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want %v", err, tc.want)
			}
		})
	}
}

func TestCheck_RejectsOversize(t *testing.T) {
	t.Parallel()
	// One huge string member pushes the raw past MaxBytes.
	huge := `[{"type":"payment_initiation","blob":"` + strings.Repeat("a", authorizationdetails.MaxBytes) + `"}]`
	_, err := authorizationdetails.Check(context.Background(), huge, nil, acceptAll())
	if !errors.Is(err, authorizationdetails.ErrTooLarge) {
		t.Fatalf("err=%v want ErrTooLarge", err)
	}
}

func TestCheck_RejectsTooManyElements(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i <= authorizationdetails.MaxElements; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"type":"payment_initiation"}`)
	}
	b.WriteByte(']')
	_, err := authorizationdetails.Check(context.Background(), b.String(), nil, acceptAll())
	if !errors.Is(err, authorizationdetails.ErrTooManyElements) {
		t.Fatalf("err=%v want ErrTooManyElements", err)
	}
}

func TestCheck_PropagatesValidatorError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("missing required field")
	reg := map[string]authorizationdetails.Validator{
		"payment_initiation": func(context.Context, map[string]any, *store.Client) error { return sentinel },
	}
	_, err := authorizationdetails.Check(context.Background(), `[{"type":"payment_initiation"}]`, nil, reg)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err=%v want validator sentinel", err)
	}
	if !strings.Contains(err.Error(), "payment_initiation") {
		t.Errorf("err=%v should name the offending type", err)
	}
}

// FuzzCheck guards the parser against panics and unbounded work on
// adversarial input: malformed JSON, huge arrays, deep nesting. The
// validators accept everything so the fuzzer exercises the structural
// path, which must always return cleanly (value or typed error), never
// panic.
func FuzzCheck(f *testing.F) {
	seeds := []string{
		"", "[]", "null", "{}", `[{"type":"payment_initiation"}]`,
		`[{"type":""}]`, `[123]`, `[null]`,
		strings.Repeat("[", 5000), `[{"type":"x","a":[[[[[]]]]]}]`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	reg := acceptAll()
	f.Fuzz(func(_ *testing.T, raw string) {
		_, _ = authorizationdetails.Check(context.Background(), raw, &store.Client{ID: "c"}, reg)
	})
}
