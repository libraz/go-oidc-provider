package op_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestErrorIs_SentinelsAreDistinct fixes the contract that two
// configuration-class sentinels which happen to share an OAuth-style
// Code MUST NOT be interchangeable under [errors.Is]. The matcher uses
// pointer identity, so [op.ErrIssuerRequired] and [op.ErrStoreRequired]
// — both Code "configuration_error" — must not collide.
func TestErrorIs_SentinelsAreDistinct(t *testing.T) {
	t.Parallel()

	if errors.Is(op.ErrIssuerRequired, op.ErrStoreRequired) {
		t.Fatal("ErrIssuerRequired must not match ErrStoreRequired under errors.Is")
	}
	if errors.Is(op.ErrStoreRequired, op.ErrIssuerRequired) {
		t.Fatal("ErrStoreRequired must not match ErrIssuerRequired under errors.Is")
	}
	if errors.Is(op.ErrKeysetRequired, op.ErrIssuerRequired) {
		t.Fatal("ErrKeysetRequired must not match ErrIssuerRequired under errors.Is")
	}
	if !errors.Is(op.ErrIssuerRequired, op.ErrIssuerRequired) {
		t.Fatal("ErrIssuerRequired must match itself under errors.Is")
	}
}

// TestErrorIs_CodeClassPredicatesUnaffected confirms that dropping the
// code-only Is shim did not regress [op.IsClientError] /
// [op.IsServerError]: those predicates inspect Code on a wrapped
// *Error via [errors.As] and stay independent of pointer identity.
func TestErrorIs_CodeClassPredicatesUnaffected(t *testing.T) {
	t.Parallel()

	if !op.IsServerError(op.ErrIssuerRequired) {
		t.Fatal("IsServerError must classify ErrIssuerRequired (configuration_error)")
	}
	if !op.IsServerError(op.ErrStoreRequired) {
		t.Fatal("IsServerError must classify ErrStoreRequired (configuration_error)")
	}
	if op.IsClientError(op.ErrIssuerRequired) {
		t.Fatal("IsClientError must not classify ErrIssuerRequired")
	}
}

// TestConstructionErrors_ClassPredicatesPartition pins the invariant
// that every construction-time failure the op package surfaces is a
// [*op.Error] whose Code lands in exactly one of the two published
// classes: [op.IsServerError] and [op.IsClientError] MUST disagree on
// it. An untyped error (a bare errors.New, or an internal error passed
// through unwrapped) makes both predicates report false, which leaves an
// embedder that branches on them with no branch to take — the failure is
// invisible to the very API the library offers for triage.
//
// Each row is one exit path out of the construction surface. A new
// fallible option, validator, or builder stage gets a row here; the row
// is what makes an untyped return fail the suite rather than ship.
func TestConstructionErrors_ClassPredicatesPartition(t *testing.T) {
	t.Parallel()

	// overlongLocale exceeds the internal tag-length bound, so tag
	// canonicalisation refuses it. It is the only way to reach the
	// bundle constructor's own rejection from the public surface.
	overlongLocale := op.Locale(strings.Repeat("a", 64))

	cases := []struct {
		name string
		fail func(tb testing.TB) error
	}{
		{"missing_issuer", func(testing.TB) error {
			_, err := op.New(op.WithStore(stubStore{}))
			return err
		}},
		{"invalid_issuer", func(tb testing.TB) error {
			_, err := op.New(op.WithIssuer("https://idp.example.com/"), op.WithStore(stubStore{}),
				op.WithKeyset(validKeyset(tb)))
			return err
		}},
		{"missing_store", func(testing.TB) error {
			_, err := op.New(op.WithIssuer(validIssuer))
			return err
		}},
		{"missing_keyset", func(testing.TB) error {
			_, err := op.New(op.WithIssuer(validIssuer), op.WithStore(stubStore{}))
			return err
		}},
		{"missing_cookie_keys", func(tb testing.TB) error {
			_, err := op.New(op.WithIssuer(validIssuer), op.WithStore(stubStore{}),
				op.WithKeyset(validKeyset(tb)), fixtureAuthenticator())
			return err
		}},
		{"custom_grant_nil", func(tb testing.TB) error {
			_, err := op.New(append(validBaseOpts(tb), op.WithCustomGrant(nil))...)
			return err
		}},
		{"locale_bundle_empty_locale", func(testing.TB) error {
			_, err := op.LocaleBundleFromMap("", map[string]string{})
			return err
		}},
		{"locale_bundle_unusable_locale", func(testing.TB) error {
			_, err := op.LocaleBundleFromMap(overlongLocale, map[string]string{})
			return err
		}},
		{"locale_bundle_zero_value", func(tb testing.TB) error {
			_, err := op.New(append(validBaseOpts(tb), op.WithLocale(op.LocaleBundle{}))...)
			return err
		}},
		{"default_locale_empty", func(tb testing.TB) error {
			_, err := op.New(append(validBaseOpts(tb), op.WithDefaultLocale(""))...)
			return err
		}},
		{"default_locale_unusable", func(tb testing.TB) error {
			_, err := op.New(append(validBaseOpts(tb), op.WithDefaultLocale("   "))...)
			return err
		}},
		{"default_locale_unregistered", func(tb testing.TB) error {
			_, err := op.New(append(validBaseOpts(tb), op.WithDefaultLocale("fr"))...)
			return err
		}},
		{"preferred_locale_store_nil", func(tb testing.TB) error {
			_, err := op.New(append(validBaseOpts(tb), op.WithPreferredLocaleStore(nil))...)
			return err
		}},
		{"advertised_locale_unregistered", func(tb testing.TB) error {
			_, err := op.New(append(validBaseOpts(tb), op.WithDiscoveryMetadata(op.DiscoveryMetadata{
				UILocalesSupported: []string{"fr"},
			}))...)
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.fail(t)
			if err == nil {
				t.Fatal("construction path must fail, got nil error")
			}
			var typed *op.Error
			if !errors.As(err, &typed) {
				t.Fatalf("construction error must be a *op.Error, got %T: %v", err, err)
			}
			server, client := op.IsServerError(err), op.IsClientError(err)
			if server == client {
				t.Fatalf("IsServerError=%v IsClientError=%v: the two classes must partition "+
					"code %q (err: %v)", server, client, typed.Code, err)
			}
		})
	}
}
