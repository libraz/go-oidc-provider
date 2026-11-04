package op_test

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// newWithInfoLog builds a provider and returns everything it logged at INFO
// and above on the operational logger.
func newWithInfoLog(tb testing.TB, opts ...op.Option) (string, error) {
	tb.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	_, err := op.New(append(opts, op.WithLogger(logger))...)
	return buf.String(), err
}

// TestWithAllowPrivateNetwork_RejectsEmptyAndUnknownTargets pins the closed
// enum: an empty list and a value outside the declared set fail op.New
// instead of silently opening nothing.
func TestWithAllowPrivateNetwork_RejectsEmptyAndUnknownTargets(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		opt  op.Option
		want string
	}{
		{"no targets", op.WithAllowPrivateNetwork(), "at least one OutboundTarget"},
		{"zero value", op.WithAllowPrivateNetwork(op.OutboundTarget(0)), "unknown OutboundTarget(0)"},
		{"out of range", op.WithAllowPrivateNetwork(op.OutboundTarget(200)), "unknown OutboundTarget(200)"},
		{"unknown after a valid one", op.WithAllowPrivateNetwork(op.OutboundJWKS, op.OutboundTarget(99)), "unknown OutboundTarget(99)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOpts(t), tc.opt)...)
			if err == nil {
				t.Fatal("op.New accepted the option")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestWithAllowPrivateNetwork_RepeatedCallsUnite pins that the targets of
// several calls are united, that repeating a target is a no-op, and that
// each opened target is announced on its own startup line.
func TestWithAllowPrivateNetwork_RepeatedCallsUnite(t *testing.T) {
	t.Parallel()

	logged, err := newWithInfoLog(t, append(validBaseOpts(t),
		op.WithAllowPrivateNetwork(op.OutboundJWKS),
		op.WithAllowPrivateNetwork(op.OutboundBackchannel, op.OutboundJWKS),
		op.WithAllowPrivateNetwork(op.OutboundSharedSignals),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	for _, target := range []string{"OutboundJWKS", "OutboundBackchannel", "OutboundSharedSignals"} {
		want := "WithAllowPrivateNetwork(op." + target + ") is enabled"
		if got := strings.Count(logged, want); got != 1 {
			t.Errorf("startup log carries %q %d times, want once; log:\n%s", want, got, logged)
		}
	}
	for _, target := range []string{"OutboundJAR", "OutboundSector", "OutboundClientIDMetadata"} {
		if strings.Contains(logged, "WithAllowPrivateNetwork(op."+target+")") {
			t.Errorf("target %s was never listed but is logged as open; log:\n%s", target, logged)
		}
	}
}

// TestWithAllowPrivateNetwork_EveryTargetIsAccepted guards the enum against
// a constant that no option branch handles.
func TestWithAllowPrivateNetwork_EveryTargetIsAccepted(t *testing.T) {
	t.Parallel()

	all := []op.OutboundTarget{
		op.OutboundJWKS, op.OutboundJAR, op.OutboundSector,
		op.OutboundClientIDMetadata, op.OutboundBackchannel, op.OutboundSharedSignals,
	}
	logged, err := newWithInfoLog(t, append(validBaseOpts(t), op.WithAllowPrivateNetwork(all...))...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	for _, target := range all {
		if !strings.Contains(logged, "WithAllowPrivateNetwork(op."+target.String()+")") {
			t.Errorf("no startup line for %s; log:\n%s", target, logged)
		}
	}
}

// TestWithAllowInsecureOutboundForDev_AcceptsOnlyDeliveryTargets pins the
// two targets the dev opt-out exists for and rejects the rest.
func TestWithAllowInsecureOutboundForDev_AcceptsOnlyDeliveryTargets(t *testing.T) {
	t.Parallel()

	for _, target := range []op.OutboundTarget{op.OutboundJWKS, op.OutboundJAR, op.OutboundSector, op.OutboundClientIDMetadata, op.OutboundTarget(77)} {
		t.Run(target.String(), func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOpts(t), op.WithIssuer(devIssuer), op.WithAllowInsecureOutboundForDev(target))...)
			if err == nil || !strings.Contains(err.Error(), "accepts only OutboundBackchannel and OutboundSharedSignals") {
				t.Fatalf("op.New err = %v, want the target restriction", err)
			}
		})
	}

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		_, err := op.New(append(validBaseOpts(t), op.WithIssuer(devIssuer), op.WithAllowInsecureOutboundForDev())...)
		if err == nil || !strings.Contains(err.Error(), "at least one OutboundTarget") {
			t.Fatalf("op.New err = %v, want the empty-list error", err)
		}
	})
}

// TestWithAllowInsecureOutboundForDev_RequiresDevelopmentIssuer keeps the
// dev-issuer requirement for each accepted target, and names the call in
// the refusal so the operator knows what to remove.
func TestWithAllowInsecureOutboundForDev_RequiresDevelopmentIssuer(t *testing.T) {
	t.Parallel()

	for _, target := range []op.OutboundTarget{op.OutboundBackchannel, op.OutboundSharedSignals} {
		t.Run(target.String(), func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOpts(t), op.WithIssuer(validIssuer), op.WithAllowInsecureOutboundForDev(target))...)
			if err == nil {
				t.Fatal("op.New accepted a dev opt-out on a public issuer")
			}
			if want := "WithAllowInsecureOutboundForDev(op." + target.String() + ") requires a development issuer"; !strings.Contains(err.Error(), want) {
				t.Errorf("err = %v, want it to contain %q", err, want)
			}
		})
	}
}

// outboundOptionMatrixRow is one combination of the option surface.
type outboundOptionMatrixRow struct {
	private   []op.OutboundTarget // WithAllowPrivateNetwork arguments; nil leaves the call out
	emptyCall bool                // call WithAllowPrivateNetwork with no arguments
	insecure  []op.OutboundTarget // WithAllowInsecureOutboundForDev arguments; nil leaves the call out
	issuer    string
}

// TestOutboundOptions_PairwiseMatrix drives WithAllowPrivateNetwork x
// WithAllowInsecureOutboundForDev x issuer kind through op.New.
//
// The factors are:
//
//	A  WithAllowPrivateNetwork  : 0 one target, 1 several targets, 2 empty call, 3 unknown target
//	B  WithAllowInsecureOutboundForDev : 0 absent, 1 Backchannel, 2 Backchannel+SharedSignals, 3 JWKS (not accepted)
//	C  issuer                   : 0 public https, 1 loopback IP over http, 2 .test development host
//
// The 16 rows enumerate every (A, B) pair and set C = (A + B) mod 3, which
// puts every (A, C) and every (B, C) pair into the set as well: the table is
// a full pairwise cover of the 4 x 4 x 3 space. The expected outcome follows
// from the three rules the options document: an empty or unknown
// WithAllowPrivateNetwork fails, a non-delivery target for the insecure
// opt-out fails, and an accepted insecure opt-out fails on a public issuer.
func TestOutboundOptions_PairwiseMatrix(t *testing.T) {
	t.Parallel()

	aVals := []func(*outboundOptionMatrixRow){
		func(r *outboundOptionMatrixRow) { r.private = []op.OutboundTarget{op.OutboundJWKS} },
		func(r *outboundOptionMatrixRow) {
			r.private = []op.OutboundTarget{op.OutboundJAR, op.OutboundSector, op.OutboundClientIDMetadata}
		},
		func(r *outboundOptionMatrixRow) { r.emptyCall = true },
		func(r *outboundOptionMatrixRow) { r.private = []op.OutboundTarget{op.OutboundTarget(99)} },
	}
	bVals := []func(*outboundOptionMatrixRow){
		func(*outboundOptionMatrixRow) {},
		func(r *outboundOptionMatrixRow) { r.insecure = []op.OutboundTarget{op.OutboundBackchannel} },
		func(r *outboundOptionMatrixRow) {
			r.insecure = []op.OutboundTarget{op.OutboundBackchannel, op.OutboundSharedSignals}
		},
		func(r *outboundOptionMatrixRow) { r.insecure = []op.OutboundTarget{op.OutboundJWKS} },
	}
	issuers := []string{validIssuer, "http://127.0.0.1:8080", devIssuer}

	for a := range aVals {
		for b := range bVals {
			c := (a + b) % 3
			t.Run(strings.Join([]string{"A" + string(rune('0'+a)), "B" + string(rune('0'+b)), "C" + string(rune('0'+c))}, "-"), func(t *testing.T) {
				t.Parallel()
				row := outboundOptionMatrixRow{issuer: issuers[c]}
				aVals[a](&row)
				bVals[b](&row)

				opts := append(validBaseOpts(t), op.WithIssuer(row.issuer))
				switch {
				case row.emptyCall:
					opts = append(opts, op.WithAllowPrivateNetwork())
				case row.private != nil:
					opts = append(opts, op.WithAllowPrivateNetwork(row.private...))
				}
				if row.insecure != nil {
					opts = append(opts, op.WithAllowInsecureOutboundForDev(row.insecure...))
				}

				wantErr := a >= 2 || b == 3 || (b != 0 && c == 0)
				_, err := op.New(opts...)
				if (err != nil) != wantErr {
					t.Fatalf("op.New err = %v, wantErr = %v (private=%v empty=%v insecure=%v issuer=%s)",
						err, wantErr, row.private, row.emptyCall, row.insecure, row.issuer)
				}
			})
		}
	}
}

// TestWithAllowLocalhostIssuerForDev pins the issuer half of the old
// localhost opt-in: it admits an http://localhost issuer, it is refused for
// any other issuer so it cannot ride along into a real deployment, and the
// redirect_uri option alone does not admit a localhost issuer.
func TestWithAllowLocalhostIssuerForDev(t *testing.T) {
	t.Parallel()

	const localhostIssuer = "http://localhost:8080"

	t.Run("admits http localhost", func(t *testing.T) {
		t.Parallel()
		if _, err := op.New(append(validBaseOpts(t), op.WithIssuer(localhostIssuer), op.WithAllowLocalhostIssuerForDev())...); err != nil {
			t.Fatalf("op.New: %v", err)
		}
	})

	for _, issuer := range []string{
		validIssuer,                // public https
		"http://127.0.0.1:8080",    // loopback literal needs no opt-in
		"https://localhost:8443",   // https localhost needs no opt-in either
		"http://localhost.example", // a lookalike host
	} {
		t.Run("refused for "+issuer, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOpts(t), op.WithIssuer(issuer), op.WithAllowLocalhostIssuerForDev())...)
			if err == nil {
				t.Fatalf("op.New accepted WithAllowLocalhostIssuerForDev with issuer %s", issuer)
			}
			if errors.Is(err, op.ErrIssuerInvalid) {
				return // the issuer itself was malformed; also a refusal
			}
			if !strings.Contains(err.Error(), "WithAllowLocalhostIssuerForDev requires an http issuer on the host localhost") {
				t.Errorf("err = %v, want the issuer-pairing refusal", err)
			}
		})
	}

	t.Run("redirect option does not admit the issuer", func(t *testing.T) {
		t.Parallel()
		_, err := op.New(append(validBaseOpts(t), op.WithIssuer(localhostIssuer), op.WithAllowLocalhostRedirectURIs())...)
		if !errors.Is(err, op.ErrIssuerInvalid) {
			t.Fatalf("op.New err = %v, want ErrIssuerInvalid", err)
		}
	})

	t.Run("logs a warning", func(t *testing.T) {
		t.Parallel()
		logged, err := newWithInfoLog(t, append(validBaseOpts(t), op.WithIssuer(localhostIssuer), op.WithAllowLocalhostIssuerForDev())...)
		if err != nil {
			t.Fatalf("op.New: %v", err)
		}
		if !strings.Contains(logged, "WithAllowLocalhostIssuerForDev is a development option") {
			t.Errorf("no development warning; log:\n%s", logged)
		}
	})
}
