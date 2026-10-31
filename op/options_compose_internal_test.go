package op

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// composeAdditive lists the options that take an argument yet accumulate
// rather than claim a single-valued setting. A new option that neither
// calls claimOnce / claimSlot nor appears here fails
// TestOptions_EveryOptionIsClassified.
var composeAdditive = map[string]string{
	"WithAuthorizationDetailTypes": "additive",
	"WithCORSOrigins":              "additive",
	"WithCustomGrant":              "additive",
	"WithFeature":                  "additive",
	"WithFirstPartyClients":        "additive",
	"WithInteractions":             "additive",
	"WithLoginAttemptObserver":     "additive",
	"WithProfile":                  "additive",
	"WithProtectedResources":       "additive",
	"WithScope":                    "additive",
	"WithStaticClients":            "additive",
	"WithTrustedProxies":           "additive",
	"WithTrustedProxyHosts":        "additive",
	"WithCIBA":                     "flag whose CIBAOptions claim their own settings",
	"WithDefaults":                 "wrapper",
	"WithSupportedEncryptionAlgs":  "claims one slot per half in applyAlgNarrowing / applyEncNarrowing",
}

// TestOptions_EveryOptionIsClassified walks every function in the package
// that returns an Option or a CIBAOption and requires it to be a flag (no
// parameters), to claim its setting through claimOnce / claimSlot, or to
// be listed in composeAdditive. It keeps a new option from silently
// reintroducing last-call-wins.
func TestOptions_EveryOptionIsClassified(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		files = append(files, f)
	}
	seen := 0
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || !returnsOption(fn) {
				continue
			}
			seen++
			name := fn.Name.Name
			claims := callsClaim(fn.Body)
			_, listed := composeAdditive[name]
			switch {
			case claims && listed:
				t.Errorf("%s claims a setting but is listed in composeAdditive", name)
			case claims, listed:
			case fn.Type.Params.NumFields() == 0:
			default:
				t.Errorf("%s takes an argument but neither claims a setting nor is listed in composeAdditive", name)
			}
		}
	}
	if seen < 50 {
		t.Fatalf("found only %d option constructors; the walk is not seeing the package", seen)
	}
}

func returnsOption(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return false
	}
	id, ok := fn.Type.Results.List[0].Type.(*ast.Ident)
	return ok && (id.Name == "Option" || id.Name == "CIBAOption")
}

func callsClaim(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && (sel.Sel.Name == "claimOnce" || sel.Sel.Name == "claimSlot") {
			found = true
		}
		return !found
	})
	return found
}

func TestClaimOnce_RepeatAndConflict(t *testing.T) {
	t.Parallel()

	_, err := newConfig([]Option{WithAccessTokenTTL(time.Minute), WithAccessTokenTTL(time.Minute)})
	if err == nil || !strings.Contains(err.Error(), "WithAccessTokenTTL may be called at most once") {
		t.Fatalf("repeated WithAccessTokenTTL: err = %v", err)
	}
	salt := make([]byte, 32)
	_, err = newConfig([]Option{WithPairwiseSubject(salt), WithSubjectGenerator(defaultSubjectGenerator())})
	if err == nil || !strings.Contains(err.Error(), "WithSubjectGenerator conflicts with prior WithPairwiseSubject") {
		t.Fatalf("subject generator conflict: err = %v", err)
	}
}

func TestWithDefaults_ExplicitWinsInEitherOrder(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		opts []Option
	}{
		{"defaults first", []Option{WithDefaults(WithAccessTokenTTL(time.Hour)), WithAccessTokenTTL(time.Minute)}},
		{"defaults last", []Option{WithAccessTokenTTL(time.Minute), WithDefaults(WithAccessTokenTTL(time.Hour))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := newConfig(tc.opts)
			if err != nil {
				t.Fatalf("newConfig: %v", err)
			}
			if c.accessTokenTTL != time.Minute {
				t.Fatalf("accessTokenTTL = %v, want the explicit 1m", c.accessTokenTTL)
			}
		})
	}
}

func TestWithDefaults_ShadowedDefaultIsNotValidated(t *testing.T) {
	t.Parallel()

	c, err := newConfig([]Option{WithDefaults(WithIssuer("")), WithIssuer("https://op.example.test")})
	if err != nil {
		t.Fatalf("a shadowed invalid default failed the build: %v", err)
	}
	if c.issuer != "https://op.example.test" {
		t.Fatalf("issuer = %q", c.issuer)
	}
}

func TestWithDefaults_DuplicateDefaultsFail(t *testing.T) {
	t.Parallel()

	_, err := newConfig([]Option{
		WithDefaults(WithAccessTokenTTL(time.Hour)),
		WithDefaults(WithDefaults(WithAccessTokenTTL(time.Minute))),
	})
	if err == nil || !strings.Contains(err.Error(), "may be called at most once") {
		t.Fatalf("two defaults for one setting: err = %v", err)
	}
}

func TestWithDefaults_AdditiveDefaultsAccumulate(t *testing.T) {
	t.Parallel()

	c, err := newConfig([]Option{
		WithDefaults(WithTrustedProxies("10.0.0.0/8")),
		WithTrustedProxies("192.168.0.0/16"),
	})
	if err != nil {
		t.Fatalf("newConfig: %v", err)
	}
	if !slices.Equal(c.trustedProxies, []string{"192.168.0.0/16", "10.0.0.0/8"}) {
		t.Fatalf("trustedProxies = %v, want both CIDRs", c.trustedProxies)
	}
}

func TestEndpoints_FieldsCoverEveryPath(t *testing.T) {
	t.Parallel()

	var e Endpoints
	if got, want := len(e.fields()), reflect.TypeFor[Endpoints]().NumField(); got != want {
		t.Fatalf("Endpoints.fields lists %d paths, the struct has %d", got, want)
	}
	for _, f := range e.fields() {
		if _, ok := reflect.TypeFor[Endpoints]().FieldByName(f.name); !ok {
			t.Errorf("Endpoints.fields names unknown field %q", f.name)
		}
	}
}

func TestWithEndpoints_FieldIsSingleValued(t *testing.T) {
	t.Parallel()

	c, err := newConfig([]Option{
		WithEndpoints(Endpoints{Token: "/t"}),
		WithEndpoints(Endpoints{UserInfo: "/u"}),
		WithDefaults(WithEndpoints(Endpoints{Token: "/default-token", Revoke: "/r"})),
	})
	if err != nil {
		t.Fatalf("disjoint fields: %v", err)
	}
	if c.endpoints.Token != "/t" || c.endpoints.UserInfo != "/u" || c.endpoints.Revoke != "/r" {
		t.Fatalf("endpoints = %+v", c.endpoints)
	}

	_, err = newConfig([]Option{WithEndpoints(Endpoints{Token: "/a"}), WithEndpoints(Endpoints{Token: "/b"})})
	if err == nil || !strings.Contains(err.Error(), "WithEndpoints (Token) may be called at most once") {
		t.Fatalf("Token set twice: err = %v", err)
	}
}

func TestWithLocale_KeyIsSingleValued(t *testing.T) {
	t.Parallel()

	bundle := func(msgs map[string]string) LocaleBundle {
		b, err := LocaleBundleFromMap("fr", msgs)
		if err != nil {
			t.Fatalf("LocaleBundleFromMap: %v", err)
		}
		return b
	}
	_, err := newConfig([]Option{WithLocale(bundle(map[string]string{"a": "1"})), WithLocale(bundle(map[string]string{"b": "2"}))})
	if err != nil {
		t.Fatalf("disjoint keys: %v", err)
	}
	_, err = newConfig([]Option{WithLocale(bundle(map[string]string{"a": "1"})), WithLocale(bundle(map[string]string{"a": "2"}))})
	if err == nil || !strings.Contains(err.Error(), "WithLocale (fr a) may be called at most once") {
		t.Fatalf("same key twice: err = %v", err)
	}
	c, err := newConfig([]Option{
		WithDefaults(WithLocale(bundle(map[string]string{"a": "default", "b": "kept"}))),
		WithLocale(bundle(map[string]string{"a": "explicit"})),
	})
	if err != nil {
		t.Fatalf("default key shadowed: %v", err)
	}
	if got, _ := c.localeBundles[1].internal.Get("a", nil); got != "" {
		t.Fatalf("the default bundle still carries the shadowed key: %q", got)
	}
	if got, _ := c.localeBundles[1].internal.Get("b", nil); got != "kept" {
		t.Fatalf("the default bundle lost an unshadowed key: %q", got)
	}
}

func TestIsDevelopmentIssuer(t *testing.T) {
	t.Parallel()

	for issuer, want := range map[string]bool{
		"http://127.0.0.1:8080":      true,
		"http://[::1]:8080":          true,
		"http://localhost:8080":      true,
		"https://op.localhost":       true,
		"https://op.example.test":    true,
		"https://op.testkit.invalid": true,
		"https://op.example":         true,
		"https://idp.example.com":    false,
		"https://test.example.com":   false,
		"https://mytest":             false,
		"https://10.0.0.1":           false,
	} {
		if got := isDevelopmentIssuer(issuer); got != want {
			t.Errorf("isDevelopmentIssuer(%q) = %v, want %v", issuer, got, want)
		}
	}
}

func TestValidate_DevBackchannelNeedsDevelopmentIssuer(t *testing.T) {
	t.Parallel()

	c := &config{issuer: "https://idp.example.com", allowInsecureBackchannelLogoutForDev: true}
	if err := c.validateRequired(); err == nil || !strings.Contains(err.Error(), "requires a development issuer") {
		t.Fatalf("validateRequired = %v, want the development-issuer refusal", err)
	}
}

// continuityNonceSource is a DPoPNonceSource whose identity is its address.
type continuityNonceSource struct{ _ byte }

func (*continuityNonceSource) IssueNonce() string   { return "n" }
func (*continuityNonceSource) Validate(string) bool { return true }

func continuityKey(t *testing.T, kid string) SigningKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return SigningKey{KeyID: kid, Signer: priv}
}

func TestCheckReloadContinuity(t *testing.T) {
	t.Parallel()

	cookieA, cookieB := make([]byte, 32), make([]byte, 32)
	cookieB[0] = 1
	mfaA, mfaB := make([]byte, 32), make([]byte, 32)
	mfaB[0] = 2
	stepKey := make([]byte, 32)
	stepKey[0] = 3
	signA, signB := continuityKey(t, "a"), continuityKey(t, "b")
	reusedKid := continuityKey(t, "a")
	nonces, otherNonces := &continuityNonceSource{}, &continuityNonceSource{}
	totpFlow := LoginFlow{Rules: []Rule{{Then: StepOneOf{Steps: []Step{StepTOTP{EncryptionKey: stepKey}}}}}}

	cur := &config{
		cookieKeys:        [][]byte{cookieA},
		keyset:            Keyset{signA},
		mfaEncryptionKeys: [][]byte{mfaA},
		loginFlow:         totpFlow,
		dpopNonces:        nonces,
	}
	next := func(edit func(*config)) *config {
		c := &config{
			cookieKeys:        [][]byte{cookieB, cookieA},
			keyset:            Keyset{signB, signA},
			mfaEncryptionKeys: [][]byte{mfaB, mfaA},
			loginFlow:         totpFlow,
			dpopNonces:        nonces,
		}
		if edit != nil {
			edit(c)
		}
		return c
	}

	for _, tc := range []struct {
		name string
		next *config
		want string
	}{
		{"rotation keeps every running key", next(nil), ""},
		{"active cookie key dropped", next(func(c *config) { c.cookieKeys = [][]byte{cookieB} }), "cookie key"},
		{"active signing key dropped", next(func(c *config) { c.keyset = Keyset{signB} }), "signing key"},
		{"active kid reused for another key", next(func(c *config) { c.keyset = Keyset{reusedKid} }), "signing key"},
		{"provider MFA key dropped", next(func(c *config) { c.mfaEncryptionKeys = [][]byte{mfaB} }), "MFA encryption key"},
		{"per-step MFA key dropped", next(func(c *config) { c.loginFlow = LoginFlow{} }), "MFA encryption key"},
		{"per-step key moved to the provider level", next(func(c *config) {
			c.loginFlow = LoginFlow{}
			c.mfaEncryptionKeys = append(c.mfaEncryptionKeys, stepKey)
		}), ""},
		{"nonce source replaced", next(func(c *config) { c.dpopNonces = otherNonces }), "WithDPoPNonceSource"},
		{"nonce source removed", next(func(c *config) { c.dpopNonces = nil }), "WithDPoPNonceSource"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkReloadContinuity(cur, tc.next)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("checkReloadContinuity = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrReloadIncompatible) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("checkReloadContinuity = %v, want ErrReloadIncompatible naming %q", err, tc.want)
			}
		})
	}
}

func TestWithDefaults_CIBASubOptionsYieldIndividually(t *testing.T) {
	t.Parallel()

	c, err := newConfig([]Option{
		WithDefaults(WithCIBA(WithCIBAPollInterval(5*time.Second), WithCIBAMaxPollViolations(3))),
		WithCIBA(WithCIBAPollInterval(10 * time.Second)),
	})
	if err != nil {
		t.Fatalf("newConfig: %v", err)
	}
	if c.cibaPollInterval != 10*time.Second || c.cibaMaxPollViolations != 3 {
		t.Fatalf("poll interval = %v, max violations = %d; want the explicit 10s and the default 3",
			c.cibaPollInterval, c.cibaMaxPollViolations)
	}
}
