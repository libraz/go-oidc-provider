package authorizeendpoint_test

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	authntotp "github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/op/totpkit"
)

// The tests in this file drive the default ACR policy and ACRLevels
// through a password-first LoginFlow with a TOTP step, over the model
// that also generates TestACRLevels_Resolve:
//
//	request kind: none | canonical | map value | unknown
//	achieved:     AAL1 (password) | AAL2 (password + TOTP)
//	policy:       default | ACRLevels | custom
//	request type: voluntary (acr_values) | essential (claims)
//
// The four tests cover the pairs the wire layer owns: an unmet voluntary
// request reports the level reached, an unmet essential one is refused,
// and a request the login actually satisfies is reported as requested,
// for a canonical URI and for a custom value declared through ACRLevels.
// The custom-policy ok=false path shares the same wire branch as the
// unmet cases below.

const (
	acrStrictUsername = "acr-strict-user"
	acrStrictPassword = "correct horse battery staple"
	acrStrictSubject  = "user-acr-strict"
	acrStrictCustom   = "urn:example:acr:strict"
)

// acrStrictFixture is a password-first Provider with a confirmed TOTP
// enrolment for acrStrictSubject. The rules builder receives the TOTP
// store and sealing key so each test chooses which acr triggers the
// second factor.
type acrStrictFixture struct {
	*reauthDriver
	totpSecret []byte
}

// newACRStrictFixture builds the Provider through op.New directly:
// testkit.NewProvider cannot be combined with op.WithLoginFlow, and the
// LoginFlow needs the store the Provider is built on.
func newACRStrictFixture(t *testing.T, rules func(totp store.TOTPStore, key []byte) []op.Rule, extra ...op.Option) *acrStrictFixture {
	t.Helper()
	clock := newMovableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	st := inmem.New(inmem.WithClock(clock))

	hash, err := op.HashPassword(acrStrictPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	st.PutUserWithPassword(context.Background(), &store.User{Subject: acrStrictSubject}, acrStrictUsername, hash)

	totpKey := make([]byte, 32)
	if _, err := rand.Read(totpKey); err != nil {
		t.Fatalf("totp key: %v", err)
	}
	codec, err := totpkit.NewCodec(totpKey)
	if err != nil {
		t.Fatalf("totpkit.NewCodec: %v", err)
	}
	pending, err := totpkit.NewEnrolment(codec, acrStrictSubject, "acr-strict", "user@example.test")
	if err != nil {
		t.Fatalf("NewEnrolment: %v", err)
	}
	pending.Record.ConfirmedAt = clock.Now()
	if err := st.TOTPs().Put(context.Background(), pending.Record); err != nil {
		t.Fatalf("TOTPs.Put: %v", err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(pending.SecretBase32)
	if err != nil {
		t.Fatalf("decode totp secret: %v", err)
	}

	const rpSecret = "rp-acr-strict-secret" //nolint:gosec // test fixture, not a real credential.
	rpHash, err := op.HashClientSecret(rpSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	rp := &store.Client{
		ID:                      "rp-acr-strict",
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SecretHash:              rpHash,
	}
	if err := st.RegisterClient(context.Background(), rp); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	var flowRules []op.Rule
	if rules != nil {
		flowRules = rules(st.TOTPs(), totpKey)
	}
	opts := append([]op.Option{
		op.WithIssuer(testkit.DefaultIssuer),
		op.WithStore(st),
		op.WithKeyset(op.Keyset{newFlowSigningKey(t)}),
		op.WithCookieKeys(newFlowCookieKey(t)),
		op.WithInteractionDriver(testkit.AutoConsentDriver{}),
		op.WithClock(clock),
		op.WithLoginFlow(op.LoginFlow{
			Primary: op.PrimaryPassword{Store: st.UserPasswords()},
			Rules:   flowRules,
		}),
	}, extra...)
	provider, err := op.New(opts...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewTLSServer(provider)
	t.Cleanup(srv.Close)

	fix := &flowFixture{
		server: srv, store: st, client: rp, clock: clock,
		issuer: testkit.DefaultIssuer, secret: rpSecret,
	}
	return &acrStrictFixture{
		reauthDriver: &reauthDriver{t: t, fix: fix, cl: fix.httpClient(t)},
		totpSecret:   secret,
	}
}

// login runs /authorize with extra query parameters through the password
// step, then the TOTP step when withTOTP is set, then consent, and
// returns the final redirect to the RP.
func (f *acrStrictFixture) login(extra url.Values, withTOTP bool) *url.URL {
	f.t.Helper()
	loc := f.authorize(extra)
	env, csrf := f.firstPrompt(loc.Path)
	stateRef, _ := env["state_ref"].(string)

	resp := f.submit(loc.Path, csrf, stateRef, map[string]string{
		"username": acrStrictUsername,
		"password": acrStrictPassword,
	})
	defer resp.Body.Close()

	if withTOTP {
		if resp.StatusCode != http.StatusOK {
			dump, _ := io.ReadAll(resp.Body)
			f.t.Fatalf("password step status=%d body=%s", resp.StatusCode, dump)
		}
		if rotated := findCookie(resp.Cookies(), "__Host-oidc_csrf"); rotated != nil {
			csrf = rotated.Value
		}
		next := decodeMap(f.t, resp)
		if got, _ := next["type"].(string); got != authntotp.PromptType {
			f.t.Fatalf("prompt after password = %q, want %q", got, authntotp.PromptType)
		}
		nextRef, _ := next["state_ref"].(string)
		resp = f.submit(loc.Path, csrf, nextRef, map[string]string{
			authntotp.CodeFieldName: authntotp.Code(f.totpSecret, f.fix.clock.Now()),
		})
		defer resp.Body.Close()
	}

	final := completeConsentIfPrompted(f.t, f.cl, f.fix.server.URL+loc.Path, f.fix.issuer, csrf, resp)
	defer final.Body.Close()
	if final.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(final.Body)
		f.t.Fatalf("interaction final status=%d body=%s", final.StatusCode, dump)
	}
	redirect, err := final.Location()
	if err != nil {
		f.t.Fatalf("final Location: %v", err)
	}
	return redirect
}

// TestEndToEnd_ACRStrict_VoluntaryUnmetReportsReachedLevel pins the
// default policy: a password-only login that was asked for silver gets
// the bronze it reached, never the silver it did not.
func TestEndToEnd_ACRStrict_VoluntaryUnmetReportsReachedLevel(t *testing.T) {
	t.Parallel()
	f := newACRStrictFixture(t, nil)

	redirect := f.login(url.Values{"acr_values": {silverACR}}, false)
	claims := f.exchange(f.codeFrom(redirect))
	if got, _ := claims["acr"].(string); got != bronzeACR {
		t.Errorf("id_token acr=%q want %q (the level reached, not the one requested)", got, bronzeACR)
	}
}

// TestEndToEnd_ACRStrict_EssentialUnmetIsRefused pins the essential
// branch: a custom acr that needs AAL2, requested through the claims
// parameter against a password-only login, ends in
// unmet_authentication_requirements and no code.
func TestEndToEnd_ACRStrict_EssentialUnmetIsRefused(t *testing.T) {
	t.Parallel()
	f := newACRStrictFixture(t, nil, op.WithACRPolicy(op.ACRLevels{acrStrictCustom: op.AAL2}))

	redirect := f.login(url.Values{
		"claims": {`{"id_token":{"acr":{"essential":true,"value":"` + acrStrictCustom + `"}}}`},
	}, false)
	q := redirect.Query()
	if got := q.Get("error"); got != "unmet_authentication_requirements" {
		t.Errorf("error=%q want unmet_authentication_requirements (redirect: %s)", got, redirect)
	}
	if got := q.Get("code"); got != "" {
		t.Errorf("code=%q want none for a refused authentication context", got)
	}
}

// TestEndToEnd_ACRStrict_TOTPReachesSilver shows silver is reported when
// a TOTP step actually ran: acr_values=silver schedules the step, the
// login reaches AAL2, and the canonical silver URI is on the id_token.
func TestEndToEnd_ACRStrict_TOTPReachesSilver(t *testing.T) {
	t.Parallel()
	f := newACRStrictFixture(t, func(totp store.TOTPStore, key []byte) []op.Rule {
		return []op.Rule{op.RuleACR(silverACR, op.StepTOTP{Store: totp, EncryptionKey: key})}
	})

	redirect := f.login(url.Values{"acr_values": {silverACR}}, true)
	claims := f.exchange(f.codeFrom(redirect))
	if got, _ := claims["acr"].(string); got != silverACR {
		t.Errorf("id_token acr=%q want %q", got, silverACR)
	}
}

// TestEndToEnd_ACRStrict_CustomLevelAfterTOTP is the custom-acr pairing
// the ACRLevels doc describes: RuleACR schedules the TOTP step for the
// custom value, ACRLevels maps it to AAL2, and the value the RP asked for
// is reported once the second factor completed.
func TestEndToEnd_ACRStrict_CustomLevelAfterTOTP(t *testing.T) {
	t.Parallel()
	f := newACRStrictFixture(t,
		func(totp store.TOTPStore, key []byte) []op.Rule {
			return []op.Rule{op.RuleACR(acrStrictCustom, op.StepTOTP{Store: totp, EncryptionKey: key})}
		},
		op.WithACRPolicy(op.ACRLevels{acrStrictCustom: op.AAL2}),
	)

	redirect := f.login(url.Values{"acr_values": {acrStrictCustom}}, true)
	claims := f.exchange(f.codeFrom(redirect))
	if got, _ := claims["acr"].(string); got != acrStrictCustom {
		t.Errorf("id_token acr=%q want %q", got, acrStrictCustom)
	}
}
