package scenarios_test

// Spec:
//   - RFC 7519 §4.1.4 — "exp" and the implementation-defined leeway
//   - RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens
//   - RFC 7662 §2.2 / RFC 7009 §2.2 / RFC 8693 §2.1 — the three
//     protocol surfaces that answer about a presented access token
//
// Four surfaces verify a JWT access token: /userinfo, /introspect,
// /revoke and the token-exchange subject_token lookup. Each one builds
// its own tokens.AccessTokenVerifier, so the clock tolerance is a
// per-site setting — and a token's validity is a property of the token,
// not of whichever surface an RP happens to reach for. A tolerance that
// differs by site makes the same token live at one endpoint and dead at
// another, and only in a deployment with clock skew, which is exactly
// the condition the tolerance exists to absorb.
//
// So the assertion here is agreement, not per-surface correctness: one
// token is driven through all four and the four answers must match.
// Four independent per-surface tests would each keep passing if one
// site's tolerance were changed on its own.

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// leewaySubject is the account the probed token is issued for. It is
// seeded into the user store so /userinfo has claims to answer with;
// without it a valid token would still draw a non-200 and the surfaces
// would agree for the wrong reason.
const leewaySubject = "user-leeway-1"

// surfaceAnswers records what each of the four verification surfaces
// said about one token. The field names are the surfaces; the values
// are "did this surface treat the token as still valid".
type surfaceAnswers struct {
	UserInfo      bool
	Introspect    bool
	TokenExchange bool
	Revoke        bool
}

// disagrees reports the surfaces whose answer differs from userInfo's,
// which is picked as the reference only because it needs to be one of
// them; the assertion is mutual agreement, not conformance to /userinfo.
func (a surfaceAnswers) disagrees() []string {
	var out []string
	for _, s := range []struct {
		name string
		got  bool
	}{
		{"/introspect", a.Introspect},
		{"token-exchange", a.TokenExchange},
		{"/revoke", a.Revoke},
	} {
		if s.got != a.UserInfo {
			out = append(out, s.name)
		}
	}
	return out
}

// TestAccessTokenLeewayAgreesAcrossVerifyingSurfaces drives one token
// through every surface that verifies an access token, at two clock
// offsets: just inside the shared tolerance and well outside it.
//
// The inside-the-window case is the one that catches a surface with no
// tolerance at all; the outside case is what keeps the test honest,
// since a surface that accepted everything would satisfy the first case
// on its own.
func TestAccessTokenLeewayAgreesAcrossVerifyingSurfaces(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// issuedAhead is how far into the future the token's "iat"
		// sits — the skew a peer whose clock runs fast produces.
		issuedAhead time.Duration
		wantValid   bool
	}{
		{
			name:        "inside the tolerance every surface still accepts",
			issuedAhead: tokens.DefaultLeeway / 2,
			wantValid:   true,
		},
		{
			name:        "outside the tolerance every surface refuses",
			issuedAhead: tokens.DefaultLeeway * 4,
			wantValid:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			capture := scenariokit.NewAuditCapture()
			p := newTXProviderOpts(t, txAllowAllPolicy{},
				op.WithFeature(feature.Introspect),
				op.WithFeature(feature.Revoke),
				op.WithAuditLogger(capture.Logger()),
			)
			p.tk.Store.PutUser(context.Background(), &store.User{
				Subject: leewaySubject,
				Claims:  map[string]any{"email": "leeway@example.com"},
			})

			token := p.mintLeewayToken(t, "jti-leeway-"+tc.name, tc.issuedAhead)
			got := probeAllSurfaces(t, p, capture, token)

			if diff := got.disagrees(); len(diff) > 0 {
				t.Errorf("the four verifying surfaces disagree about one token: /userinfo=%v but %v "+
					"answered otherwise (full answers: %+v). An access token's validity belongs to "+
					"the token, so a deployment with clock skew would see it accepted at one "+
					"endpoint and refused at another",
					got.UserInfo, diff, got)
			}
			for _, s := range []struct {
				name string
				got  bool
			}{
				{"/userinfo", got.UserInfo},
				{"/introspect", got.Introspect},
				{"token-exchange", got.TokenExchange},
				{"/revoke", got.Revoke},
			} {
				if s.got != tc.wantValid {
					t.Errorf("%s treated the token as valid=%v, want %v (iat is %v in the future, "+
						"tolerance is %v)", s.name, s.got, tc.wantValid, tc.issuedAhead, tokens.DefaultLeeway)
				}
			}
		})
	}
}

// mintLeewayToken signs an access token whose "iat" sits issuedAhead in
// the future — the shape a peer whose clock runs fast produces, and the
// other half of the symmetric tolerance.
//
// The skew is put on "iat" rather than on "exp" deliberately. An
// already-expired token is refused by rules that have nothing to do with
// clock tolerance — token exchange declines a subject_token with no
// remaining lifetime however cleanly it verified — so an exp-side probe
// measures those rules instead of the leeway. Here "exp" stays an hour
// out, leaving each surface's own tolerance as the only variable.
//
// Backdating the claim rather than moving a clock also keeps every
// surface reading the same real "now".
func (p *txProvider) mintLeewayToken(t *testing.T, jti string, issuedAhead time.Duration) string {
	t.Helper()

	now := txClockNow()
	claims := tokens.AccessTokenClaims{
		Issuer:  p.tk.Issuer,
		Subject: leewaySubject,
		// The caller client owns the token: /revoke ignores a token
		// belonging to another client (RFC 7009 §2.2), and the exchange
		// then runs as a self-exchange, so one credential drives all
		// four probes.
		ClientID: txCallerID,
		// The issuer rides in the audience alongside the resource:
		// /userinfo refuses a token that does not name the OP itself
		// (its own audience gate), and the probe has to clear every
		// surface's non-clock rules or it would be measuring those
		// instead of the tolerance.
		Audience:  []string{p.tk.Issuer, txOriginAud},
		IssuedAt:  now.Add(issuedAhead).Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       jti,
		Scope:     []string{"openid", "read"},
	}
	return p.mintSubjectToken(t, claims)
}

// probeAllSurfaces presents token to each verifying surface and records
// the answer. /revoke runs last: on the accept path it is the only
// destructive probe, and a revoked token would change what the others
// see.
func probeAllSurfaces(t *testing.T, p *txProvider, capture *scenariokit.AuditCapture, token string) surfaceAnswers {
	t.Helper()

	var out surfaceAnswers

	status, _, _ := getUserInfo(t, p.tk, token)
	out.UserInfo = status == 200

	_, body := postIntrospect(t, p.tk, token, txCallerID, txClientSecret)
	active, _ := body["active"].(bool)
	out.Introspect = active

	exchangeStatus, _ := p.postTokenExchange(t, url.Values{
		"grant_type":         {txGrantType},
		"subject_token":      {token},
		"subject_token_type": {txTokenTypeAT},
		"audience":           {txTargetAud},
	})
	out.TokenExchange = exchangeStatus == 200

	// /revoke answers 200 whether or not it accepted the token (RFC 7009
	// §2.2 forbids leaking the failure mode through the status), so the
	// audit trail is the only place its answer is visible: the revoked
	// event fires exactly when the token verified.
	before := len(capture.EventsByName(string(op.AuditTokenRevoked)))
	postRevoke(t, p.tk, token, txCallerID, txClientSecret)
	out.Revoke = len(capture.EventsByName(string(op.AuditTokenRevoked))) > before

	return out
}
