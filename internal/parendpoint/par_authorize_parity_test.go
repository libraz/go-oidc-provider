package parendpoint_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorizationdetails"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// /par and /authorize are two gates on the same authorization request, and
// the RP walks through them in that order. A rule that fires at only one of
// them is not a cosmetic inconsistency: if /par accepts and /authorize
// rejects, the RP has already spent its one-time request_uri (RFC 9126 §2.2)
// and the user is left with no way forward; if /par rejects what /authorize
// would accept, the pushed flow is simply unusable for that request shape.
//
// The tests below drive one request through both endpoints and assert they
// reach the same verdict. They deliberately assert on the decision rather
// than on the response bytes: the two endpoints owe their callers different
// shapes (a redirect to a validated redirect_uri versus the RFC 9126 §2.3
// JSON envelope), and pinning the bytes would pin the wrong thing.

// verdict is the accept / reject decision an endpoint reached, stripped of
// the wire shape it expressed the decision in. errCode is the OAuth error
// identifier on a rejection and empty on an acceptance.
type verdict struct {
	accepted bool
	errCode  string
}

// String renders a verdict for failure messages.
func (v verdict) String() string {
	if v.accepted {
		return "accepted"
	}
	return "rejected(" + v.errCode + ")"
}

// newParityFixture builds an OP with every extension the two endpoints
// share switched on: PAR itself, an RFC 9396 authorization_details registry
// with one type, and the Grant Management draft limited to create / merge.
// DPoP is deliberately left off so the RFC 9449 §10.1 "dpop_jkt" gate is
// exercised in its rejecting state at both endpoints.
//
// Grant Management is configured with create and merge but NOT replace, so
// the table can separate "this action is not an authorization-time action"
// from "this authorization-time action is not enabled on this OP".
func newParityFixture(tb testing.TB) *fixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithFeature(feature.PAR),
			op.WithAuthorizationDetailTypes(op.AuthorizationDetailType{
				Type:     parityDetailType,
				Validate: validateParityDetail,
			}),
			op.WithGrantManagement([]op.GrantManagementAction{
				op.GrantActionCreate,
				op.GrantActionMerge,
			}, false),
		),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/par",
		clock:    clock,
	}
}

// parityDetailType is the single RFC 9396 "type" the parity fixture accepts.
const parityDetailType = "payment_initiation"

// validateParityDetail is the type-specific validator behind
// [parityDetailType]. It demands a non-empty string "amount" so the table
// can distinguish "the OP does not know this type" from "the OP knows the
// type and the element failed its validator" — both of which RFC 9396 §5
// answers with invalid_authorization_details, and both of which must be
// answered identically by the two endpoints.
func validateParityDetail(_ context.Context, el map[string]any, _ *store.Client) error {
	if amount, _ := el["amount"].(string); amount == "" {
		return errors.New("payment_initiation requires a non-empty string amount")
	}
	return nil
}

// parityForm returns the happy-path authorization parameters with the
// row-specific overrides applied, so every row differs from the accepted
// baseline on exactly the axis it names.
func parityForm(clientID, redirectURI string, set map[string]string) url.Values {
	v := goodAuthorizeForm(clientID, redirectURI)
	for k, val := range set {
		v.Set(k, val)
	}
	return v
}

// parVerdict pushes form at /par and reduces the response to a [verdict].
func parVerdict(tb testing.TB, f *fixture, clientID, secret string, form url.Values) verdict {
	tb.Helper()
	resp := f.post(tb, form, clientID, secret)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusCreated {
		return verdict{accepted: true}
	}
	body := decodeJSON(tb, resp)
	code, _ := body["error"].(string)
	if code == "" {
		tb.Fatalf("/par status=%d carried no error code: %v", resp.StatusCode, body)
	}
	return verdict{errCode: code}
}

// authorizeVerdict submits the same parameters inline at /authorize and
// reduces the response to a [verdict]. The endpoint expresses an acceptance
// as a redirect to the interaction it started and a rejection either as the
// pre-redirect JSON envelope (redirect_uri not trusted yet) or as a redirect
// carrying the OAuth error parameters; all three are collapsed here.
func authorizeVerdict(tb testing.TB, f *fixture, form url.Values) verdict {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		f.prov.Server.URL+"/oidc/auth?"+form.Encode(), http.NoBody)
	if err != nil {
		tb.Fatalf("NewRequest /authorize: %v", err)
	}
	// HTTPClient does not follow redirects, so the 302 is observable.
	resp, err := f.prov.HTTPClient(nil).Do(req)
	if err != nil {
		tb.Fatalf("Do /authorize: %v", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusFound:
		loc, locErr := resp.Location()
		if locErr != nil {
			tb.Fatalf("/authorize 302 without Location: %v", locErr)
		}
		if code := loc.Query().Get("error"); code != "" {
			return verdict{errCode: code}
		}
		if strings.HasPrefix(loc.Path, "/oidc/interaction/") || loc.Query().Get("code") != "" {
			return verdict{accepted: true}
		}
		tb.Fatalf("/authorize redirected to %s, which is neither an interaction nor an error", loc)
	case http.StatusBadRequest:
		body := decodeJSON(tb, resp)
		code, _ := body["error"].(string)
		if code == "" {
			tb.Fatalf("/authorize 400 carried no error code: %v", body)
		}
		return verdict{errCode: code}
	}
	tb.Fatalf("/authorize status=%d is neither an acceptance nor a rejection", resp.StatusCode)
	return verdict{}
}

// oversizeAuthorizationDetails returns an authorization_details value past
// the decoder's byte cap, padded with characters that survive form encoding
// unchanged so the encoded request stays well inside the 64 KiB form-body
// limit both endpoints enforce.
func oversizeAuthorizationDetails() string {
	padding := strings.Repeat("A", authorizationdetails.MaxBytes)
	return `[{"type":"` + parityDetailType + `","amount":"1.00","reference":"` + padding + `"}]`
}

// TestPARAuthorizeParity_SameRequestSameDecision drives one malformed (or
// well-formed) request at both endpoints and asserts they agree.
//
// The agreement assertion is the property worth pinning: it fails if a
// future edit adds a rule to one endpoint only, which is exactly the class
// of change that strands an RP mid-flow. The expected verdict is asserted
// too, because agreeing on the wrong answer is also a defect.
func TestPARAuthorizeParity_SameRequestSameDecision(t *testing.T) {
	t.Parallel()

	f := newParityFixture(t)
	client, secret := f.confidentialClient(t)
	redirectURI := client.RedirectURIs[0]

	tests := []struct {
		name     string
		override map[string]string
		want     verdict
	}{
		{
			name:     "well-formed request",
			override: nil,
			want:     verdict{accepted: true},
		},
		{
			name:     "redirect_uri outside the client registration",
			override: map[string]string{"redirect_uri": "https://not-registered.testkit.invalid/cb"},
			want:     verdict{errCode: "invalid_request"},
		},
		{
			name:     "scope outside the client registration",
			override: map[string]string{"scope": "openid administrator"},
			want:     verdict{errCode: "invalid_scope"},
		},
		{
			name:     "dpop_jkt commitment an OP without DPoP cannot honour",
			override: map[string]string{"dpop_jkt": committedJKT},
			want:     verdict{errCode: "invalid_request"},
		},
		{
			name: "authorization_details naming an unregistered type",
			override: map[string]string{
				"authorization_details": `[{"type":"account_information"}]`,
			},
			want: verdict{errCode: "invalid_authorization_details"},
		},
		{
			name: "authorization_details rejected by its type validator",
			override: map[string]string{
				"authorization_details": `[{"type":"` + parityDetailType + `"}]`,
			},
			want: verdict{errCode: "invalid_authorization_details"},
		},
		{
			name: "authorization_details past the size cap",
			override: map[string]string{
				"authorization_details": oversizeAuthorizationDetails(),
			},
			want: verdict{errCode: "invalid_request"},
		},
		{
			name: "authorization_details accepted by its type validator",
			override: map[string]string{
				"authorization_details": `[{"type":"` + parityDetailType + `","amount":"12.34"}]`,
			},
			want: verdict{accepted: true},
		},
		{
			name:     "grant_management_action=create",
			override: map[string]string{"grant_management_action": "create"},
			want:     verdict{accepted: true},
		},
		{
			name: "grant_management_action=create carrying a grant_id",
			override: map[string]string{
				"grant_management_action": "create",
				"grant_id":                "grant-parity-1",
			},
			want: verdict{errCode: "invalid_request"},
		},
		{
			name:     "grant_management_action=merge without a grant_id",
			override: map[string]string{"grant_management_action": "merge"},
			want:     verdict{errCode: "invalid_request"},
		},
		{
			name: "grant_management_action=merge with a grant_id",
			override: map[string]string{
				"grant_management_action": "merge",
				"grant_id":                "grant-parity-2",
			},
			want: verdict{accepted: true},
		},
		{
			name: "grant_management_action=replace, an action this OP did not enable",
			override: map[string]string{
				"grant_management_action": "replace",
				"grant_id":                "grant-parity-3",
			},
			want: verdict{errCode: "invalid_request"},
		},
		{
			name:     "grant_management_action=query, an endpoint-only action",
			override: map[string]string{"grant_management_action": "query"},
			want:     verdict{errCode: "invalid_request"},
		},
		{
			name:     "grant_management_action outside the defined set",
			override: map[string]string{"grant_management_action": "obliterate"},
			want:     verdict{errCode: "invalid_request"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			form := parityForm(client.ID, redirectURI, tc.override)
			atPAR := parVerdict(t, f, client.ID, secret, form)
			atAuthorize := authorizeVerdict(t, f, form)

			if atPAR != atAuthorize {
				t.Fatalf("/par %s but /authorize %s; the two gates must agree or an RP is stranded mid-flow",
					atPAR, atAuthorize)
			}
			if atPAR != tc.want {
				t.Errorf("both endpoints %s, want %s", atPAR, tc.want)
			}
		})
	}
}

// TestPARAuthorizeParity_MixedCaseRequestURIStaysOnThePARBranch pins the one
// classification rule that decides whether an inbound request_uri is a PAR
// reference (RFC 9126 §2.2) or a JAR reference (RFC 9101 §5.2.2).
//
// RFC 8141 §3 makes at least the "urn" scheme and the "ietf" namespace
// identifier case-insensitive, so a URN whose prefix differs from the minted
// one only in case is still a PAR reference and must be answered by the PAR
// branch — with invalid_request_uri, because no record carries that key.
// Routing it to the JAR branch instead produces an error about a mechanism
// the client never invoked.
func TestPARAuthorizeParity_MixedCaseRequestURIStaysOnThePARBranch(t *testing.T) {
	t.Parallel()

	f := newParityFixture(t)
	client, secret := f.confidentialClient(t)

	resp := f.post(t, goodAuthorizeForm(client.ID, client.RedirectURIs[0]), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("/par status=%d want 201; body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	requestURI, _ := decodeJSON(t, resp)["request_uri"].(string)
	if requestURI == "" {
		t.Fatal("/par returned no request_uri")
	}

	// Control: the minted value resolves and parks the browser at the
	// interaction, so any difference below is attributable to the case
	// change alone.
	exact := getAuthorize(t, f.prov, client.ID, requestURI)
	defer exact.Body.Close()
	if exact.StatusCode != http.StatusFound {
		t.Fatalf("exact-case request_uri status=%d want 302; body=%v", exact.StatusCode, decodeJSON(t, exact))
	}

	prefixLen := len(authorize.PARRequestURIPrefix)
	mixed := strings.ToUpper(requestURI[:prefixLen]) + requestURI[prefixLen:]
	if mixed == requestURI {
		t.Fatalf("case mutation was a no-op on %q", requestURI)
	}

	mixedResp := getAuthorize(t, f.prov, client.ID, mixed)
	defer mixedResp.Body.Close()
	if mixedResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("mixed-case request_uri status=%d want 400", mixedResp.StatusCode)
	}
	body := decodeJSON(t, mixedResp)
	if body["error"] != "invalid_request_uri" {
		t.Errorf("error=%v want invalid_request_uri; the value was classified as something other than a PAR reference",
			body["error"])
	}
}
