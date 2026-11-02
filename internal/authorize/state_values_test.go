package authorize_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorize"
)

func TestRequestSnapshot_ValuesRoundTripsThroughParseValues(t *testing.T) {
	t.Parallel()

	maxAge := int64(300)
	snap := authorize.RequestSnapshot{
		ClientID:            "client-1",
		ResponseType:        "code",
		RedirectURI:         "https://rp.example.com/cb",
		State:               "st",
		Nonce:               "nn",
		CodeChallenge:       "cc",
		CodeChallengeMethod: "S256",
		Scope:               []string{"openid", "profile"},
		Resource:            "https://api.example.com",
		Prompt:              []string{"consent", "select_account"},
		ACRValues:           []string{"urn:a", "urn:b"},
		UILocales:           []string{"en-US", "ja"},
		MaxAge:              &maxAge,
		LoginHint:           "user@example.com",
		ResponseMode:        "query",
		DPoPJKT:             "jkt",
		PARRequestURI:       "urn:ietf:params:oauth:request_uri:abc",
		Claims: &authorize.ClaimsRequest{
			IDToken: map[string]authorize.ClaimSpec{"acr": {Essential: true, Values: []any{"urn:a"}}},
		},
		AuthorizationDetails:  []map[string]any{{"type": "payment"}},
		GrantManagementAction: "create",
		GrantID:               "grant-1",
		CreatedUnix:           1,
	}

	// A field added to the snapshot without a value here would pass the
	// round trip vacuously.
	rv := reflect.ValueOf(snap)
	for i := range rv.NumField() {
		if rv.Field(i).IsZero() {
			t.Fatalf("fixture leaves %s zero; set it so the round trip covers it", rv.Type().Field(i).Name)
		}
	}

	values, err := snap.Values()
	if err != nil {
		t.Fatalf("Values: %v", err)
	}
	req, err := authorize.ParseValues(values)
	if err != nil {
		t.Fatalf("ParseValues: %v", err)
	}
	// authorization_details is validated into structure downstream of the
	// parser, and the PAR reference and creation time are not request
	// parameters.
	var details []map[string]any
	if err := json.Unmarshal([]byte(req.AuthorizationDetailsRaw), &details); err != nil {
		t.Fatalf("authorization_details: %v", err)
	}
	req.AuthorizationDetails = details
	req.PARRequestURI = snap.PARRequestURI

	got := authorize.SnapshotFrom(req, fixedNow)
	got.CreatedUnix = snap.CreatedUnix
	if !reflect.DeepEqual(got, snap) {
		t.Errorf("round trip lost data:\n got=%+v\nwant=%+v", got, snap)
	}
}
