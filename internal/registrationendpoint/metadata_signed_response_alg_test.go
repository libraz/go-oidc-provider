package registrationendpoint_test

import (
	"io"
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestRegister_SignedResponseAlgNamesTheShapeTheOPServes drives every
// *_signed_response_alg member through the registration endpoint and
// pins the single rule they share: the member may name the shape its
// surface actually puts on the wire for this client, and nothing else.
// A 201 therefore means the client's later responses carry the named
// shape, and a value the OP would ignore is refused at registration
// time instead of surfacing as an algorithm mismatch on the RP's first
// verification attempt.
func TestRegister_SignedResponseAlgNamesTheShapeTheOPServes(t *testing.T) {
	t.Parallel()

	// encryptedUserInfoMetadata is the standard metadata set, which
	// registers UserInfo response encryption; every /userinfo response
	// for such a client is signed before it is encrypted.
	encryptedUserInfoMetadata := func(alg any) map[string]any {
		body := fullStandardMetadata()
		body["userinfo_signed_response_alg"] = alg
		return body
	}
	withMember := func(member string, value any) map[string]any {
		body := minimalMetadata()
		body[member] = value
		return body
	}

	cases := []struct {
		name string
		body map[string]any
		want int
	}{
		{
			name: "JARM response signed with an algorithm the OP does not hold",
			body: withMember("authorization_signed_response_alg", "RS256"),
			want: http.StatusBadRequest,
		},
		{
			name: "JARM response the client asks the OP to leave unsigned",
			body: withMember("authorization_signed_response_alg", "none"),
			want: http.StatusBadRequest,
		},
		{
			name: "JARM response signed with the algorithm the OP holds",
			body: withMember("authorization_signed_response_alg", "ES256"),
			want: http.StatusCreated,
		},
		{
			name: "signed UserInfo response for a client the OP answers in JSON",
			body: withMember("userinfo_signed_response_alg", "ES256"),
			want: http.StatusBadRequest,
		},
		{
			name: "unsigned UserInfo response, which is the shape the client receives",
			body: withMember("userinfo_signed_response_alg", "none"),
			want: http.StatusCreated,
		},
		{
			name: "signed UserInfo response for a client whose responses are encrypted",
			body: encryptedUserInfoMetadata("ES256"),
			want: http.StatusCreated,
		},
		{
			name: "unsigned UserInfo response for a client whose responses are encrypted",
			body: encryptedUserInfoMetadata("none"),
			want: http.StatusBadRequest,
		},
		{
			name: "ID Token the client asks the OP to leave unsigned",
			body: withMember("id_token_signed_response_alg", "none"),
			want: http.StatusBadRequest,
		},
		{
			name: "introspection response the client asks the OP to leave unsigned",
			body: withMember("introspection_signed_response_alg", "none"),
			want: http.StatusCreated,
		},
		{
			name: "introspection response signed with the algorithm the OP holds",
			body: withMember("introspection_signed_response_alg", "ES256"),
			want: http.StatusCreated,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t, op.RegistrationOption{})
			_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

			resp := f.post(t, tc.body, iat)
			defer resp.Body.Close()

			if resp.StatusCode != tc.want {
				raw, _ := io.ReadAll(resp.Body)
				t.Fatalf("status=%d want %d body=%s", resp.StatusCode, tc.want, raw)
			}
			if tc.want != http.StatusBadRequest {
				return
			}
			if got := decodeBody(t, resp); got["error"] != "invalid_client_metadata" {
				t.Errorf("error=%v want invalid_client_metadata", got["error"])
			}
		})
	}
}

// TestManage_Update_RefusesJARMSigningAlgTheOPWillNotUse pins that the
// RFC 7592 update path holds the JARM member to the same rule as
// registration. The two paths share a validator, and a member that is
// refused on the way in must not be a way to smuggle the same
// expectation in afterwards.
func TestManage_Update_RefusesJARMSigningAlgTheOPWillNotUse(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	created := f.register(t, nil)

	body := minimalMetadata()
	body["authorization_signed_response_alg"] = "RS256"
	resp := f.manage(t, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	if got := decodeBody(t, resp); got["error"] != "invalid_client_metadata" {
		t.Errorf("error=%v want invalid_client_metadata", got["error"])
	}
}
