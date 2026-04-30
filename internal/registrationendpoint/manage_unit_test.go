package registrationendpoint

import (
	"encoding/json"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

func TestSecretMaterialForUpdate_PublicToConfidentialMintsSecret(t *testing.T) {
	t.Parallel()

	raw, hash, err := secretMaterialForUpdate(&store.Client{}, true)
	if err != nil {
		t.Fatalf("secretMaterialForUpdate: %v", err)
	}
	if raw == "" {
		t.Fatal("raw secret is empty")
	}
	if hash == "" {
		t.Fatal("hash is empty")
	}
}

func TestSecretMaterialForUpdate_ConfidentialToConfidentialKeepsHash(t *testing.T) {
	t.Parallel()

	raw, hash, err := secretMaterialForUpdate(&store.Client{SecretHash: "existing-hash"}, true)
	if err != nil {
		t.Fatalf("secretMaterialForUpdate: %v", err)
	}
	if raw != "" {
		t.Fatalf("raw=%q want empty", raw)
	}
	if hash != "existing-hash" {
		t.Fatalf("hash=%q want existing-hash", hash)
	}
}

func TestValidateManageUpdateRequest_RejectsReservedFields(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		extras metadataExtras
		want   string
	}{
		{
			name: "registration access token",
			extras: metadataExtras{
				RegAccessToken: json.RawMessage(`"rat"`),
			},
			want: "request MUST NOT include the registration_access_token field",
		},
		{
			name: "registration client uri",
			extras: metadataExtras{
				RegClientURI: json.RawMessage(`"https://op.example/register/client"`),
			},
			want: "request MUST NOT include the registration_client_uri field",
		},
		{
			name: "client secret expires at",
			extras: metadataExtras{
				ClientSecretExp: json.RawMessage(`0`),
			},
			want: "request MUST NOT include the client_secret_expires_at field",
		},
		{
			name: "client id issued at",
			extras: metadataExtras{
				ClientIDIssuedAt: json.RawMessage(`123`),
			},
			want: "request MUST NOT include the client_id_issued_at field",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateManageUpdateRequest(&store.Client{ID: "client-1"}, "client-1", tc.extras)
			if err == nil {
				t.Fatal("expected error")
			}
			if err.Error() != tc.want {
				t.Fatalf("error=%q want %q", err.Error(), tc.want)
			}
		})
	}
}

func TestValidateManageUpdateRequest_ClientIDMismatchRejected(t *testing.T) {
	t.Parallel()

	err := validateManageUpdateRequest(&store.Client{ID: "client-1"}, "client-1", metadataExtras{ClientID: "client-2"})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "client_id is immutable" {
		t.Fatalf("error=%q want client_id is immutable", err.Error())
	}
}

func TestValidateManageClientSecret(t *testing.T) {
	t.Parallel()

	raw, hash, err := newClientSecret()
	if err != nil {
		t.Fatalf("newClientSecret: %v", err)
	}
	client := &store.Client{ID: "client-1", SecretHash: hash}

	cases := []struct {
		name    string
		payload json.RawMessage
		wantErr bool
	}{
		{name: "matching secret", payload: json.RawMessage(`"` + raw + `"`), wantErr: false},
		{name: "null secret", payload: json.RawMessage(`null`), wantErr: true},
		{name: "wrong secret", payload: json.RawMessage(`"wrong"`), wantErr: true},
		{name: "wrong type", payload: json.RawMessage(`123`), wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateManageClientSecret(client, tc.payload)
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
