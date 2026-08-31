package discovery_test

import (
	"slices"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/discovery"
)

// encryptionInput returns the minimum Input that advertises a JWE
// inventory, with the feature bits the caller wants layered on top. The
// inbound list matches the outbound one, standing for an OP holding a
// key of every advertised family; the tests that care about the
// difference override it.
func encryptionInput(features discovery.Features) discovery.Input {
	return discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints: discovery.EndpointPaths{
			JWKS: "/jwks", Authorize: "/auth", Token: "/token", UserInfo: "/userinfo",
			Introspect: "/introspect",
		},
		Features:                       features,
		GrantsSupported:                []string{"authorization_code"},
		EncryptionAlgsSupported:        []string{"RSA-OAEP-256", "ECDH-ES"},
		EncryptionEncsSupported:        []string{"A128GCM", "A256GCM"},
		InboundEncryptionAlgsSupported: []string{"RSA-OAEP-256", "ECDH-ES"},
	}
}

// TestBuild_InboundEncryptionAlgsAreTheInboundList pins the inbound
// array to the algs the OP can actually decrypt with, independently of
// the wider inventory it negotiates outbound. An encrypted request
// object is addressed to the OP's own key, so an alg no configured key
// backs is an offer no RP can take up: it selects a recipient the OP's
// JWKS does not carry, and the request object it builds anyway is
// refused as invalid_request_object with nothing naming the cause.
func TestBuild_InboundEncryptionAlgsAreTheInboundList(t *testing.T) {
	t.Parallel()

	in := encryptionInput(discovery.Features{
		AuthorizeEndpoint: true, JAR: true, EncryptionInbound: true,
	})
	in.InboundEncryptionAlgsSupported = []string{"RSA-OAEP-256"}

	doc := discovery.Build(in)
	if !slices.Equal(doc.RequestObjectEncryptionAlgValuesSupported, []string{"RSA-OAEP-256"}) {
		t.Errorf("request_object_encryption_alg_values_supported=%v want [RSA-OAEP-256]",
			doc.RequestObjectEncryptionAlgValuesSupported)
	}
	// The outbound families negotiate against the relying party's key,
	// so the OP's own key inventory must not shrink them.
	if !slices.Equal(doc.IDTokenEncryptionAlgValuesSupported, in.EncryptionAlgsSupported) {
		t.Errorf("id_token_encryption_alg_values_supported=%v want %v",
			doc.IDTokenEncryptionAlgValuesSupported, in.EncryptionAlgsSupported)
	}
}

// TestBuild_NoInboundEncryptionAlgsSuppressesRequestObject pins the
// fail-closed end of the same rule: an OP holding a keyset whose
// families back none of the advertised algs claims no inbound
// capability at all rather than advertising one it cannot serve.
func TestBuild_NoInboundEncryptionAlgsSuppressesRequestObject(t *testing.T) {
	t.Parallel()

	in := encryptionInput(discovery.Features{
		AuthorizeEndpoint: true, JAR: true, EncryptionInbound: true,
	})
	in.InboundEncryptionAlgsSupported = nil

	doc := discovery.Build(in)
	if len(doc.RequestObjectEncryptionAlgValuesSupported) != 0 {
		t.Errorf("request_object_encryption_alg_values_supported=%v want empty",
			doc.RequestObjectEncryptionAlgValuesSupported)
	}
	if len(doc.RequestObjectEncryptionEncValuesSupported) != 0 {
		t.Errorf("request_object_encryption_enc_values_supported=%v want empty",
			doc.RequestObjectEncryptionEncValuesSupported)
	}
}

// TestBuild_OutboundEncryptionNeedsNoKeyset is the correction this
// split exists for: the OP encrypts an id_token / userinfo / JARM /
// introspection response to a key from the *client's* JWKS, so it can
// serve all four without holding an encryption key of its own.
// Advertising them only alongside a keyset told RPs the OP could not do
// something it could.
func TestBuild_OutboundEncryptionNeedsNoKeyset(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(encryptionInput(discovery.Features{
		AuthorizeEndpoint: true, JAR: true, JARM: true, Introspect: true,
		EncryptionInbound: false,
	}))

	outbound := map[string][]string{
		"id_token_encryption_alg":      doc.IDTokenEncryptionAlgValuesSupported,
		"id_token_encryption_enc":      doc.IDTokenEncryptionEncValuesSupported,
		"userinfo_encryption_alg":      doc.UserInfoEncryptionAlgValuesSupported,
		"userinfo_encryption_enc":      doc.UserInfoEncryptionEncValuesSupported,
		"authorization_encryption_alg": doc.AuthorizationEncryptionAlgValuesSupported,
		"authorization_encryption_enc": doc.AuthorizationEncryptionEncValuesSupported,
		"introspection_encryption_alg": doc.IntrospectionEncryptionAlgValuesSupported,
		"introspection_encryption_enc": doc.IntrospectionEncryptionEncValuesSupported,
	}
	for name, got := range outbound {
		if len(got) == 0 {
			t.Errorf("%s_values_supported is empty without an encryption keyset", name)
		}
	}

	if len(doc.RequestObjectEncryptionAlgValuesSupported) != 0 {
		t.Errorf("request_object_encryption_alg_values_supported present without a decryption keyset: %v",
			doc.RequestObjectEncryptionAlgValuesSupported)
	}
	if len(doc.RequestObjectEncryptionEncValuesSupported) != 0 {
		t.Errorf("request_object_encryption_enc_values_supported present without a decryption keyset: %v",
			doc.RequestObjectEncryptionEncValuesSupported)
	}
}

// TestBuild_InboundEncryptionNeedsKeysetAndJAR pins the one direction
// that genuinely depends on the OP's own keyset: an encrypted request
// object is addressed to the OP, so both the keyset and JAR are
// required before the OP claims to accept one.
func TestBuild_InboundEncryptionNeedsKeysetAndJAR(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		features discovery.Features
		want     bool
	}{
		{
			name:     "keyset_and_jar",
			features: discovery.Features{AuthorizeEndpoint: true, JAR: true, EncryptionInbound: true},
			want:     true,
		},
		{
			name:     "keyset_without_jar",
			features: discovery.Features{AuthorizeEndpoint: true, EncryptionInbound: true},
			want:     false,
		},
		{
			name:     "jar_without_keyset",
			features: discovery.Features{AuthorizeEndpoint: true, JAR: true},
			want:     false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc := discovery.Build(encryptionInput(tc.features))
			got := len(doc.RequestObjectEncryptionAlgValuesSupported) > 0
			if got != tc.want {
				t.Fatalf("request_object_encryption_alg_values_supported present=%v want %v", got, tc.want)
			}
		})
	}
}

// TestBuild_FeatureGatedOutboundFields pins that the two outbound
// families riding on another protocol feature stay gated on it: an OP
// that does not serve JARM or introspection must not advertise
// encryption for a response it never produces.
func TestBuild_FeatureGatedOutboundFields(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(encryptionInput(discovery.Features{AuthorizeEndpoint: true}))

	if len(doc.IDTokenEncryptionAlgValuesSupported) == 0 {
		t.Error("id_token_encryption_alg_values_supported must not be feature-gated")
	}
	if len(doc.AuthorizationEncryptionAlgValuesSupported) != 0 {
		t.Error("authorization_encryption_alg_values_supported present without JARM")
	}
	if len(doc.IntrospectionEncryptionAlgValuesSupported) != 0 {
		t.Error("introspection_encryption_alg_values_supported present without Introspect")
	}
}

// TestBuild_EmptyInventorySuppressesEveryField pins the deliberate
// "negotiate nothing" posture: an operator who narrowed the inventory
// to the empty set advertises no encryption at all, on either
// direction.
func TestBuild_EmptyInventorySuppressesEveryField(t *testing.T) {
	t.Parallel()

	in := encryptionInput(discovery.Features{
		AuthorizeEndpoint: true, JAR: true, JARM: true, Introspect: true,
		EncryptionInbound: true,
	})
	in.EncryptionAlgsSupported = []string{}

	doc := discovery.Build(in)
	for name, got := range map[string][]string{
		"id_token_encryption_alg":       doc.IDTokenEncryptionAlgValuesSupported,
		"id_token_encryption_enc":       doc.IDTokenEncryptionEncValuesSupported,
		"userinfo_encryption_alg":       doc.UserInfoEncryptionAlgValuesSupported,
		"request_object_encryption_alg": doc.RequestObjectEncryptionAlgValuesSupported,
		"authorization_encryption_alg":  doc.AuthorizationEncryptionAlgValuesSupported,
		"introspection_encryption_alg":  doc.IntrospectionEncryptionAlgValuesSupported,
	} {
		if len(got) != 0 {
			t.Errorf("%s_values_supported present with an empty inventory: %v", name, got)
		}
	}
}
