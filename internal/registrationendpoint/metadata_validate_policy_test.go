package registrationendpoint_test

import (
	"io"
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestRegister_NarrowedEncryptionAlgs_RejectsExcludedAlg pins the DCR
// half of an operator narrowing. Registering a client for an algorithm
// op.WithSupportedEncryptionAlgs excluded used to succeed, minting a
// client whose every encrypted exchange the runtime would then refuse;
// the registration is now rejected up front, on every one of the five
// encryption families.
func TestRegister_NarrowedEncryptionAlgs_RejectsExcludedAlg(t *testing.T) {
	t.Parallel()

	for _, fam := range jweFamilies() {
		t.Run(fam.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t, op.RegistrationOption{},
				op.WithSupportedEncryptionAlgs([]string{"ECDH-ES"}, nil))
			_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})
			body := minimalMetadata()
			body[fam.algKey] = "RSA-OAEP-256"
			body[fam.encKey] = fam.encGood

			resp := f.post(t, body, iat)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				raw, _ := io.ReadAll(resp.Body)
				t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
			}
			got := decodeBody(t, resp)
			if got["error"] != "invalid_client_metadata" {
				t.Errorf("error=%v want invalid_client_metadata", got["error"])
			}
		})
	}
}

// TestRegister_NarrowedEncryptionEncs_RejectsExcludedEnc mirrors the
// alg case for the content-encryption half.
func TestRegister_NarrowedEncryptionEncs_RejectsExcludedEnc(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{},
		op.WithSupportedEncryptionAlgs(nil, []string{"A256GCM"}))
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})
	body := minimalMetadata()
	body["id_token_encrypted_response_alg"] = "RSA-OAEP-256"
	body["id_token_encrypted_response_enc"] = "A128GCM"

	resp := f.post(t, body, iat)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
}

// TestRegister_NarrowedEncryptionAlgs_AdmitsRetainedAlg guards the
// other direction: narrowing must not reject the pair the operator
// deliberately kept.
func TestRegister_NarrowedEncryptionAlgs_AdmitsRetainedAlg(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{},
		op.WithSupportedEncryptionAlgs([]string{"ECDH-ES"}, []string{"A256GCM"}))
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})
	body := minimalMetadata()
	body["id_token_encrypted_response_alg"] = "ECDH-ES"
	body["id_token_encrypted_response_enc"] = "A256GCM"

	resp := f.post(t, body, iat)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 201 body=%s", resp.StatusCode, raw)
	}
}

// TestRegister_UnnarrowedOP_AdmitsEveryShippedAlg pins the default: an
// OP that never called op.WithSupportedEncryptionAlgs stays at the
// library ceiling, so the narrowing gate cannot silently tighten the
// baseline.
func TestRegister_UnnarrowedOP_AdmitsEveryShippedAlg(t *testing.T) {
	t.Parallel()

	for _, alg := range op.SupportedEncryptionAlgs() {
		t.Run(alg, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t, op.RegistrationOption{})
			_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})
			body := minimalMetadata()
			body["id_token_encrypted_response_alg"] = alg
			body["id_token_encrypted_response_enc"] = "A256GCM"

			resp := f.post(t, body, iat)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				raw, _ := io.ReadAll(resp.Body)
				t.Fatalf("status=%d want 201 body=%s", resp.StatusCode, raw)
			}
		})
	}
}
