package jar_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/timex"
)

// rpEncryptionOnlyJWK is a JWK the JOSE layer cannot turn into a key: an
// OKP curve outside the Ed25519 it implements. An RP that offers ECDH-ES
// encryption publishes a member of this shape next to its signing key.
const rpEncryptionOnlyJWK = `{"kty":"OKP","crv":"X25519","x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo","use":"enc","kid":"rp-enc"}`

// TestVerify_JWKSCarryingUnsupportedMember pins the end-to-end JAR path for
// an RP whose published keyset mixes a supported signing key with a key
// type this build does not implement. RFC 7517 §5 requires the unsupported
// member to be ignored; taking it as a document-level failure would lock
// the client out of request objects entirely.
func TestVerify_JWKSCarryingUnsupportedMember(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	raw, jwk, _ := signedRequestObject(t, happyClaims(now), testKID)
	member, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal signing JWK: %v", err)
	}
	document := `{"keys":[` + rpEncryptionOnlyJWK + `,` + string(member) + `]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write([]byte(document))
	}))
	defer srv.Close()

	f := jar.NewFetcher(timex.SystemClock)
	f.SetAllowPrivate(true) // httptest binds to 127.0.0.1.
	keys, err := f.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	v := newTestVerifier(t, now, keys)
	if _, err := v.Verify(context.Background(), raw, testClientID, newClient()); err != nil {
		t.Fatalf("Verify with a mixed keyset: %v", err)
	}
}
