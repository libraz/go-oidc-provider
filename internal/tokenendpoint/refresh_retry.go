package tokenendpoint

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/op/store"
)

const refreshRetryKeyLabel = "go-oidc-provider/refresh-retry-response/v1"

// refreshRetryFormatV0 is the leading format-version byte of a sealed retry
// response, followed by nonce||ciphertext||tag.
const refreshRetryFormatV0 byte = 0

var errRefreshRetryBadKey = errors.New("refresh retry key is invalid")

// retryStore returns the durable retry-response store behind deps.RefreshTokens.
func retryStore(deps Deps) (store.RefreshRetryResponseStore, error) {
	retries, ok := deps.RefreshTokens.(store.RefreshRetryResponseStore)
	if !ok {
		return nil, errors.New("tokenendpoint: refresh store does not support durable retry responses")
	}
	return retries, nil
}

// refreshRetryRing derives one AES key per configured key, in order, so the
// first seals and every one opens.
func refreshRetryRing(material [][]byte) (*keys.AEADRing, error) {
	derived := make([][]byte, len(material))
	for i, m := range material {
		derived[i] = deriveRefreshRetryKey(m)
	}
	return keys.NewAEADRing(errRefreshRetryBadKey, derived[0], derived[1:]...)
}

// sealRefreshRetryResponse encrypts the exact successful /token response.
// Cookie keys are domain-separated with HMAC before AES-GCM use, so cookie
// encryption and refresh-response encryption never reuse an AES key directly.
func sealRefreshRetryResponse(material [][]byte, predecessor string, response successResponse) ([]byte, error) {
	plain, err := json.Marshal(response) //nolint:gosec // encrypted immediately below; response is intentionally cached for RFC 9700 retry recovery.
	if err != nil {
		return nil, fmt.Errorf("refresh retry marshal: %w", err)
	}
	if len(material) == 0 {
		return nil, errors.New("refresh retry has no encryption keys")
	}
	ring, err := refreshRetryRing(material)
	if err != nil {
		return nil, err
	}
	return append([]byte{refreshRetryFormatV0}, ring.Seal(plain, []byte(predecessor))...), nil
}

func openRefreshRetryResponse(material [][]byte, predecessor string, sealed []byte) (successResponse, error) {
	if len(material) == 0 || len(sealed) < 1 {
		return successResponse{}, errors.New("refresh retry response is unavailable")
	}
	ring, err := refreshRetryRing(material)
	if err != nil {
		return successResponse{}, err
	}
	// Decrypt tries every configured key, so reordering during rotation is
	// safe for records sealed by an earlier process.
	plain, ok := ring.Open(sealed[1:], []byte(predecessor))
	if !ok {
		return successResponse{}, errors.New("refresh retry response cannot be decrypted")
	}
	var response successResponse
	if err := json.Unmarshal(plain, &response); err != nil {
		return successResponse{}, fmt.Errorf("refresh retry unmarshal: %w", err)
	}
	if response.AccessToken == "" || response.RefreshToken == "" {
		return successResponse{}, errors.New("refresh retry response is malformed")
	}
	return response, nil
}

func deriveRefreshRetryKey(material []byte) []byte {
	mac := hmac.New(sha256.New, material)
	_, _ = mac.Write([]byte(refreshRetryKeyLabel))
	return mac.Sum(nil)
}
