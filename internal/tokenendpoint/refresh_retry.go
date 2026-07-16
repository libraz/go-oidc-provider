package tokenendpoint

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

const refreshRetryKeyLabel = "go-oidc-provider/refresh-retry-response/v1"

// sealRefreshRetryResponse encrypts the exact successful /token response.
// Cookie keys are domain-separated with HMAC before AES-GCM use, so cookie
// encryption and refresh-response encryption never reuse an AES key directly.
func sealRefreshRetryResponse(keys [][]byte, predecessor string, response successResponse) ([]byte, error) {
	plain, err := json.Marshal(response) //nolint:gosec // encrypted immediately below; response is intentionally cached for RFC 9700 retry recovery.
	if err != nil {
		return nil, fmt.Errorf("refresh retry marshal: %w", err)
	}
	if len(keys) == 0 {
		return nil, errors.New("refresh retry has no encryption keys")
	}
	key := deriveRefreshRetryKey(keys[0])
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("refresh retry nonce: %w", err)
	}
	// Prefix the key index for future rotation. The active key is index zero;
	// decrypt still tries every configured key so reordering during rotation is
	// safe for records sealed by an earlier process.
	sealed := gcm.Seal(nil, nonce, plain, []byte(predecessor))
	out := make([]byte, 1+len(nonce)+len(sealed))
	out[0] = 0
	copy(out[1:], nonce)
	copy(out[1+len(nonce):], sealed)
	return out, nil
}

func openRefreshRetryResponse(keys [][]byte, predecessor string, sealed []byte) (successResponse, error) {
	if len(keys) == 0 || len(sealed) < 1 {
		return successResponse{}, errors.New("refresh retry response is unavailable")
	}
	for _, material := range keys {
		key := deriveRefreshRetryKey(material)
		block, err := aes.NewCipher(key)
		if err != nil {
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil || len(sealed) < 1+gcm.NonceSize() {
			continue
		}
		plain, err := gcm.Open(nil, sealed[1:1+gcm.NonceSize()], sealed[1+gcm.NonceSize():], []byte(predecessor))
		if err != nil {
			continue
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
	return successResponse{}, errors.New("refresh retry response cannot be decrypted")
}

func deriveRefreshRetryKey(material []byte) []byte {
	mac := hmac.New(sha256.New, material)
	_, _ = mac.Write([]byte(refreshRetryKeyLabel))
	return mac.Sum(nil)
}
