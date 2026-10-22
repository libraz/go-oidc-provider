package devicecode

import (
	"crypto/sha256"
	"encoding/base64"
)

// GrantID derives the grant identifier the token endpoint issues a
// device authorization's credentials under. It is a one-way function of
// the device_code, so the grant can be found again from the code at
// revocation without the code itself ever appearing in a "gid" claim, a
// token row or an audit record. The prefix keeps it distinct from the
// plain hash the audit stream carries as device_code_hash.
func GrantID(deviceCode string) string {
	sum := sha256.Sum256([]byte("device_code:" + deviceCode))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
