package jar

import (
	"bytes"
	"encoding/json"
	"fmt"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

// Object is the parsed view of a JAR request object. The struct holds
// the original compact JWS so the caller can hand it to a verifier, the
// parsed header values that drove the keyset lookup, and the decoded
// claim bag (kept untyped because RFC 9101 admits any of the OAuth /
// OIDC authorization parameters as a claim).
//
// Object fields are read-only; callers MUST NOT mutate the JWS or the
// claim map after construction.
type Object struct {
	// Raw is the compact-serialised JWS the client presented. It is
	// preserved so audit logs can reproduce the input; the verifier
	// re-parses Raw rather than trusting the parsed projection.
	Raw string

	// Algorithm is the [jose.Algorithm] taken from the JWS protected
	// header. The value is already inside the project allow-list when
	// Object reaches the caller, so the per-client pin is the only
	// remaining check.
	Algorithm jose.Algorithm

	// KeyID is the "kid" header carried by the JWS, or "" when the
	// header is absent. The verifier uses it to pick a key from the
	// resolved client keyset.
	KeyID string

	// Type is the "typ" protected header. RFC 9101 §10.8 uses
	// "oauth-authz-req+jwt" to separate request objects from other
	// client-signed JWTs that may share key material.
	Type string

	// Claims is the decoded payload as a generic map. JSON numbers are
	// decoded into json.Number values so the claim consumer can pick
	// the integer / float interpretation explicitly. RFC 9101 §6.1
	// forbids nested "request" / "request_uri" inside the payload;
	// [Verify] enforces that rule.
	Claims map[string]any

	// jws is the underlying go-jose object retained for signature
	// verification. It is not exported because callers should go
	// through [Verifier.Verify] rather than reaching into go-jose
	// internals directly.
	jws *josev4.JSONWebSignature
}

// Parse splits raw into header + payload without verifying the signature.
// The return value is suitable for inspecting "kid" / "alg" before the
// caller looks up the matching keyset.
//
// Parse rejects "alg=none", the HMAC family, and any value outside the
// project allow-list (see [jose.Algorithm]). The check happens
// before any signature work so a downgrade attack cannot trick a later
// verifier into accepting a weaker primitive.
func Parse(raw string) (*Object, error) {
	if raw == "" {
		return nil, fmt.Errorf("%w: empty request object", ErrParse)
	}
	jws, alg, err := jose.ParseSigned(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}
	if len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("%w: request object must carry exactly one signature", ErrParse)
	}
	hdr := jws.Signatures[0].Header
	claims, err := decodeUnverifiedPayload(jws)
	if err != nil {
		return nil, err
	}
	return &Object{
		Raw:       raw,
		Algorithm: alg,
		KeyID:     hdr.KeyID,
		Type:      headerString(hdr.ExtraHeaders[josev4.HeaderType]),
		Claims:    claims,
		jws:       jws,
	}, nil
}

func headerString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case josev4.ContentType:
		return string(t)
	default:
		return ""
	}
}

// decodeUnverifiedPayload extracts the JSON object body from the JWS
// without verifying the signature. The caller MUST NOT trust the values
// in the returned map until [Verifier.Verify] confirms the signature.
//
// The function is split out so [Parse] can populate [Object.Claims]
// before signature verification — the keyset lookup needs the "kid"
// header, and presenting attacker-supplied header values is preferable
// to letting the verifier touch unverified payload bytes elsewhere.
func decodeUnverifiedPayload(jws *josev4.JSONWebSignature) (map[string]any, error) {
	payload := jws.UnsafePayloadWithoutVerification()
	out := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("%w: decode payload: %w", ErrParse, err)
	}
	return out, nil
}
