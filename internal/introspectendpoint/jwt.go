package introspectendpoint

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/op/store"
)

// jwtMediaType is the wire content-type RFC 9701 §4 mandates for JWT
// introspection responses. The "+jwt" suffix tells the RP this is a
// compact-serialised JWS, not a JSON document.
const jwtMediaType = "application/token-introspection+jwt"

// jsonMediaType is the legacy JSON content-type the negotiator
// compares against when ranking the Accept header. Pulled into a
// constant so the parser cannot drift from the writer.
const jsonMediaType = "application/json"

// jwtTyp is the JWS header "typ" RFC 9701 §4 mandates. Aligns the
// header with the body media type so a JWT pulled out of context still
// self-describes.
const jwtTyp = "token-introspection+jwt"

// shouldEmitJWT applies the RFC 9701 §5 negotiation rule. The signer
// must be configured AND any one of:
//
//   - [Deps.RequireSignedIntrospection] is true (FAPI 2.0 Message
//     Signing §5: profile forces JWT regardless of client metadata or
//     Accept).
//   - The client has preregistered an introspection_signed_response_alg.
//   - The Accept header prefers the JWT media type.
//
// The profile-force check sits ahead of the per-client metadata check
// so a client that did not preregister an alg cannot use a JSON-asking
// Accept header to slip past a profile that forbids unsigned
// introspection.
func shouldEmitJWT(deps Deps, client *store.Client, accept string) bool {
	if deps.SigningKey.Signer == nil {
		return false
	}
	if deps.RequireSignedIntrospection {
		return true
	}
	if client.IntrospectionSignedResponseAlg != "" {
		return true
	}
	return preferJWT(accept)
}

// signIntrospectionJWT serialises body as the RFC 9701 §4 JWT
// envelope signed with deps.SigningKey. The function returns an
// error only on key/encoder faults; payload validation already
// happened on the JSON path.
func signIntrospectionJWT(deps Deps, audience string, body response) (string, error) {
	// Build the claim bundle: top-level iss/aud/iat plus the
	// token_introspection object whose fields mirror the JSON
	// response shape exactly (omitempty preserved).
	claims := map[string]any{
		"iss":                 deps.Issuer,
		"aud":                 audience,
		"iat":                 deps.now().UTC().Unix(),
		"token_introspection": body,
	}
	sk := josev4.SigningKey{
		Algorithm: josev4.ES256,
		Key: josev4.JSONWebKey{
			Key:       deps.SigningKey.Signer,
			KeyID:     deps.SigningKey.KeyID,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		},
	}
	opts := (&josev4.SignerOptions{}).WithType(jwtTyp)
	signer, err := josev4.NewSigner(sk, opts)
	if err != nil {
		return "", fmt.Errorf("introspect: build signer: %w", err)
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("introspect: sign jwt: %w", err)
	}
	return out, nil
}

// writeJWTResponse emits the RFC 9701 §4 envelope. Cache-Control is
// stamped so the JWT path matches the JSON path. A signing failure
// collapses onto the 500 error envelope: an unsigned wire body is
// unsafe under FAPI and the spec does not define a 5xx error format
// for the JWT path.
//
// When the authenticated client registered
// introspection_encrypted_response_alg / _enc (RFC 9701 §5) the signed
// envelope is wrapped in a JWE addressed to the RP's `use=enc` key
// before reaching the wire. A resolution / encryption failure also
// collapses onto the 500 envelope: silently emitting a signed-only
// body when the client opted into encryption is a confidentiality
// downgrade, so the path treats encryption faults the same as signing
// faults.
func writeJWTResponse(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	audience string,
	body response,
) {
	signed, err := signIntrospectionJWT(deps, audience, body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	out, err := maybeEncryptIntrospection(ctx, deps, client, signed)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	stampNoStore(w)
	w.Header().Set("Content-Type", jwtMediaType)
	w.WriteHeader(http.StatusOK)
	// out is a compact JWS or JWE produced by the OP's own JOSE
	// pipeline (sign + optional nested JWE wrap). Content-Type pins
	// it as application/token-introspection+jwt (RFC 9701 §5); the
	// taint gosec sees through client.* metadata is allow-list
	// validated by clientencjwks.ResolveRecipient before reaching
	// the encrypter.
	_, _ = w.Write([]byte(out)) //nolint:gosec // G705: JOSE output, JWT Content-Type, no HTML surface.
}

// preferJWT parses an Accept header and reports whether the JWT media
// type is preferred over JSON. See RFC 7231 §5.3.2 for the precedence
// rules; the parser is intentionally shallow — full media-range
// matching is out of scope. The decision rule:
//
//   - An Accept entry naming the JWT media type with q>0 wins outright
//     when its q-value strictly exceeds the JSON entry's q.
//   - On a tie (equal q, including the all-defaults case where every
//     entry is q=1.0) the more specific JWT type is preferred over
//     "application/json" / "*/*".
//   - An empty / missing Accept defaults to JSON: the v1.0 posture only
//     emits JWT on an explicit ask.
//   - "*/*" alone is treated as "no opinion" and routes to JSON.
//   - q=0 on the JWT entry means "explicitly not acceptable" and
//     forces JSON regardless of what other entries say.
func preferJWT(accept string) bool {
	if strings.TrimSpace(accept) == "" {
		return false
	}
	jwtQ := highestQ(accept, jwtMediaType)
	if jwtQ <= 0 {
		return false
	}
	jsonQ := highestQ(accept, jsonMediaType)
	if jsonQ < 0 {
		// JSON not mentioned at all: any positive JWT q wins.
		return true
	}
	// On equal q (including the all-defaults case where every entry
	// is q=1.0) the more specific JWT type is preferred over the
	// generic JSON media type.
	return jwtQ >= jsonQ
}

// highestQ returns the maximum q-value attached to mediaType across
// the comma-separated Accept entries, or -1 when mediaType is absent.
// A q=0 entry counts as "explicitly not acceptable" and is preserved
// in the return value so [preferJWT] can short-circuit.
func highestQ(accept, mediaType string) float64 {
	best := -1.0
	for _, entry := range strings.Split(accept, ",") {
		mt, q, ok := parseAcceptEntry(entry)
		if !ok || mt != mediaType {
			continue
		}
		if q > best {
			best = q
		}
	}
	return best
}

// parseAcceptEntry splits a single Accept header entry into its media
// type and q-value. Unparseable entries return ok=false so the caller
// can skip them; q defaults to 1.0 when the parameter is absent
// (RFC 7231 §5.3.1).
func parseAcceptEntry(entry string) (mediaType string, q float64, ok bool) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "", 0, false
	}
	parts := strings.Split(entry, ";")
	mediaType = strings.ToLower(strings.TrimSpace(parts[0]))
	if mediaType == "" {
		return "", 0, false
	}
	q = 1.0
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if !strings.HasPrefix(strings.ToLower(p), "q=") {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(p[2:]), 64)
		if err != nil {
			continue
		}
		q = v
	}
	return mediaType, q, true
}
