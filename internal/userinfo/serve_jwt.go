package userinfo

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/clientencjwks"
	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/op/store"
)

// userInfoJWTType is the JOSE "typ" header stamped on a signed userinfo
// response. OIDC Core 1.0 §5.3.2 does not mandate a specific typ value
// for signed userinfo; "JWT" is the safe default that RP libraries
// strict-checking the type recognise.
const userInfoJWTType = "JWT"

// userInfoJWTContentType is the HTTP Content-Type the OP emits for a
// JWT-shaped userinfo response (signed-only or signed-then-encrypted).
// OIDC Core 1.0 §5.3.2 specifies "application/jwt" for both shapes.
const userInfoJWTContentType = "application/jwt"

// wantsJWTShape reports whether the request opted into the JWT-shape
// userinfo response via its Accept header (OIDC Core 1.0 §5.3.1.1: a
// client signals the JWT shape by listing application/jwt in Accept).
// The check is media-type aware so an Accept value carrying parameters
// (charset, q-values) is recognised; "*/*" alone is NOT treated as a
// JWT-shape opt-in because the JSON shape is the OIDC default.
func wantsJWTShape(r *http.Request) bool {
	header := r.Header.Get("Accept")
	if header == "" {
		return false
	}
	for _, raw := range strings.Split(header, ",") {
		mediatype, _, err := mime.ParseMediaType(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		if mediatype == userInfoJWTContentType {
			return true
		}
	}
	return false
}

// writeUserInfoJWT signs the userinfo claim map with the OP's active
// signing key, optionally wraps the JWS in a JWE addressed to the
// client's `use=enc` recipient, and writes the application/jwt
// response. The function is the JWT-shape counterpart of [writeJSON].
//
// The signed body always carries `iss` and `aud` in addition to the
// scope-derived claim set so the RP can satisfy OIDC Core 1.0 §5.3.2's
// MUST clauses (an RP-side parser that hard-checks the values has
// somewhere to bind to). On any failure the function emits the
// standard 500 response without leaking which sub-cause produced the
// rejection — the operator recovers the cause from the audit / log
// stream, the wire stays opaque.
func writeUserInfoJWT(
	ctx context.Context,
	w http.ResponseWriter,
	deps HandlerDeps,
	clientID string,
	body map[string]any,
) {
	// Stamp iss / aud on the signed body. The handler does not overwrite
	// an existing iss / aud (the assembler does not currently emit either,
	// but a future scope projection could; respecting prior values keeps
	// the splice future-proof).
	if _, ok := body["iss"]; !ok && deps.Issuer != "" {
		body["iss"] = deps.Issuer
	}
	if _, ok := body["aud"]; !ok && clientID != "" {
		body["aud"] = clientID
	}

	signed, err := signUserInfoJWT(deps.Keys, body)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	out, err := maybeEncryptUserInfo(ctx, deps, clientID, signed)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", userInfoJWTContentType)
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Pragma", "no-cache")
	// out is a compact JWS or JWE produced by the OP's own JOSE
	// pipeline (sign + optional nested JWE wrap). Content-Type pins
	// it as application/jwt; the taint gosec sees through client.*
	// metadata is allow-list validated by clientencjwks.ResolveRecipient
	// before reaching the encrypter.
	_, _ = w.Write([]byte(out)) //nolint:gosec // G705: JOSE output, JWT Content-Type, no HTML surface.
}

// signUserInfoJWT serialises body as a compact-serialised ES256 JWS
// using the OP's active signing key (RFC 7515 / OIDC Core 1.0 §5.3.2).
// The `kid` header is set to the active Entry's KeyID; `typ` is "JWT".
// The function fails when [HandlerDeps.Keys] is nil (a misconfigured
// embedder did not pass a keyset) or when the active entry has a nil
// Signer (defensive — [keys.NewSet] rejects this at construction time).
func signUserInfoJWT(set *keys.Set, body map[string]any) (string, error) {
	if set == nil {
		return "", errors.New("userinfo: signing keyset is not configured")
	}
	active := set.Active()
	if active.Signer == nil {
		return "", errors.New("userinfo: active signing key has nil Signer")
	}
	sk := josev4.SigningKey{
		Algorithm: josev4.ES256,
		Key: josev4.JSONWebKey{
			Key:       active.Signer,
			KeyID:     active.KeyID,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		},
	}
	opts := (&josev4.SignerOptions{}).WithType(josev4.ContentType(userInfoJWTType))
	signer, err := josev4.NewSigner(sk, opts)
	if err != nil {
		return "", fmt.Errorf("userinfo: build signer: %w", err)
	}
	out, err := jwt.Signed(signer).Claims(body).Serialize()
	if err != nil {
		return "", fmt.Errorf("userinfo: sign: %w", err)
	}
	return out, nil
}

// maybeEncryptUserInfo wraps a signed userinfo JWT in a JWE addressed
// to the client's `use=enc` recipient when the client registered
// userinfo_encrypted_response_alg / _enc (OIDC Core 1.0 §5.3.2 / RFC
// 7516). The returned string is the JWE compact serialisation; on
// [clientencjwks.ErrNoEncryptionConfigured] the function returns
// signed verbatim so the JWS-only path stays a single code surface.
//
// Failure semantics match the task spec: any other resolver error
// surfaces verbatim so the caller maps it onto a 500 response. The
// caller MUST NOT silently fall back to the signed JWS when
// encryption was requested but failed — that would be a silent
// downgrade of an opt-in confidentiality property.
//
// Resolution proceeds:
//
//  1. If [HandlerDeps.ClientEncJWKs] is nil OR clientID is empty OR
//     the client lookup fails, the function treats the request as
//     "no encryption configured" (the embedder did not wire
//     outbound encryption, or the AT carried no client_id we could
//     resolve, or the client was deleted between issuance and the
//     userinfo call).
//  2. Otherwise the resolver is consulted with the client's
//     registered (alg, enc) pair. An empty (alg, enc) — the client
//     did not register encryption — collapses onto
//     [clientencjwks.ErrNoEncryptionConfigured] and the signed JWS
//     is returned verbatim.
//  3. A successful resolution feeds [jose.EncryptNestedJWT] which
//     produces the 5-segment JWE with `cty=JWT` per RFC 7519 §5.2.
func maybeEncryptUserInfo(
	ctx context.Context,
	deps HandlerDeps,
	clientID, signedJWT string,
) (string, error) {
	if deps.ClientEncJWKs == nil || clientID == "" || deps.Clients == nil {
		return signedJWT, nil
	}
	client, err := deps.Clients.GetClient(ctx, clientID)
	if err != nil {
		// Client deleted between AT issuance and the userinfo call: the
		// caller maps this onto invalid_token via the bearer challenge,
		// but at this point we only have the signed body to return. The
		// JWT-shape entry point checks the client lookup before calling
		// this helper so this branch is defensive.
		return "", fmt.Errorf("userinfo: client lookup failed: %w", err)
	}
	rcpt, err := deps.ClientEncJWKs.ResolveRecipient(
		ctx,
		client,
		client.UserInfoEncryptedResponseAlg,
		client.UserInfoEncryptedResponseEnc,
	)
	if err != nil {
		if errors.Is(err, clientencjwks.ErrNoEncryptionConfigured) {
			return signedJWT, nil
		}
		return "", err
	}
	jwe, err := jose.EncryptNestedJWT(signedJWT, rcpt)
	if err != nil {
		return "", fmt.Errorf("userinfo: encrypt: %w", err)
	}
	return jwe, nil
}

// resolveClient fetches the AT-bound client when the JWT-shape branch
// is going to fire. A nil [HandlerDeps.Clients] disables the lookup;
// the caller treats that as "no JWT-shape" and falls back to JSON.
//
// The function returns ([client], true) on a successful read, and
// (nil, false) when the client was deleted between AT issuance and the
// userinfo call — the caller MUST then emit the invalid_token challenge
// rather than a plain signed body, because the AT was minted for a
// client the OP no longer recognises.
func resolveClient(ctx context.Context, deps HandlerDeps, clientID string) (*store.Client, bool) {
	if deps.Clients == nil || clientID == "" {
		return nil, true
	}
	c, err := deps.Clients.GetClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, false
		}
		return nil, false
	}
	return c, true
}
