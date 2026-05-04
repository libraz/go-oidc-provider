//go:build example

// service_b.go — resource-server-side actions for example
// 32-token-exchange-delegation.
//
// In a real deployment this code lives in service-b's resource-server
// binary: an incoming request carries the access_token service-a got
// back from /oidc/token, the RS decodes it, walks the act chain, and
// authorises the call. The example pins this minimal pattern so the
// read shape — issuer / audience / sub / act — is observable next to
// the OP-side write that produces it.

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
)

// serviceBVerify is the resource-server side of the round-trip. It
// decodes the JWT (without signature verification — the OP is the
// same process), asserts the issuer / audience / sub fields, walks
// the act chain, and prints the canonical chain summary line. A
// production RS would verify the signature against the OP's JWKS;
// the comment block on [decodeJWTClaims] explains why this example
// elides that step.
func serviceBVerify(logger *slog.Logger, issuer, accessToken string) error {
	claims, err := decodeJWTClaims(accessToken)
	if err != nil {
		return err
	}

	if got, _ := claims["iss"].(string); got != issuer {
		return fmt.Errorf("iss=%q want %q", got, issuer)
	}
	if got, _ := claims["sub"].(string); got != userSubject {
		return fmt.Errorf("sub=%q want %q", got, userSubject)
	}
	// RFC 8707 §2 normalises audience values: lowercase scheme + host,
	// trailing-slash stripped. The OP serves the canonical form, so
	// the RS-side check compares against the stripped variant.
	const wantAud = "https://api.service-b.example"
	if !audienceContains(claims["aud"], wantAud) {
		return fmt.Errorf("aud=%v does not contain %q", claims["aud"], wantAud)
	}
	if got, _ := claims["scope"].(string); got != scopeNarrow {
		return fmt.Errorf("scope=%q want %q", got, scopeNarrow)
	}
	act, ok := claims["act"].(map[string]any)
	if !ok {
		return fmt.Errorf("act claim absent on exchanged token; claims=%v", claims)
	}
	actSub, _ := act["sub"].(string)
	if actSub != serviceAID {
		return fmt.Errorf("act.sub=%q want %q (impersonation chain names the calling client)", actSub, serviceAID)
	}

	logger.Info("service-b accepted exchanged token",
		slog.String("sub", userSubject),
		slog.String("act.sub", serviceAID),
		slog.String("aud", wantAud),
		slog.String("scope", scopeNarrow))
	fmt.Printf("[service-b] User %s (acting via %s) has %s access to %s\n",
		userSubject, serviceAID, scopeNarrow, serviceBID)
	return nil
}

// decodeJWTClaims pulls the payload out of a compact JWS without
// verifying the signature. The example is single-process: the OP
// that signed the token is the same process verifying it, so the
// signature would only confirm what we already know. Production
// resource servers MUST verify against the OP's published JWKS via
// a real JWS verifier (go-jose, jose-jwt, ...).
func decodeJWTClaims(jws string) (map[string]any, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("compact JWS expected 3 parts, got %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWS payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("decode JWS claims: %w", err)
	}
	return claims, nil
}

// audienceContains reports whether aud (RFC 7519 §4.1.3 — string or
// []string) carries the supplied value. The function is tolerant of
// either wire shape so the RS-side check stays uniform across single-
// and multi-audience tokens.
func audienceContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
