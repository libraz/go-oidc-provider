package clientauth

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Credentials is the parsed view of a token-endpoint request's
// authentication material. Exactly one of the SecretBasic / SecretPost /
// AssertionJWT fields is populated when ClientID is set; for the "none"
// method only ClientID is populated (and even that is optional, since a
// public client may convey the id through the request body).
type Credentials struct {
	// ClientID is the client identifier the request claimed. The parser
	// always normalises to a single value: when both Basic and body
	// channels carry an id, they MUST match (RFC 6749 §2.3.1) — a
	// disagreement triggers [ErrClientMismatch].
	ClientID string

	// Method is the authentication method the parser inferred from the
	// request shape. Verifiers MUST cross-check this against the
	// registered client's TokenEndpointAuthMethod.
	Method Method

	// SecretBasic carries the raw secret extracted from HTTP Basic.
	// Empty for non-Basic methods.
	SecretBasic string

	// SecretPost carries the raw secret extracted from the body form.
	// Empty for non-Post methods.
	SecretPost string

	// AssertionJWT carries the compact-serialised client_assertion when
	// MethodPrivateKeyJWT is detected. Empty otherwise.
	AssertionJWT string
}

// Parse extracts client credentials from an HTTP request without
// verifying them. The parser is strict: ambiguous combinations (e.g.
// Basic + form secret) are rejected with [ErrAmbiguousCredentials], and
// unsupported assertion types raise [ErrUnsupportedMethod].
//
// The function calls [http.Request.ParseForm] when needed, so callers
// MUST NOT pass a request whose body has already been read by an
// incompatible parser. The library's HTTP middleware always wraps
// requests through a multipart-aware decoder before reaching this layer.
func Parse(r *http.Request) (*Credentials, error) {
	if r == nil {
		return nil, errors.New("authn: nil request")
	}
	basicID, basicSecret, hasBasic, err := parseBasicAuth(r)
	if err != nil {
		return nil, err
	}

	form, err := readForm(r)
	if err != nil {
		return nil, err
	}
	parsed := extractFormCredentials(form)
	if err := validateCredentialChannels(hasBasic, parsed); err != nil {
		return nil, err
	}

	clientID, err := pickClientID(hasBasic, basicID, parsed.bodyID)
	if err != nil {
		return nil, err
	}

	creds := buildCredentials(clientID, hasBasic, basicSecret, parsed)
	if creds.Method == MethodPrivateKeyJWT && creds.ClientID == "" {
		// RFC 7521 §4.2 / RFC 7523 §3: the JWT bearer assertion's
		// "iss" / "sub" claims identify the client. When the request
		// omits client_id (FAPI 2.0 / OAuth 2.1 deployments often
		// drop the redundant parameter), the parser derives the
		// claim from the assertion header / payload so the verifier
		// can resolve the client. The value here is unverified and
		// is re-checked against the signed claim by the assertion
		// verifier — extraction is for lookup, not authorization.
		if id, err := unverifiedAssertionClientID(parsed.assertion); err == nil {
			creds.ClientID = id
		}
	}
	if creds.Method == MethodNone && creds.ClientID == "" {
		return nil, ErrNoCredentials
	}
	return creds, nil
}

// maxAssertionBytes caps the size of a client_assertion the parser
// will inspect for its unverified "iss" / "sub" claim. RFC 7523
// client_assertion JWTs in real deployments are typically 1-4 KB
// (a P-256 ECDSA signature plus the canonical FAPI / OIDC claim
// set); the 8 KB ceiling leaves comfortable headroom for embedders
// who chain extra header parameters (x5c chains, embedder-specific
// claims) while rejecting obviously-pathological inputs that would
// force [encoding/json.Unmarshal] to allocate megabytes of header /
// claim buffers before the verifier ever runs. The cap fires before
// any base64 decoding so a malicious client cannot pivot the parser
// onto an OOM by attaching a multi-megabyte header.
const maxAssertionBytes = 8 * 1024

// unverifiedAssertionClientID returns the assertion's "iss" claim
// without verifying the signature. Callers MUST treat the value as a
// lookup key only; the assertion verifier re-checks iss / sub against
// the resolved clientID before authenticating.
func unverifiedAssertionClientID(assertion string) (string, error) {
	if len(assertion) > maxAssertionBytes {
		return "", ErrAssertionMalformed
	}
	parts := strings.Split(assertion, ".")
	if len(parts) < 2 {
		return "", ErrAssertionMalformed
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ErrAssertionMalformed
	}
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
	}
	if err := jsonUnmarshal(body, &claims); err != nil {
		return "", ErrAssertionMalformed
	}
	switch {
	case claims.Iss != "":
		return claims.Iss, nil
	case claims.Sub != "":
		return claims.Sub, nil
	default:
		return "", ErrAssertionMalformed
	}
}

// formCredentials is the de-structured view of the credential-bearing
// fields the parser pulls off the form body. It exists so [Parse] can
// stay below the cyclomatic-complexity gate without losing the
// branch-by-branch readability the spec invites.
type formCredentials struct {
	bodyID        string
	bodySecret    string
	assertionType string
	assertion     string
	hasPostSecret bool
	hasAssertion  bool
}

func extractFormCredentials(form url.Values) formCredentials {
	bodyID := form.Get("client_id")
	bodySecret := form.Get("client_secret")
	assertion := form.Get("client_assertion")
	return formCredentials{
		bodyID:        bodyID,
		bodySecret:    bodySecret,
		assertionType: form.Get("client_assertion_type"),
		assertion:     assertion,
		hasPostSecret: bodySecret != "",
		hasAssertion:  assertion != "",
	}
}

func validateCredentialChannels(hasBasic bool, p formCredentials) error {
	if hasBasic && p.hasPostSecret {
		return ErrAmbiguousCredentials
	}
	if hasBasic && p.hasAssertion {
		return ErrAmbiguousCredentials
	}
	if p.hasPostSecret && p.hasAssertion {
		return ErrAmbiguousCredentials
	}
	if p.hasAssertion && p.assertionType != AssertionType {
		return ErrUnsupportedMethod
	}
	return nil
}

func buildCredentials(clientID string, hasBasic bool, basicSecret string, p formCredentials) *Credentials {
	creds := &Credentials{ClientID: clientID}
	switch {
	case hasBasic:
		creds.Method = MethodSecretBasic
		creds.SecretBasic = basicSecret
	case p.hasPostSecret:
		creds.Method = MethodSecretPost
		creds.SecretPost = p.bodySecret
	case p.hasAssertion:
		creds.Method = MethodPrivateKeyJWT
		creds.AssertionJWT = p.assertion
	default:
		creds.Method = MethodNone
	}
	return creds
}

// pickClientID reconciles the Basic-auth username and the body's
// client_id. Per RFC 6749 §2.3.1 the two MUST refer to the same client
// when both are present; we reject the request otherwise.
func pickClientID(hasBasic bool, basicID, bodyID string) (string, error) {
	switch {
	case hasBasic && bodyID != "" && basicID != bodyID:
		return "", ErrClientMismatch
	case hasBasic:
		return basicID, nil
	case bodyID != "":
		return bodyID, nil
	default:
		return "", nil
	}
}

// readForm parses the request's form fields. The parser only consults
// the form body, never the URL query, because OAuth credentials in the
// query string are forbidden by the security BCP (RFC 6750 §2.3 and
// RFC 9700 §2.4) — leaving them to leak through proxy logs is the kind
// of footgun this package exists to close.
func readForm(r *http.Request) (url.Values, error) {
	if err := r.ParseForm(); err != nil {
		return nil, ErrAssertionMalformed
	}
	return r.PostForm, nil
}

// parseBasicAuth extracts the HTTP Basic credentials per RFC 6749 §2.3.1
// and Appendix B: the username and password MUST be
// application/x-www-form-urlencoded before being joined with ":" and
// base64-encoded. Go's [http.Request.BasicAuth] only base64-decodes and
// splits on the first ":", so this wrapper applies the form-decode step
// the spec requires. A credential containing %, &, +, or space is
// authenticated under the same value the registry stores for it.
//
// A malformed header (non-Basic, undecodable base64, missing ":") is
// reported as hasBasic=false rather than an error so the caller can fall
// back to the form-body channel — that mirrors Go's BasicAuth contract
// and keeps the channel-selection logic identical to the pre-Appendix-B
// behaviour. A credential whose form-decode fails is the only path that
// raises [ErrCredentialsInvalid]; the wire shape is "the header was
// present but malformed", which is indistinguishable from "wrong
// secret" by design (same RFC 6749 §5.2 invalid_client envelope).
func parseBasicAuth(r *http.Request) (id, secret string, ok bool, err error) {
	rawID, rawSecret, hasBasic := r.BasicAuth()
	if !hasBasic {
		return "", "", false, nil
	}
	decodedID, derr := url.QueryUnescape(rawID)
	if derr != nil {
		return "", "", false, ErrCredentialsInvalid
	}
	decodedSecret, derr := url.QueryUnescape(rawSecret)
	if derr != nil {
		return "", "", false, ErrCredentialsInvalid
	}
	return decodedID, decodedSecret, true, nil
}
