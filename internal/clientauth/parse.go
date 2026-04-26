package clientauth

import (
	"errors"
	"net/http"
	"net/url"
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
	basicID, basicSecret, hasBasic := r.BasicAuth()

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
	if creds.Method == MethodNone && creds.ClientID == "" {
		return nil, ErrNoCredentials
	}
	return creds, nil
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
