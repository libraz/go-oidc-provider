//go:build example

package rpkit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/timex"
)

// FAPI2Options configures a FAPI 2.0 Baseline Relying Party. The RP
// uses ES256 throughout: one key (ClientPrivateKey) signs
// private_key_jwt assertions, and a separate ephemeral key (generated
// inside NewFAPI2) signs DPoP proofs. Splitting the keys keeps the
// long-lived registered key off the DPoP wire path so a stolen DPoP
// proof never grants the holder client_assertion-signing capability.
type FAPI2Options struct {
	// Issuer, ClientID, RedirectURL, Scopes — same shape as Options.
	Issuer      string
	ClientID    string
	RedirectURL string
	Scopes      []string

	// ClientPrivateKey signs private_key_jwt assertions. Its public
	// half MUST be registered with the OP under ClientKeyID.
	ClientPrivateKey *ecdsa.PrivateKey

	// ClientKeyID is the JWS "kid" header for ClientPrivateKey. The
	// OP looks up the verifying public key by this kid.
	ClientKeyID string

	// Clock supplies JWT and DPoP timestamps. Nil uses timex.SystemClock.
	Clock timex.Clock
}

// FAPI2Flow drives a FAPI 2.0 Baseline Authorization Code flow:
// PAR + private_key_jwt + DPoP-bound access tokens + PKCE.
type FAPI2Flow struct {
	issuer      string
	clientID    string
	redirectURL string
	scopes      []string

	clientKey *ecdsa.PrivateKey
	clientKID string

	// dpopKey is generated once per process and reused for every
	// token-endpoint POST. The OP records the JWK thumbprint in the
	// access token's "cnf" claim; reusing the key keeps every token
	// the RP holds bound to the same proof key.
	dpopKey *ecdsa.PrivateKey
	clock   timex.Clock

	endpoints discoveryDoc
	verifier  *oidc.IDTokenVerifier

	mu      sync.Mutex
	pending map[string]string // state -> code_verifier
	last    map[string]any
}

type discoveryDoc struct {
	Issuer        string `json:"issuer"`
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
	ParEndpoint   string `json:"pushed_authorization_request_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
}

// NewFAPI2 runs OIDC discovery, generates an ephemeral DPoP key, and
// returns a FAPI2Flow ready to mount through Handler().
func NewFAPI2(ctx context.Context, opts FAPI2Options) (*FAPI2Flow, error) {
	if opts.ClientPrivateKey == nil {
		return nil, errors.New("rpkit: FAPI2Options.ClientPrivateKey is required")
	}
	if opts.ClientKeyID == "" {
		return nil, errors.New("rpkit: FAPI2Options.ClientKeyID is required")
	}
	clock := opts.Clock
	if clock == nil {
		clock = timex.SystemClock
	}

	provider, err := oidc.NewProvider(ctx, opts.Issuer)
	if err != nil {
		return nil, fmt.Errorf("rpkit: discover %s: %w", opts.Issuer, err)
	}

	var doc discoveryDoc
	if err := provider.Claims(&doc); err != nil {
		return nil, fmt.Errorf("rpkit: decode discovery doc: %w", err)
	}
	if doc.ParEndpoint == "" {
		return nil, errors.New("rpkit: OP discovery missing pushed_authorization_request_endpoint")
	}

	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("rpkit: generate DPoP key: %w", err)
	}

	scopes := opts.Scopes
	if !hasScope(scopes, oidc.ScopeOpenID) {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}

	return &FAPI2Flow{
		issuer:      opts.Issuer,
		clientID:    opts.ClientID,
		redirectURL: opts.RedirectURL,
		scopes:      scopes,
		clientKey:   opts.ClientPrivateKey,
		clientKID:   opts.ClientKeyID,
		dpopKey:     dpopKey,
		clock:       clock,
		endpoints:   doc,
		verifier:    provider.Verifier(&oidc.Config{ClientID: opts.ClientID}),
		pending:     make(map[string]string),
	}, nil
}

// Handler mirrors the basic CodeFlow shape so embedders can swap
// constructors without changing routes.
func (f *FAPI2Flow) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", f.index)
	mux.HandleFunc("/login", f.login)
	mux.HandleFunc("/callback", f.callback)
	mux.HandleFunc("/me", f.me)
	return mux
}

func (f *FAPI2Flow) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w,
		`<!doctype html><html><body><h1>rpkit FAPI 2.0 demo RP</h1>`+
			`<p>Issuer: <code>%s</code></p>`+
			`<p>Client: <code>%s</code> (private_key_jwt)</p>`+
			`<p>Profile: PAR + DPoP + PKCE</p>`+
			`<ul><li><a href="/login">Log in via the OP (PAR)</a></li>`+
			`<li><a href="/me">Show last verified claims (/me)</a></li></ul>`+
			`</body></html>`,
		htmlEscape(f.issuer), htmlEscape(f.clientID))
}

func (f *FAPI2Flow) login(w http.ResponseWriter, r *http.Request) {
	state, err := randURL(16)
	if err != nil {
		http.Error(w, "rpkit: generate state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	verifier, err := randURL(48)
	if err != nil {
		http.Error(w, "rpkit: generate code_verifier: "+err.Error(), http.StatusInternalServerError)
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	form := url.Values{}
	form.Set("response_type", "code")
	form.Set("client_id", f.clientID)
	form.Set("redirect_uri", f.redirectURL)
	form.Set("scope", strings.Join(f.scopes, " "))
	form.Set("state", state)
	form.Set("code_challenge", challenge)
	form.Set("code_challenge_method", "S256")

	if err := f.attachClientAssertion(form); err != nil {
		http.Error(w, "rpkit: build private_key_jwt: "+err.Error(), http.StatusInternalServerError)
		return
	}

	requestURI, err := f.pushAuthorizationRequest(r.Context(), form)
	if err != nil {
		http.Error(w, "rpkit: PAR: "+err.Error(), http.StatusBadGateway)
		return
	}

	f.mu.Lock()
	f.pending[state] = verifier
	f.mu.Unlock()

	q := url.Values{}
	q.Set("client_id", f.clientID)
	q.Set("request_uri", requestURI)
	http.Redirect(w, r, f.endpoints.AuthEndpoint+"?"+q.Encode(), http.StatusFound)
}

func (f *FAPI2Flow) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if errCode := q.Get("error"); errCode != "" {
		http.Error(w, "rpkit: OP returned error="+errCode+" desc="+q.Get("error_description"),
			http.StatusBadGateway)
		return
	}
	state := q.Get("state")
	code := q.Get("code")
	if state == "" || code == "" {
		http.Error(w, "rpkit: missing state or code", http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	verifier, ok := f.pending[state]
	delete(f.pending, state)
	f.mu.Unlock()
	if !ok {
		http.Error(w, "rpkit: unknown state", http.StatusBadRequest)
		return
	}

	tokens, err := f.exchange(r.Context(), code, verifier)
	if err != nil {
		http.Error(w, "rpkit: token exchange: "+err.Error(), http.StatusBadGateway)
		return
	}

	idt, err := f.verifier.Verify(r.Context(), tokens.IDToken)
	if err != nil {
		http.Error(w, "rpkit: verify id_token: "+err.Error(), http.StatusBadGateway)
		return
	}

	claims := map[string]any{}
	if err := idt.Claims(&claims); err != nil {
		http.Error(w, "rpkit: decode claims: "+err.Error(), http.StatusInternalServerError)
		return
	}
	claims["_token_type"] = tokens.TokenType
	claims["_access_token_cnf_jkt"] = jwkThumbprint(&f.dpopKey.PublicKey)

	f.mu.Lock()
	f.last = claims
	f.mu.Unlock()

	http.Redirect(w, r, "/me", http.StatusFound)
}

func (f *FAPI2Flow) me(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	claims := f.last
	f.mu.Unlock()

	if claims == nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("rpkit: no verified ID Token yet — visit /login first\n"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(claims)
}

// attachClientAssertion adds private_key_jwt fields to form per
// RFC 7521 / RFC 7523. aud == issuer per FAPI 2.0 §5.2.2.
func (f *FAPI2Flow) attachClientAssertion(form url.Values) error {
	now := f.clock.Now()
	jti, err := randURL(16)
	if err != nil {
		return err
	}
	claims := jwt.Claims{
		Issuer:   f.clientID,
		Subject:  f.clientID,
		Audience: jwt.Audience{f.endpoints.Issuer},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(60 * time.Second)),
		ID:       jti,
	}
	signed, err := signJWT(f.clientKey, f.clientKID, "JWT", claims, nil)
	if err != nil {
		return err
	}
	form.Set("client_id", f.clientID)
	form.Set("client_assertion_type",
		"urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", signed)
	return nil
}

func (f *FAPI2Flow) pushAuthorizationRequest(ctx context.Context, form url.Values) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		f.endpoints.ParEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("PAR endpoint %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("decode PAR response: %w", err)
	}
	if out.RequestURI == "" {
		return "", errors.New("PAR response missing request_uri")
	}
	return out.RequestURI, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (f *FAPI2Flow) exchange(ctx context.Context, code, codeVerifier string) (*tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", f.redirectURL)
	form.Set("code_verifier", codeVerifier)
	if err := f.attachClientAssertion(form); err != nil {
		return nil, fmt.Errorf("client_assertion: %w", err)
	}

	status, headers, body, err := f.exchangeRequest(ctx, form, "")
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized || status == http.StatusBadRequest {
		// RFC 9449 §8 nonce challenge: retry once with the supplied
		// DPoP-Nonce. The OP issues the nonce out-of-band; the RP just
		// echoes it in the next proof.
		if nonce := headers.Get("DPoP-Nonce"); nonce != "" {
			log.Printf("rpkit: DPoP nonce challenge received, retrying")
			status, _, body, err = f.exchangeRequest(ctx, form, nonce)
			if err != nil {
				return nil, err
			}
		}
	}

	if status != http.StatusOK {
		return nil, fmt.Errorf("token endpoint %d: %s", status, string(body))
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if tr.IDToken == "" {
		return nil, errors.New("token response missing id_token")
	}
	return &tr, nil
}

// exchangeRequest sends a single DPoP-bound authorization-code exchange and
// returns a detached response snapshot so callers do not retain an open body.
func (f *FAPI2Flow) exchangeRequest(ctx context.Context, form url.Values, nonce string) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoints.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dpop, err := f.signDPoPWithNonce(http.MethodPost, f.endpoints.TokenEndpoint, "", nonce)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("DPoP proof: %w", err)
	}
	req.Header.Set("DPoP", dpop)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("read token response: %w", err)
	}
	return resp.StatusCode, resp.Header.Clone(), body, nil
}

func (f *FAPI2Flow) signDPoPWithNonce(htm, htu, ath, nonce string) (string, error) {
	jti, err := randURL(16)
	if err != nil {
		return "", err
	}
	type proofClaims struct {
		HTM   string `json:"htm"`
		HTU   string `json:"htu"`
		IAT   int64  `json:"iat"`
		JTI   string `json:"jti"`
		ATH   string `json:"ath,omitempty"`
		Nonce string `json:"nonce,omitempty"`
	}
	pc := proofClaims{
		HTM: htm,
		HTU: htu,
		IAT: f.clock.Now().Unix(),
		JTI: jti,
	}
	if ath != "" {
		pc.ATH = ath
	}
	if nonce != "" {
		pc.Nonce = nonce
	}
	headers := map[string]any{
		"jwk": ecPublicJWK(&f.dpopKey.PublicKey),
	}
	return signJWT(f.dpopKey, "" /* no kid for DPoP */, "dpop+jwt", pc, headers)
}

// signJWT signs claims with key using ES256. typ goes into the JWS
// header; extraHeaders override or augment the protected header.
func signJWT(key *ecdsa.PrivateKey, kid, typ string, claims any, extraHeaders map[string]any) (string, error) {
	signerKey := jose.SigningKey{Algorithm: jose.ES256, Key: key}
	opts := &jose.SignerOptions{}
	opts.WithType(jose.ContentType(typ))
	if kid != "" {
		opts.WithHeader(jose.HeaderKey("kid"), kid)
	}
	for k, v := range extraHeaders {
		opts.WithHeader(jose.HeaderKey(k), v)
	}
	signer, err := jose.NewSigner(signerKey, opts)
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}

// ecPublicJWK returns the JSON Web Key form of pub. The DPoP proof
// embeds this in its protected header so the OP can verify the proof
// signature without prior key registration.
func ecPublicJWK(pub *ecdsa.PublicKey) map[string]string {
	return map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
	}
}

// jwkThumbprint computes the RFC 7638 thumbprint the OP records in the
// access token's "cnf" claim. The RP renders it on /me so an embedder
// can confirm DPoP binding worked end-to-end.
func jwkThumbprint(pub *ecdsa.PublicKey) string {
	canon := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`,
		base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
		base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()))
	sum := sha256.Sum256([]byte(canon))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// PublicJWKSetJSON returns the JWK Set the OP registers as the
// client's verifying key for private_key_jwt. Examples call this once
// at boot to seed PrivateKeyJWTClient.JWKS.
func PublicJWKSetJSON(pub *ecdsa.PublicKey, kid string) ([]byte, error) {
	type jwk struct {
		KTY string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		Use string `json:"use"`
		KID string `json:"kid"`
		Alg string `json:"alg"`
	}
	type set struct {
		Keys []jwk `json:"keys"`
	}
	return json.Marshal(set{Keys: []jwk{{
		KTY: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
		Use: "sig",
		KID: kid,
		Alg: "ES256",
	}}})
}
