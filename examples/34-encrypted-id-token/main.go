//go:build example

// Example 34-encrypted-id-token demonstrates an OP that issues
// encrypted ID Tokens (JWE-of-signed-JWT, RFC 7519 §5.2 nested) to a
// client registered with `id_token_encrypted_response_alg=RSA-OAEP-256`
// and `id_token_encrypted_response_enc=A256GCM`. The OP advertises an
// RSA `use=enc` key on its JWKS endpoint; the example RP advertises
// its own `use=enc` JWKS inline on the client metadata, drives an
// authorization_code + PKCE flow, and decrypts the five-part JWE wrap
// with the RP's private key before verifying the inner JWS against
// the OP's signing JWKS. The example exists to make the v0.9.1
// outbound id_token JWE wire shape readable end-to-end.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/34-encrypted-id-token
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, with WithEncryptionKeyset registering one RSA
//     2048-bit `use=enc` key. The OP's JWKS endpoint publishes both
//     the ES256 signing key and the RSA encryption key.
//   - :9090 — a minimal inline RP. It exposes /, /login, /callback,
//     /me. The RP holds the private half of an RSA 2048-bit
//     `use=enc` key whose public half is registered with the OP via
//     the client metadata `JWKs` field.
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/ — you see the RP landing page.
//  2. Click "Log in via the OP" — the browser is redirected to the
//     OP's /authorize, then to the password prompt.
//  3. Sign in as username "demo" / password "demo".
//  4. Approve the consent prompt.
//  5. The browser ends up at http://127.0.0.1:9090/me. The JSON body
//     includes "_id_token_jwe_parts": 5 (the compact JWE shape) plus
//     the decrypted ID Token claims (iss, sub, aud, iat, exp, nonce,
//     name, email).
//
// Cross-check the OP's advertised encryption key (the discovery
// document's "jwks_uri" points at /jwks by default):
//
//	curl "$(curl -s http://127.0.0.1:8080/.well-known/openid-configuration | jq -r .jwks_uri)" \
//	  | jq '.keys[] | select(.use == "enc")'
//
// You should see one RSA JWK with use=enc, alg=RSA-OAEP-256, and the
// kid the OP registered ("op-enc-1").
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production. The OP
//     signing key, the OP encryption key, and the RP encryption key
//     are all generated fresh on every restart.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress. JWE
//     protects the id_token claims at rest, but the rest of the wire
//     (cookies, /token POST, /authorize redirects) still benefits
//     from TLS.
//   - User seed: the demo username / password are hard-coded;
//     production embedders enrol users through their own management
//     plane.
//   - RP: the inline RP in this main.go is a demo, not a library.
//     Production RPs that consume encrypted ID tokens use a tested
//     client framework that handles JWKS rotation, key caching, and
//     the JWE-over-JWS verification dance correctly.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	opAddr      = ":8080"
	rpAddr      = ":9090"
	issuer      = "http://127.0.0.1" + opAddr
	rpBase      = "http://127.0.0.1" + rpAddr
	clientID    = "encrypted-id-token-example-client"
	clientKID   = "rp-enc-1"
	opEncKID    = "op-enc-1"
	redirectURI = rpBase + "/callback"
	// clientSecret is unique to this example so the cross-example
	// duplicate-secret guard stays green; it is not a security claim.
	clientSecret = "encrypted-id-token-demo-shhh"

	demoUsername = "demo"
	demoPassword = "demo"
	demoSubject  = "demo-user"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	keys := devkeys.MustEphemeral("encrypted-id-token-1")

	// Generate the OP's encryption keypair. The private half stays in
	// process; the public half lands in JWKS as use=enc and is the key
	// the OP would use to decrypt inbound JWE (e.g. encrypted request
	// objects). It is unrelated to the outbound id_token JWE — that
	// wraps to the RP's key, registered below.
	opEncPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate OP encryption key: %w", err)
	}

	// Generate the RP's encryption keypair. The OP wraps every
	// id_token issued to this client to the public half via JWKs on
	// the client metadata; the RP decrypts with the private half.
	rpEncPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate RP encryption key: %w", err)
	}
	rpJWKS, err := rsaPublicJWKSetJSON(&rpEncPriv.PublicKey, clientKID)
	if err != nil {
		return fmt.Errorf("marshal RP JWKS: %w", err)
	}

	st := inmem.New()
	if err := seedUser(st); err != nil {
		return err
	}

	// Register the RP with id_token_encrypted_response_alg /
	// id_token_encrypted_response_enc set. The typed builders
	// (PublicClient / ConfidentialClient) do not yet expose the JWE
	// metadata fields, so we project onto store.Client directly.
	secretHash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		return fmt.Errorf("hash client secret: %w", err)
	}
	if err := st.RegisterClient(context.Background(), &store.Client{
		ID:                          clientID,
		RedirectURIs:                []string{redirectURI},
		Scopes:                      []string{"openid", "profile", "email"},
		GrantTypes:                  []string{"authorization_code"},
		ResponseTypes:               []string{"code"},
		TokenEndpointAuthMethod:     op.AuthClientSecretBasic.String(),
		SecretHash:                  secretHash,
		Source:                      store.ClientSourceStatic,
		JWKs:                        rpJWKS,
		IDTokenEncryptedResponseAlg: "RSA-OAEP-256",
		IDTokenEncryptedResponseEnc: "A256GCM",
	}); err != nil {
		return fmt.Errorf("register client: %w", err)
	}

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: st.UserPasswords()},
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLoginFlow(flow),
		// WithEncryptionKeyset publishes the OP's use=enc key on
		// /.well-known/jwks.json and wires the inbound JWE
		// decrypter. The same option also unlocks outbound JWE
		// emission: when a client registers
		// id_token_encrypted_response_alg / _enc, the token endpoint
		// wraps the signed id_token in a JWE addressed to the RP's
		// own use=enc key (resolved via the client metadata's JWKs).
		op.WithEncryptionKeyset(op.EncryptionKeyset{{
			KeyID:      opEncKID,
			PrivateKey: opEncPriv,
		}}),
	)
	if err != nil {
		return err
	}

	opMux := http.NewServeMux()
	opMux.Handle("/", provider)

	opErrCh := make(chan error, 1)
	go func() {
		log.Printf("OP listening on %s (issuer %s, encrypted ID tokens via RSA-OAEP-256 + A256GCM)",
			opAddr, issuer)
		opErrCh <- serve.Listen(opAddr, opMux)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := waitForIssuer(ctx, issuer); err != nil {
		return err
	}

	rp, err := newRP(rpOptions{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Scopes:       []string{"openid", "profile", "email"},
		EncPrivate:   rpEncPriv,
	})
	if err != nil {
		return err
	}

	rpMux := http.NewServeMux()
	rpMux.Handle("/", rp.Handler())

	log.Printf("RP listening on %s — open %s/", rpAddr, rpBase)
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)

	rpErrCh := make(chan error, 1)
	go func() { rpErrCh <- serve.Listen(rpAddr, rpMux) }()

	select {
	case err := <-opErrCh:
		return err
	case err := <-rpErrCh:
		return err
	}
}

func seedUser(st *inmem.Store) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return err
	}
	st.PutUserWithPassword(context.Background(), &store.User{
		Subject: demoSubject,
		Claims: map[string]any{
			"name":  "Demo User",
			"email": "demo@example.com",
		},
	}, demoUsername, hash)
	return nil
}

// waitForIssuer polls iss + "/.well-known/openid-configuration" until
// it returns 200 or ctx is cancelled.
func waitForIssuer(ctx context.Context, iss string) error {
	url := iss + "/.well-known/openid-configuration"
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("waitForIssuer: timeout polling " + url)
		case <-tick.C:
		}
	}
}

// rsaPublicJWKSetJSON serialises pub as a one-key JSON Web Key Set
// suitable for store.Client.JWKs. The library's encryption recipient
// resolver picks a key with use=enc whose alg matches the client's
// IDTokenEncryptedResponseAlg.
func rsaPublicJWKSetJSON(pub *rsa.PublicKey, kid string) ([]byte, error) {
	jwk := josev4.JSONWebKey{
		Key:       pub,
		KeyID:     kid,
		Use:       "enc",
		Algorithm: "RSA-OAEP-256",
	}
	return json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{jwk}})
}

// rpOptions configures the inline Relying Party. ClientSecret carries
// the demo client_secret_basic credential; EncPrivate is the RSA
// private half whose public counterpart is registered with the OP as
// the RP's use=enc key.
type rpOptions struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	EncPrivate   *rsa.PrivateKey
}

type discoveryDoc struct {
	Issuer        string `json:"issuer"`
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
}

// rp is a minimal Authorization Code + PKCE Relying Party that
// expects an encrypted ID Token. It does not depend on
// examples/internal/rpkit because rpkit's CodeFlow uses
// coreos/go-oidc's verifier, which does not understand the
// JWE-of-JWS nested shape; this RP performs the decrypt + verify
// dance explicitly so the wire shape is observable.
type rp struct {
	opts      rpOptions
	endpoints discoveryDoc
	opSigJWKS *josev4.JSONWebKeySet // fetched once at startup

	mu      sync.Mutex
	pending map[string]pendingState
	last    map[string]any
}

// pendingState pairs the PKCE code_verifier with the nonce for a
// single in-flight authorization request.
type pendingState struct {
	verifier string
	nonce    string
}

func newRP(opts rpOptions) (*rp, error) {
	if opts.EncPrivate == nil {
		return nil, errors.New("rp: EncPrivate is required")
	}

	doc, err := fetchDiscovery(opts.Issuer)
	if err != nil {
		return nil, err
	}
	jwks, err := fetchJWKS(doc.JWKSURI)
	if err != nil {
		return nil, err
	}

	return &rp{
		opts:      opts,
		endpoints: doc,
		opSigJWKS: jwks,
		pending:   make(map[string]pendingState),
	}, nil
}

func fetchDiscovery(issuer string) (discoveryDoc, error) {
	var doc discoveryDoc
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return doc, fmt.Errorf("rp: build discovery request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("rp: discover %s: %w", issuer, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return doc, fmt.Errorf("rp: discovery %s status %d", issuer, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("rp: decode discovery: %w", err)
	}
	return doc, nil
}

func fetchJWKS(uri string) (*josev4.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("rp: build jwks request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rp: fetch jwks %s: %w", uri, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rp: jwks %s status %d", uri, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("rp: read jwks: %w", err)
	}
	var set josev4.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("rp: parse jwks: %w", err)
	}
	return &set, nil
}

func (r *rp) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", r.index)
	mux.HandleFunc("/login", r.login)
	mux.HandleFunc("/callback", r.callback)
	mux.HandleFunc("/me", r.me)
	return mux
}

func (r *rp) index(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w,
		`<!doctype html><html><body><h1>Encrypted ID Token demo RP</h1>`+
			`<p>Issuer: <code>%s</code></p>`+
			`<p>Client: <code>%s</code></p>`+
			`<p>The OP wraps every id_token in a JWE (RSA-OAEP-256 + A256GCM).</p>`+
			`<ul><li><a href="/login">Log in via the OP</a></li>`+
			`<li><a href="/me">Show last decrypted claims (/me)</a></li></ul>`+
			`</body></html>`,
		htmlEscape(r.opts.Issuer), htmlEscape(r.opts.ClientID))
}

func (r *rp) login(w http.ResponseWriter, req *http.Request) {
	state, err := randURL(16)
	if err != nil {
		http.Error(w, "rp: generate state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	verifier, err := randURL(48)
	if err != nil {
		http.Error(w, "rp: generate code_verifier: "+err.Error(), http.StatusInternalServerError)
		return
	}
	nonce, err := randURL(16)
	if err != nil {
		http.Error(w, "rp: generate nonce: "+err.Error(), http.StatusInternalServerError)
		return
	}

	r.mu.Lock()
	r.pending[state] = pendingState{verifier: verifier, nonce: nonce}
	r.mu.Unlock()

	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", r.opts.ClientID)
	q.Set("redirect_uri", r.opts.RedirectURL)
	q.Set("scope", strings.Join(r.opts.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	http.Redirect(w, req, r.endpoints.AuthEndpoint+"?"+q.Encode(), http.StatusFound)
}

func (r *rp) callback(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	if errCode := q.Get("error"); errCode != "" {
		http.Error(w, "rp: OP returned error="+errCode+" desc="+q.Get("error_description"),
			http.StatusBadGateway)
		return
	}
	state := q.Get("state")
	code := q.Get("code")
	if state == "" || code == "" {
		http.Error(w, "rp: missing state or code", http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	pending, ok := r.pending[state]
	delete(r.pending, state)
	r.mu.Unlock()
	if !ok {
		http.Error(w, "rp: unknown state", http.StatusBadRequest)
		return
	}

	rawIDToken, err := r.exchangeCode(req.Context(), code, pending.verifier)
	if err != nil {
		http.Error(w, "rp: token exchange: "+err.Error(), http.StatusBadGateway)
		return
	}

	parts := strings.Split(rawIDToken, ".")
	if len(parts) != 5 {
		http.Error(w,
			fmt.Sprintf("rp: expected 5-part JWE id_token, got %d parts", len(parts)),
			http.StatusBadGateway)
		return
	}

	claims, err := r.decryptAndVerify(rawIDToken)
	if err != nil {
		http.Error(w, "rp: decrypt/verify id_token: "+err.Error(), http.StatusBadGateway)
		return
	}

	if got, _ := claims["nonce"].(string); got != pending.nonce {
		http.Error(w, "rp: id_token nonce mismatch", http.StatusBadGateway)
		return
	}

	// Surface the JWE wire shape next to the decrypted claims so the
	// operator sees both in a single /me response.
	claims["_id_token_jwe_parts"] = len(parts)

	r.mu.Lock()
	r.last = claims
	r.mu.Unlock()

	http.Redirect(w, req, "/me", http.StatusFound)
}

// exchangeCode POSTs to /token with client_secret_basic credentials
// and returns the raw id_token field. The token response also carries
// access_token / token_type but the example does not exercise the
// userinfo path.
func (r *rp) exchangeCode(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", r.opts.RedirectURL)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoints.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(r.opts.ClientID, r.opts.ClientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("/token status %d: %s", resp.StatusCode, string(body))
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if tok.IDToken == "" {
		return "", errors.New("/token response missing id_token")
	}
	return tok.IDToken, nil
}

// decryptAndVerify splits the JWE-of-JWS shape: it decrypts the JWE
// with the RP's private encryption key, recovers the inner JWS,
// verifies the JWS against the OP's signing JWKS, and returns the
// claim map.
func (r *rp) decryptAndVerify(rawJWE string) (map[string]any, error) {
	jwe, err := josev4.ParseEncrypted(rawJWE,
		[]josev4.KeyAlgorithm{josev4.RSA_OAEP_256},
		[]josev4.ContentEncryption{josev4.A256GCM},
	)
	if err != nil {
		return nil, fmt.Errorf("parse JWE: %w", err)
	}
	innerJWS, err := jwe.Decrypt(r.opts.EncPrivate)
	if err != nil {
		return nil, fmt.Errorf("decrypt JWE: %w", err)
	}

	jws, err := josev4.ParseSigned(string(innerJWS),
		[]josev4.SignatureAlgorithm{josev4.ES256},
	)
	if err != nil {
		return nil, fmt.Errorf("parse inner JWS: %w", err)
	}
	if len(jws.Signatures) == 0 {
		return nil, errors.New("inner JWS has no signatures")
	}

	kid := jws.Signatures[0].Header.KeyID
	matches := r.opSigJWKS.Key(kid)
	if len(matches) == 0 {
		return nil, fmt.Errorf("no OP signing key for kid %q", kid)
	}
	payload, err := jws.Verify(matches[0].Key)
	if err != nil {
		return nil, fmt.Errorf("verify inner JWS: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	if iss, _ := claims["iss"].(string); iss != r.opts.Issuer {
		return nil, fmt.Errorf("iss mismatch: got %q want %q", iss, r.opts.Issuer)
	}
	return claims, nil
}

func (r *rp) me(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	claims := r.last
	r.mu.Unlock()

	if claims == nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("rp: no decrypted ID Token yet — visit /login first\n"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(claims)
}

func randURL(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func htmlEscape(s string) string {
	const lt, gt, amp, quot, apos = "&lt;", "&gt;", "&amp;", "&#34;", "&#39;"
	out := make([]byte, 0, len(s))
	for _, r := range s {
		switch r {
		case '<':
			out = append(out, lt...)
		case '>':
			out = append(out, gt...)
		case '&':
			out = append(out, amp...)
		case '"':
			out = append(out, quot...)
		case '\'':
			out = append(out, apos...)
		default:
			out = append(out, string(r)...)
		}
	}
	return string(out)
}
