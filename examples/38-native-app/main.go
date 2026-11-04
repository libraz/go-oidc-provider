//go:build example

// Example 38-native-app demonstrates the native / CLI Relying Party shape of
// RFC 8252: a public client with no secret that receives the authorization
// response on a loopback redirect URI and redeems it with PKCE. The OP and
// the client run in one process so the whole round-trip can be driven from a
// terminal and a browser.
//
// Run with the example build tag:
//
//	(cd examples/38-native-app && GOWORK=off go run -tags example .)
//
// Two parts come up in the same process:
//
//   - 127.0.0.1:8080 — the OP, on the default OAuth 2.1 profile with one
//     seeded password user and one op.PublicClient registered with the
//     redirect URI http://127.0.0.1/callback. RFC 8252 §7.3 lets a native
//     app pick any free port at run time, so the OP matches the registered
//     loopback URI regardless of port; the IP literal 127.0.0.1 is admitted
//     without any development option.
//   - the native client — it listens on 127.0.0.1 with an ephemeral port,
//     prints the authorization URL (and opens it when NATIVE_OPEN_BROWSER=1),
//     waits for the redirect, redeems the code with the PKCE code_verifier
//     and no client secret, and calls /userinfo with the access token.
//
// Manual verification:
//
//  1. Start the example. The log prints "open this URL to sign in:" followed
//     by the authorization URL; set NATIVE_OPEN_BROWSER=1 to have it opened
//     for you.
//  2. Open the URL, sign in as username "demo" / password "demo", and
//     approve the consent prompt.
//  3. The browser lands on http://127.0.0.1:<port>/callback and shows
//     "Signed in as demo-user"; the terminal prints
//     "✓ native login: sub=demo-user" and the process exits.
//
// Wiring details:
//
//   - The redirect_uri sent at /authorize and at /token is the same string,
//     port included; only the registration omits the port.
//   - The client sends client_id and code_verifier at /token and no
//     credential: a public client is authenticated by PKCE alone, which the
//     default profile requires on every authorization-code request.
//   - The client checks the RFC 9207 "iss" response parameter against the
//     issuer before it trusts the callback.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP on loopback; the OP behind a real deployment is served over TLS (only the native client's loopback redirect stays http, per RFC 8252 §7.3).
//   - User seed: the demo username / password are hard-coded; production embedders enrol users through their own management plane.
//   - Client: the OP and the client share a process only to keep the demo self-contained; a shipped native app contains just the client half and persists its tokens in the OS keychain.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	opAddr   = "127.0.0.1:8080"
	issuer   = "http://" + opAddr
	clientID = "native-cli"

	// registeredRedirect carries no port: the OP matches the loopback
	// host and path and accepts whatever port the client bound.
	registeredRedirect = "http://127.0.0.1/callback"

	demoUsername = "demo"
	demoPassword = "demo"
	demoSubject  = "demo-user"

	loginTimeout = 5 * time.Minute
)

func main() {
	if err := run(); err != nil {
		fmt.Println("✗ native login: " + err.Error())
		log.Fatal(err)
	}
}

func run() error {
	keys := devkeys.MustEphemeral("native-app-1")

	st := inmem.New()
	if err := seedUser(st); err != nil {
		return err
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		// No WithProfile: the default OAuth 2.1 profile already demands PKCE.
		op.WithLoginFlow(op.LoginFlow{Primary: op.PrimaryPassword{Store: st.UserPasswords()}}),
		op.WithStaticClients(op.PublicClient{
			ID:              clientID,
			RedirectURIs:    []string{registeredRedirect},
			Scopes:          []string{"openid", "profile"},
			ApplicationType: "native",
		}),
	)
	if err != nil {
		return err
	}

	opMux := http.NewServeMux()
	opMux.Handle("/", provider)
	go func() {
		log.Printf("OP listening on %s (issuer %s)", opAddr, issuer)
		if err := serve.Listen(opAddr, opMux, provider); err != nil {
			log.Fatalf("listen: %v", err)
		}
	}()

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := serve.WaitForIssuer(waitCtx, issuer); err != nil {
		return err
	}
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)

	ctx, stop := context.WithTimeout(context.Background(), loginTimeout)
	defer stop()
	return nativeLogin(ctx)
}

// nativeLogin is the client half: everything a shipped CLI would contain.
func nativeLogin(ctx context.Context) error {
	meta, err := discover(ctx)
	if err != nil {
		return err
	}

	verifier, err := randomString(48)
	if err != nil {
		return err
	}
	state, err := randomString(16)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// Port 0 asks the OS for a free port; the redirect URI is built from
	// what was actually bound.
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("bind loopback listener: %w", err)
	}
	redirectURI := "http://" + listener.Addr().String() + "/callback"

	done := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		sub, err := finishLogin(r, meta, redirectURI, state, verifier)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprintf(w, "<!doctype html><p>Sign-in failed: %s</p>", html.EscapeString(err.Error()))
		} else {
			_, _ = fmt.Fprintf(w, "<!doctype html><h1>Signed in as %s</h1><p>You can close this window.</p>", html.EscapeString(sub))
			fmt.Println("✓ native login: sub=" + sub)
		}
		select {
		case done <- err:
		default:
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(listener) }()

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid profile")
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	authorizeURL := meta.AuthorizationEndpoint + "?" + q.Encode()

	log.Printf("open this URL to sign in:\n%s", authorizeURL)
	if os.Getenv("NATIVE_OPEN_BROWSER") == "1" {
		if err := openBrowser(ctx, authorizeURL); err != nil {
			log.Printf("could not open a browser: %v", err)
		}
	}

	var result error
	select {
	case result = <-done:
	case <-ctx.Done():
		result = errors.New("timed out waiting for the browser to return to the loopback redirect")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Shutdown lets the in-flight callback response reach the browser.
	return errors.Join(result, srv.Shutdown(shutdownCtx))
}

type opMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

func discover(ctx context.Context) (*opMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var meta opMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("decode discovery document: %w", err)
	}
	return &meta, nil
}

// finishLogin validates the redirect, redeems the code and returns the sub
// reported by /userinfo for the resulting access token.
func finishLogin(r *http.Request, meta *opMetadata, redirectURI, wantState, verifier string) (string, error) {
	q := r.URL.Query()
	if code := q.Get("error"); code != "" {
		return "", fmt.Errorf("authorization failed: %s %s", code, q.Get("error_description"))
	}
	if q.Get("state") != wantState {
		return "", errors.New("state mismatch")
	}
	// RFC 9207: a response naming a different issuer is a mix-up attempt.
	if iss := q.Get("iss"); iss != "" && iss != meta.Issuer {
		return "", fmt.Errorf("unexpected issuer %q", iss)
	}
	code := q.Get("code")
	if code == "" {
		return "", errors.New("redirect carries no code")
	}

	// A public client sends no credential: client_id and the PKCE verifier.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	body, err := postForm(r.Context(), meta.TokenEndpoint, form)
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" || tok.IDToken == "" {
		return "", fmt.Errorf("token response lacks access_token or id_token: %s", body)
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, meta.UserinfoEndpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("userinfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo %d: %s", resp.StatusCode, raw)
	}
	var info struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(raw, &info); err != nil || info.Sub == "" {
		return "", fmt.Errorf("userinfo response lacks sub: %s", raw)
	}
	return info.Sub, nil
}

func postForm(ctx context.Context, endpoint string, form url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}
	return body, nil
}

func openBrowser(ctx context.Context, target string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "open", target)
	case "windows":
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", target)
	default:
		cmd = exec.CommandContext(ctx, "xdg-open", target)
	}
	return cmd.Start()
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func seedUser(st *inmem.Store) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return err
	}
	st.PutUserWithPassword(context.Background(), &store.User{
		Subject: demoSubject,
		Claims: store.StandardClaims{
			Name:  "Demo User",
			Email: "demo@example.com",
		}.Map(),
	}, demoUsername, hash)
	return nil
}
