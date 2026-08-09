//go:build apiverify

package apiverify

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/testutil/softkey"
)

// 29-passkey's deliverable is the whole passkey lifecycle: enrol a device
// through op/passkeykit on the example's own account page, then sign in
// with it through op.PrimaryPasskey. The two halves only work together if
// the credential registered under one configuration is the credential the
// other accepts, and nothing short of running both proves that.
//
// It lands here rather than in browserverify because WebAuthn needs an
// authenticator, not a browser: internal/testutil/softkey signs the
// ceremonies, and the SPA's prompt contract is JSON, so the entire login
// is drivable over plain HTTP.
//
// The example binds localhost rather than the 127.0.0.1 every other
// example uses — a WebAuthn Relying Party ID must be a domain, and
// browsers reject an IP.
const (
	pkOPBase  = "http://localhost:8080"
	pkRPBase  = "http://localhost:9090"
	pkRPID    = "localhost"
	pkSubject = "demo-user"
)

func TestExample29Passkey(t *testing.T) {
	p := buildAndStart(t, "../../29-passkey")
	defer p.kill()
	pollHTTP(t, p, pkOPBase+"/.well-known/openid-configuration", 30*time.Second)

	key, err := softkey.New()
	if err != nil {
		t.Fatalf("softkey.New: %v", err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := &http.Client{Jar: jar, Timeout: 15 * time.Second}

	credentialID := enrolPasskey(t, client, key)
	claims := loginWithPasskey(t, p, client, key)

	// "swk" is the RFC 8176 token for a software-keyed credential —
	// what a passkey assertion without user verification reports, and
	// the proof that the login actually ran the passkey step rather
	// than stopping at the password.
	for _, want := range []string{`"swk"`, `"` + pkSubject + `"`} {
		if !strings.Contains(claims, want) {
			t.Errorf("/me is missing %s:\n%s", want, claims)
		}
	}
	if credentialID == "" {
		t.Error("enrolment reported no credential id")
	}
}

// enrolPasskey drives the two-request registration ceremony against the
// example's account page and returns the credential id it stored.
func enrolPasskey(t *testing.T, client *http.Client, key *softkey.Key) string {
	t.Helper()

	var begun struct {
		PublicKey json.RawMessage `json:"publicKey"`
	}
	postJSONInto(t, client, pkOPBase+"/account/register/begin",
		map[string]string{"username": "demo", "password": "demo"}, &begun)
	if len(begun.PublicKey) == 0 {
		t.Fatal("register/begin returned no creation options")
	}

	challenge, err := softkey.ChallengeFromOptions(begun.PublicKey)
	if err != nil {
		t.Fatalf("ChallengeFromOptions: %v", err)
	}
	created, err := key.Create(pkRPID, pkOPBase, challenge)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var stored struct {
		CredentialID string `json:"credential_id"`
	}
	postBytesInto(t, client, pkOPBase+"/account/register/finish", created, &stored)

	want := base64.RawURLEncoding.EncodeToString(key.CredentialID())
	if stored.CredentialID != want {
		t.Fatalf("stored credential %q want %q", stored.CredentialID, want)
	}
	return stored.CredentialID
}

// loginWithPasskey runs the RP-initiated login to completion and returns
// the /me body. The SPA answers prompts over JSON, so the loop below is
// the same one the browser bundle runs, minus the rendering.
func loginWithPasskey(t *testing.T, p *proc, client *http.Client, key *softkey.Key) string {
	t.Helper()

	resp, err := client.Get(pkRPBase + "/login") //nolint:noctx // harness request, bounded by the client timeout
	if err != nil {
		t.Fatalf("start login: %v\n%s", err, p.readLog())
	}
	_ = resp.Body.Close()

	// The redirect chain ends on the SPA page, whose last path segment
	// is the interaction id every subsequent call is keyed by.
	landed := resp.Request.URL
	uid := landed.Path[strings.LastIndex(landed.Path, "/")+1:]
	if !strings.HasPrefix(landed.Path, "/login/") || uid == "" {
		t.Fatalf("login did not land on the SPA: %s\n%s", landed, p.readLog())
	}
	stateURL := pkOPBase + "/login/state/" + uid

	for step := range 8 {
		prompt := fetchPrompt(t, client, stateURL)
		promptType, _ := prompt["type"].(string)

		if promptType == "redirect" {
			location, _ := prompt["location"].(string)
			return followToMe(t, client, location)
		}

		values, err := answerPrompt(prompt, key)
		if err != nil {
			t.Fatalf("step %d: %v\n%s", step, err, p.readLog())
		}
		next := submitPrompt(t, client, stateURL, prompt, values)
		if location, ok := next["location"].(string); ok && next["type"] == "redirect" {
			return followToMe(t, client, location)
		}
	}
	t.Fatalf("login did not complete in 8 steps\n%s", p.readLog())
	return ""
}

// answerPrompt produces the submission values for one prompt. An
// unrecognised prompt is an error rather than a skip: silently ignoring
// one would turn a changed flow into a timeout instead of a failure.
func answerPrompt(prompt map[string]any, key *softkey.Key) (map[string]string, error) {
	switch prompt["type"] {
	case "auth.password":
		return map[string]string{"username": "demo", "password": "demo"}, nil

	case "auth.passkey":
		assertion, err := assertPasskey(prompt, key)
		if err != nil {
			return nil, err
		}
		return map[string]string{"response": string(assertion)}, nil

	case "consent.scope":
		data, _ := prompt["data"].(map[string]any)
		scopes, _ := data["scopes"].([]any)
		names := make([]string, 0, len(scopes))
		for _, s := range scopes {
			entry, _ := s.(map[string]any)
			if name, ok := entry["name"].(string); ok {
				names = append(names, name)
			}
		}
		return map[string]string{"approved_scopes": strings.Join(names, " ")}, nil

	default:
		return nil, fmt.Errorf("unexpected prompt %q", prompt["type"])
	}
}

// assertPasskey turns the prompt's challenge into a signed assertion.
// The prompt carries Go []byte fields, which encoding/json renders as
// standard padded base64 — not the base64url the WebAuthn wire format
// uses, which is why the two encodings appear side by side here.
func assertPasskey(prompt map[string]any, key *softkey.Key) ([]byte, error) {
	data, _ := prompt["data"].(map[string]any)
	encoded, _ := data["Challenge"].(string)
	challenge, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode challenge %q: %w", encoded, err)
	}
	return key.Assert(pkRPID, pkOPBase, challenge, []byte(pkSubject))
}

func fetchPrompt(t *testing.T, client *http.Client, stateURL string) map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, stateURL, nil) //nolint:noctx // harness request, bounded by the client timeout
	if err != nil {
		t.Fatalf("build prompt request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	return doJSON(t, client, req)
}

func submitPrompt(t *testing.T, client *http.Client, stateURL string, prompt map[string]any, values map[string]string) map[string]any {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"state_ref": prompt["state_ref"],
		"values":    values,
	})
	if err != nil {
		t.Fatalf("marshal submission: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, stateURL, strings.NewReader(string(body))) //nolint:noctx // harness request, bounded by the client timeout
	if err != nil {
		t.Fatalf("build submission: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// The browser sets both automatically; the OP checks them, so a
	// bare Go client has to state them or every POST is a CSRF failure.
	req.Header.Set("Origin", pkOPBase)
	if token, ok := prompt["csrf_token"].(string); ok {
		req.Header.Set("X-CSRF-Token", token)
	}
	return doJSON(t, client, req)
}

// followToMe lands the RP callback and reads the claims page the example
// promises.
func followToMe(t *testing.T, client *http.Client, location string) string {
	t.Helper()
	resp, err := client.Get(location) //nolint:noctx // harness request, bounded by the client timeout
	if err != nil {
		t.Fatalf("follow callback: %v", err)
	}
	_ = resp.Body.Close()

	resp, err = client.Get(pkRPBase + "/me") //nolint:noctx // harness request, bounded by the client timeout
	if err != nil {
		t.Fatalf("GET /me: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /me: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/me returned %d:\n%s", resp.StatusCode, body)
	}
	return string(body)
}

func postJSONInto(t *testing.T, client *http.Client, url string, body, out any) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	postBytesInto(t, client, url, encoded, out)
}

func postBytesInto(t *testing.T, client *http.Client, url string, body []byte, out any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body))) //nolint:noctx // harness request, bounded by the client timeout
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	raw := doRaw(t, client, req)
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("decode %s: %v\n%s", url, err, raw)
	}
}

func doJSON(t *testing.T, client *http.Client, req *http.Request) map[string]any {
	t.Helper()
	raw := doRaw(t, client, req)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %s: %v\n%s", req.URL, err, raw)
	}
	return out
}

func doRaw(t *testing.T, client *http.Client, req *http.Request) []byte {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", req.URL, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s returned %d:\n%s", req.Method, req.URL, resp.StatusCode, body)
	}
	return body
}
