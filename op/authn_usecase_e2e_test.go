package op_test

// End-to-end coverage of the login-flow use cases: legacy password
// hashes, passwordless passkeys, StepOneOf, session reuse, Begin-failure
// audit, ExternalStep lockout, and the session view a LoginContext gives.
// Every test runs a real op.New over the in-memory store behind an
// httptest server.
//
// The StepOneOf cases come from a pairwise model generated with coverwise
// (seed 1, 2-wise coverage 1.0, 10 rows) over
//
//	position    primary | post_primary
//	enrolled    zero | one | many
//	policy      Deny | Skip
//	submission  offered | unoffered | none
//
// under the constraints primary => Deny (Skip there is a construction
// error), primary => many (Primary offers every step without probing),
// and enrolled != many => submission = none (no choice prompt is shown).
// "none" on a many row means the user never answers the choice: the test
// checks the prompt offers exactly the enrolled kinds.
//
//	row  position      enrolled  policy  submission
//	01   post_primary  zero      Deny    none
//	02   post_primary  one       Skip    none
//	03   post_primary  many      Skip    offered
//	04   post_primary  many      Deny    unoffered
//	05   post_primary  many      Skip    unoffered
//	06   primary       many      Deny    offered
//	07   primary       many      Deny    unoffered
//	08   primary       many      Deny    none
//	09   post_primary  one       Deny    none
//	10   post_primary  zero      Skip    none

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	authnpasskey "github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/internal/authn/passkey/passkeytest"
	authnpassword "github.com/libraz/go-oidc-provider/internal/authn/password"
	authntotp "github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/op"
	opaudit "github.com/libraz/go-oidc-provider/op/audit"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/op/totpkit"
)

const (
	ucRedirect  = "https://rp.usecase.invalid/callback" //nolint:gosec // G101: a redirect URI, not a credential.
	ucClient    = "uc-rp"
	ucAdmin     = "uc-rp-admin"
	ucSecret    = "uc-rp-secret" //nolint:gosec // G101: a test-only client secret.
	ucUsername  = "uc-user"
	ucPassword  = "correct horse battery staple"
	ucSubject   = "user-usecase"
	ucVerifier  = "dBjftJeZ4CVP-mJ92K9qpWb0sDHkOvH4mn6SpQ8Z3Ws"
	ucChallenge = "VviKmd2zOhOGlHVDnnaVx-LWSHKI_DWqYH_e2pjSGYE"
	ucRPID      = "op.testkit.invalid"
	ucOrigin    = "https://op.testkit.invalid"
	ucSPAMount  = "/login"

	ucExternalPrompt = "uctest.code"
	ucExternalField  = "code"
)

const ucExternalKind op.StepKind = "uctest.ext"

type ucClock struct{ now time.Time }

func (c ucClock) Now() time.Time { return c.now }

// ucFixture is one Provider under test plus a browser driving it.
type ucFixture struct {
	t          *testing.T
	st         *inmem.Store
	srv        *httptest.Server
	cl         *http.Client
	clock      ucClock
	audit      *ucAuditSink
	totpKey    []byte
	totpSecret []byte
}

// ucUI selects the interaction surface: the JSON driver at
// /interaction/{uid}, or the SPA mount at /login/state/{uid}.
type ucUI int

const (
	ucJSONDriver ucUI = iota
	ucSPA
)

// newUCFixture builds a Provider whose login flow flow returns, with two
// confidential clients (ucClient, ucAdmin) and a pinned clock.
func newUCFixture(t *testing.T, ui ucUI, flow func(f *ucFixture) op.LoginFlow, extra ...op.Option) *ucFixture {
	t.Helper()
	ctx := context.Background()
	clock := ucClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	f := &ucFixture{
		t:       t,
		st:      inmem.New(inmem.WithClock(clock)),
		clock:   clock,
		audit:   &ucAuditSink{},
		totpKey: bytes32("uc-totp-encryption-key-32-bytes!"),
	}
	secretHash, err := op.HashClientSecret(ucSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	for _, id := range []string{ucClient, ucAdmin} {
		if err := f.st.RegisterClient(ctx, &store.Client{
			ID:                      id,
			RedirectURIs:            []string{ucRedirect},
			GrantTypes:              []string{"authorization_code"},
			ResponseTypes:           []string{"code"},
			Scopes:                  []string{"openid", "profile"},
			TokenEndpointAuthMethod: "client_secret_basic",
			SecretHash:              secretHash,
		}); err != nil {
			t.Fatalf("RegisterClient %s: %v", id, err)
		}
	}
	opts := []op.Option{
		op.WithIssuer(testkit.DefaultIssuer),
		op.WithStore(f.st),
		op.WithUserStore(f.st.Users()),
		op.WithKeyset(op.Keyset{testkit.NewSigningKey(t, "uc")}),
		op.WithCookieKeys(testkit.NewCookieKey(t)),
		op.WithClock(clock),
		op.WithAuditLogger(slog.New(f.audit)),
		op.WithLoginFlow(flow(f)),
	}
	if ui == ucSPA {
		opts = append(opts, op.WithUI(op.SPAUI{LoginMount: ucSPAMount}))
	} else {
		opts = append(opts, op.WithUI(op.DriverUI{Driver: testkit.AutoConsentDriver{}}))
	}
	provider, err := op.New(append(opts, extra...)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	f.srv = httptest.NewTLSServer(provider)
	t.Cleanup(f.srv.Close)
	f.newBrowser()
	return f
}

// newBrowser replaces the cookie jar, dropping the session.
func (f *ucFixture) newBrowser() {
	f.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		f.t.Fatalf("cookiejar.New: %v", err)
	}
	f.cl = &http.Client{
		Transport: f.srv.Client().Transport,
		Jar:       jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (f *ucFixture) seedPasswordUser(hash []byte) {
	f.t.Helper()
	f.st.PutUserWithPassword(context.Background(), &store.User{Subject: ucSubject}, ucUsername, hash)
}

func (f *ucFixture) seedArgonUser() {
	f.t.Helper()
	hash, err := op.HashPassword(ucPassword)
	if err != nil {
		f.t.Fatalf("HashPassword: %v", err)
	}
	f.seedPasswordUser(hash)
}

func (f *ucFixture) seedBcryptUser() {
	f.t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(ucPassword), bcrypt.MinCost)
	if err != nil {
		f.t.Fatalf("bcrypt: %v", err)
	}
	f.seedPasswordUser(hash)
}

// storedHash reads the subject's password hash back from the store.
func (f *ucFixture) storedHash() []byte {
	f.t.Helper()
	hash, err := f.st.UserPasswords().ReadPasswordHash(context.Background(), ucSubject)
	if err != nil {
		f.t.Fatalf("ReadPasswordHash: %v", err)
	}
	return hash
}

func (f *ucFixture) totpStep() op.StepTOTP {
	return op.StepTOTP{Store: f.st.TOTPs(), EncryptionKey: f.totpKey}
}

func (f *ucFixture) passkeyStep() op.PrimaryPasskey {
	return op.PrimaryPasskey{
		Store:                   f.st.Passkeys(),
		RPID:                    ucRPID,
		RPDisplayName:           "Use case",
		RPOrigins:               []string{ucOrigin},
		RequireUserVerification: true,
	}
}

func (f *ucFixture) passwordStep() op.PrimaryPassword {
	return op.PrimaryPassword{Store: f.st.UserPasswords()}
}

// enrollTOTP stores a confirmed TOTP secret for ucSubject.
func (f *ucFixture) enrollTOTP() {
	f.t.Helper()
	codec, err := totpkit.NewCodec(f.totpKey)
	if err != nil {
		f.t.Fatalf("totpkit.NewCodec: %v", err)
	}
	pending, err := totpkit.NewEnrolment(codec, ucSubject, "usecase", "user@example.test")
	if err != nil {
		f.t.Fatalf("NewEnrolment: %v", err)
	}
	pending.Record.ConfirmedAt = f.clock.Now()
	if err := f.st.TOTPs().Put(context.Background(), pending.Record); err != nil {
		f.t.Fatalf("TOTPs.Put: %v", err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(pending.SecretBase32)
	if err != nil {
		f.t.Fatalf("decode totp secret: %v", err)
	}
	f.totpSecret = secret
}

func (f *ucFixture) totpCode() map[string]string {
	return map[string]string{authntotp.CodeFieldName: authntotp.Code(f.totpSecret, f.clock.Now())}
}

// enrollPasskey stores a credential of a fresh software authenticator for
// subject and returns the authenticator.
func (f *ucFixture) enrollPasskey(subject string) *passkeytest.Authenticator {
	f.t.Helper()
	key := passkeytest.New(f.t, ucRPID)
	f.putPasskey(key.Record(subject))
	return key
}

func (f *ucFixture) putPasskey(rec store.PasskeyRecord) {
	f.t.Helper()
	if err := f.st.Passkeys().Put(context.Background(), &rec); err != nil {
		f.t.Fatalf("Passkeys.Put: %v", err)
	}
}

// failedCount reads the cross-factor lockout count for ucSubject.
func (f *ucFixture) failedCount() int {
	f.t.Helper()
	rec, err := f.st.AuthnLockouts().Get(context.Background(), ucSubject)
	if errors.Is(err, store.ErrNotFound) {
		return 0
	}
	if err != nil {
		f.t.Fatalf("AuthnLockouts.Get: %v", err)
	}
	return rec.FailedCount
}

func ucCredentials() map[string]string {
	return map[string]string{
		authnpassword.UsernameFieldName: ucUsername,
		authnpassword.PasswordFieldName: ucPassword,
	}
}

// authorize runs GET /authorize for clientID plus extra and returns the
// redirect target.
func (f *ucFixture) authorize(clientID string, extra url.Values) *url.URL {
	f.t.Helper()
	v := url.Values{
		"client_id":             {clientID},
		"response_type":         {"code"},
		"redirect_uri":          {ucRedirect},
		"scope":                 {"openid profile"},
		"state":                 {"state-uc"},
		"nonce":                 {"nonce-uc"},
		"code_challenge":        {ucChallenge},
		"code_challenge_method": {"S256"},
	}
	for k, vs := range extra {
		v[k] = vs
	}
	resp := f.do(http.MethodGet, f.srv.URL+"/oidc/auth?"+v.Encode(), "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(resp.Body)
		f.t.Fatalf("authorize status=%d body=%s", resp.StatusCode, dump)
	}
	loc, err := resp.Location()
	if err != nil {
		f.t.Fatalf("authorize Location: %v", err)
	}
	return loc
}

func (f *ucFixture) do(method, target, csrf string, body any) *http.Response {
	f.t.Helper()
	var reader io.Reader = http.NoBody
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			f.t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, target, reader)
	if err != nil {
		f.t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Origin", testkit.DefaultIssuer)
		req.Header.Set("X-CSRF-Token", csrf)
		req.AddCookie(&http.Cookie{Name: "__Host-oidc_csrf", Value: csrf})
	}
	resp, err := f.cl.Do(req)
	if err != nil {
		f.t.Fatalf("%s %s: %v", method, target, err)
	}
	return resp
}

// ucPage is one prompt envelope and where to answer it.
type ucPage struct {
	target string
	csrf   string
	env    map[string]any
}

func (p ucPage) promptType() string {
	s, _ := p.env["type"].(string)
	return s
}

func (p ucPage) data() map[string]any {
	d, _ := p.env["data"].(map[string]any)
	return d
}

// options returns the kinds a factor-choice prompt offers, in order.
func (p ucPage) options() []string {
	raw, _ := p.data()["options"].([]any)
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		m, _ := entry.(map[string]any)
		kind, _ := m["kind"].(string)
		out = append(out, kind)
	}
	return out
}

func (f *ucFixture) requireType(p ucPage, want string) {
	f.t.Helper()
	if got := p.promptType(); got != want {
		f.t.Fatalf("prompt type = %q, want %q (envelope %v)", got, want, p.env)
	}
}

// open starts an authorization for clientID and returns its first prompt.
func (f *ucFixture) open(clientID string) ucPage {
	f.t.Helper()
	return f.openAt(f.authorize(clientID, nil))
}

// openAt follows an /authorize redirect into the interaction.
func (f *ucFixture) openAt(loc *url.URL) ucPage {
	f.t.Helper()
	if strings.HasPrefix(loc.String(), ucRedirect) {
		f.t.Fatalf("authorize answered the RP directly (%s), want an interaction", loc)
	}
	target := f.srv.URL + loc.Path
	if uid, ok := strings.CutPrefix(loc.Path, ucSPAMount+"/"); ok {
		target = f.srv.URL + ucSPAMount + "/state/" + uid
	}
	return f.page(f.do(http.MethodGet, target, "", nil), target, "") //nolint:bodyclose // page closes the body.
}

// post submits values against p.
func (f *ucFixture) post(p ucPage, values map[string]string) *http.Response {
	f.t.Helper()
	return f.do(http.MethodPost, p.target, p.csrf, map[string]any{
		"state_ref": p.env["state_ref"],
		"values":    values,
	})
}

// page decodes resp as the next prompt at target.
func (f *ucFixture) page(resp *http.Response, target, csrf string) ucPage {
	f.t.Helper()
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("prompt status=%d body=%s", resp.StatusCode, raw)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-oidc_csrf" {
			csrf = c.Value
		}
	}
	env := map[string]any{}
	if err := json.Unmarshal(raw, &env); err != nil {
		f.t.Fatalf("decode prompt: %v (body=%s)", err, raw)
	}
	if _, ok := env["state_ref"].(string); !ok {
		f.t.Fatalf("response is not a prompt: %s", raw)
	}
	return ucPage{target: target, csrf: csrf, env: env}
}

// answer submits values and expects another prompt.
func (f *ucFixture) answer(p ucPage, values map[string]string) ucPage {
	f.t.Helper()
	return f.page(f.post(p, values), p.target, p.csrf) //nolint:bodyclose // page closes the body.
}

// finish submits values, approves consent when it is presented, and
// returns the redirect to the RP.
func (f *ucFixture) finish(p ucPage, values map[string]string) *url.URL {
	f.t.Helper()
	return f.terminal(p, f.post(p, values)) //nolint:bodyclose // terminal closes the body.
}

// terminal reads resp as the end of the interaction at p's target: a 302,
// the SPA redirect envelope, or a consent prompt it approves first.
func (f *ucFixture) terminal(p ucPage, resp *http.Response) *url.URL {
	f.t.Helper()
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusFound:
		loc, err := resp.Location()
		if err != nil {
			f.t.Fatalf("terminal Location: %v", err)
		}
		return loc
	case http.StatusOK:
	default:
		f.t.Fatalf("terminal status=%d body=%s", resp.StatusCode, raw)
	}
	csrf := p.csrf
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-oidc_csrf" {
			csrf = c.Value
		}
	}
	env := map[string]any{}
	if err := json.Unmarshal(raw, &env); err != nil {
		f.t.Fatalf("decode terminal: %v (body=%s)", err, raw)
	}
	switch env["type"] {
	case "redirect":
		loc, err := url.Parse(stringOf(env["location"]))
		if err != nil {
			f.t.Fatalf("redirect envelope location: %v", err)
		}
		return loc
	case "consent.scope":
		next := testkit.PostConsentApproval(f.t, f.cl, p.target, testkit.DefaultIssuer, csrf, //nolint:bodyclose // terminal closes the body.
			stringOf(env["state_ref"]), testkit.ApprovedScopesFrom(f.t, env))
		return f.terminal(ucPage{target: p.target, csrf: csrf}, next)
	default:
		f.t.Fatalf("interaction did not end: %s", raw)
		return nil
	}
}

// requireStatus asserts the submission was refused within [lo, hi].
func (f *ucFixture) requireStatus(resp *http.Response, lo, hi int) {
	f.t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode < lo || resp.StatusCode > hi {
		dump, _ := io.ReadAll(resp.Body)
		f.t.Fatalf("status=%d body=%s, want %d..%d", resp.StatusCode, dump, lo, hi)
	}
}

// code returns the authorization code loc carries to the RP.
func (f *ucFixture) code(loc *url.URL) string {
	f.t.Helper()
	code := loc.Query().Get("code")
	if !strings.HasPrefix(loc.String(), ucRedirect) || code == "" {
		f.t.Fatalf("redirect %s, want a code at the RP", loc)
	}
	return code
}

// idToken redeems code for clientID and returns the id_token claims.
func (f *ucFixture) idToken(clientID, code string) map[string]any {
	f.t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {ucRedirect},
		"code_verifier": {ucVerifier},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.srv.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		f.t.Fatalf("token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, ucSecret)
	resp, err := f.cl.Do(req)
	if err != nil {
		f.t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("/token status=%d body=%s", resp.StatusCode, raw)
	}
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(raw, &tokens); err != nil {
		f.t.Fatalf("decode token response: %v", err)
	}
	parts := strings.Split(tokens.IDToken, ".")
	if len(parts) != 3 {
		f.t.Fatalf("id_token is not a JWS: %q", tokens.IDToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		f.t.Fatalf("decode id_token payload: %v", err)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		f.t.Fatalf("parse id_token payload: %v", err)
	}
	return claims
}

// ucAuditRecord is one captured audit line.
type ucAuditRecord struct {
	event  string
	extras map[string]string
}

// ucAuditSink is the slog handler behind WithAuditLogger.
type ucAuditSink struct {
	mu      sync.Mutex
	records []ucAuditRecord
}

func (s *ucAuditSink) Enabled(context.Context, slog.Level) bool { return true }

func (s *ucAuditSink) WithAttrs([]slog.Attr) slog.Handler { return s }

func (s *ucAuditSink) WithGroup(string) slog.Handler { return s }

func (s *ucAuditSink) Handle(_ context.Context, rec slog.Record) error {
	captured := ucAuditRecord{extras: map[string]string{}}
	rec.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "event":
			captured.event = a.Value.String()
		case "extras":
			for _, inner := range a.Value.Resolve().Group() {
				captured.extras[inner.Key] = inner.Value.String()
			}
		}
		return true
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, captured)
	return nil
}

// named returns the captured records of event.
func (s *ucAuditSink) named(event opaudit.Event) []ucAuditRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ucAuditRecord
	for _, r := range s.records {
		if r.event == string(event) {
			out = append(out, r)
		}
	}
	return out
}

// requireBeginFailed asserts exactly one step_begin_failed for kind with reason.
func (f *ucFixture) requireBeginFailed(kind op.StepKind, reason string) {
	f.t.Helper()
	got := f.audit.named(opaudit.StepBeginFailed)
	if len(got) != 1 {
		f.t.Fatalf("%s events = %d (%v), want 1", opaudit.StepBeginFailed, len(got), got)
	}
	if got[0].extras["step_kind"] != string(kind) || got[0].extras["reason"] != reason {
		f.t.Fatalf("%s extras = %v, want step_kind=%s reason=%s", opaudit.StepBeginFailed, got[0].extras, kind, reason)
	}
}

// ucExternal is an embedder factor: a prompt for a code where "ok"
// completes, "again" is a rejected code that re-shows the prompt, and
// anything else is a rejected code. It claims amr "pwd" for itself, which
// the session must not trust.
type ucExternal struct {
	beginErr error
	begins   atomic.Int32
}

func (*ucExternal) Type() op.FactorType { return "uctest.ext" }
func (*ucExternal) AAL() op.AAL         { return op.AAL1 }
func (*ucExternal) AMR() string         { return "pwd" }
func (*ucExternal) Prompts() []string   { return []string{ucExternalPrompt} }

func (e *ucExternal) Begin(context.Context, op.BeginInput) (interaction.Step, error) {
	e.begins.Add(1)
	if e.beginErr != nil {
		return interaction.Step{}, e.beginErr
	}
	return interaction.Step{Prompt: ucExternalCodePrompt()}, nil
}

func (e *ucExternal) Continue(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
	switch in.Submission.Values[ucExternalField] {
	case "ok":
		return interaction.Step{Result: &interaction.Result{Subject: in.Subject, AuthTime: in.AuthTime}}, nil
	case "again":
		return interaction.Step{Prompt: ucExternalCodePrompt()}, fmt.Errorf("uctest: wrong code: %w", op.ErrFactorRetry)
	case "other":
		return interaction.Step{Result: &interaction.Result{Subject: "uctest-other", AuthTime: in.AuthTime}}, nil
	default:
		return interaction.Step{}, fmt.Errorf("uctest: wrong code: %w", op.ErrFactorRetry)
	}
}

func ucExternalCodePrompt() *interaction.Prompt {
	return &interaction.Prompt{
		Type: ucExternalPrompt,
		Inputs: []interaction.FieldSpec{{
			Name:     ucExternalField,
			Kind:     interaction.FieldText,
			Required: true,
			MaxLen:   64,
		}},
	}
}

func ucExternalStep(e *ucExternal, countFailures bool) op.ExternalStep {
	return op.ExternalStep{Authenticator: e, KindLabel: ucExternalKind, CountFailures: countFailures}
}

// --- Legacy password hashes ---

func ucLegacyFlow(passwords store.UserPasswordStore) op.LoginFlow {
	return op.LoginFlow{Primary: op.PrimaryPassword{
		Store:         passwords,
		LegacySchemes: []op.PasswordHashScheme{op.BcryptHashScheme()},
	}}
}

func TestEndToEnd_PasswordLegacyBcrypt_LoginAndRehash(t *testing.T) {
	t.Parallel()
	f := newUCFixture(t, ucJSONDriver, func(f *ucFixture) op.LoginFlow { return ucLegacyFlow(f.st.UserPasswords()) })
	f.seedBcryptUser()

	p := f.open(ucClient)
	f.requireType(p, authnpassword.PromptType)
	f.code(f.finish(p, ucCredentials()))

	if hash := f.storedHash(); !bytes.HasPrefix(hash, []byte("$argon2id$")) {
		t.Fatalf("stored hash after login = %q, want an argon2id rewrite", hash)
	}
	// A fresh browser logs in against the rewritten hash.
	f.newBrowser()
	f.code(f.finish(f.open(ucClient), ucCredentials()))
}

func TestEndToEnd_PasswordLegacyBcrypt_MismatchCountsTowardLockout(t *testing.T) {
	t.Parallel()
	f := newUCFixture(t, ucJSONDriver, func(f *ucFixture) op.LoginFlow { return ucLegacyFlow(f.st.UserPasswords()) })
	f.seedBcryptUser()

	p := f.open(ucClient)
	p = f.answer(p, map[string]string{
		authnpassword.UsernameFieldName: ucUsername,
		authnpassword.PasswordFieldName: "wrong password",
	})
	f.requireType(p, authnpassword.PromptType)
	if got := f.failedCount(); got != 1 {
		t.Fatalf("lockout count after a bcrypt mismatch = %d, want 1", got)
	}
	if hash := f.storedHash(); !bytes.HasPrefix(hash, []byte("$2a$")) {
		t.Fatalf("stored hash after a mismatch = %q, want the bcrypt hash untouched", hash)
	}
	f.code(f.finish(p, ucCredentials()))
}

// ucPasswordsNoUpdater hides the store's UpdatePasswordHash.
type ucPasswordsNoUpdater struct{ store.UserPasswordStore }

// ucPasswordsFailingUpdater refuses every hash rewrite.
type ucPasswordsFailingUpdater struct {
	store.UserPasswordStore
	calls atomic.Int32
}

func (u *ucPasswordsFailingUpdater) UpdatePasswordHash(context.Context, string, []byte) error {
	u.calls.Add(1)
	return errors.New("uctest: write refused")
}

func TestEndToEnd_PasswordLegacyBcrypt_NoUpdaterKeepsLegacy(t *testing.T) {
	t.Parallel()
	f := newUCFixture(t, ucJSONDriver, func(f *ucFixture) op.LoginFlow {
		return ucLegacyFlow(&ucPasswordsNoUpdater{UserPasswordStore: f.st.UserPasswords()})
	})
	f.seedBcryptUser()

	f.code(f.finish(f.open(ucClient), ucCredentials()))
	if hash := f.storedHash(); !bytes.HasPrefix(hash, []byte("$2a$")) {
		t.Fatalf("stored hash = %q, want the bcrypt hash kept without an updater", hash)
	}
}

func TestEndToEnd_PasswordLegacyBcrypt_UpdaterErrorStillLogsIn(t *testing.T) {
	t.Parallel()
	var updater *ucPasswordsFailingUpdater
	f := newUCFixture(t, ucJSONDriver, func(f *ucFixture) op.LoginFlow {
		updater = &ucPasswordsFailingUpdater{UserPasswordStore: f.st.UserPasswords()}
		return ucLegacyFlow(updater)
	})
	f.seedBcryptUser()

	f.code(f.finish(f.open(ucClient), ucCredentials()))
	if got := updater.calls.Load(); got != 1 {
		t.Fatalf("UpdatePasswordHash calls = %d, want 1", got)
	}
	if hash := f.storedHash(); !bytes.HasPrefix(hash, []byte("$2a$")) {
		t.Fatalf("stored hash = %q, want the bcrypt hash kept after a failed rewrite", hash)
	}
}

// --- Passwordless passkey ---

func newPasskeyFixture(t *testing.T) *ucFixture {
	t.Helper()
	f := newUCFixture(t, ucSPA, func(f *ucFixture) op.LoginFlow { return op.LoginFlow{Primary: f.passkeyStep()} })
	f.st.PutUser(context.Background(), &store.User{Subject: ucSubject})
	return f
}

// assertPasskey answers a passkey prompt with key signing for userHandle.
func (f *ucFixture) assertPasskey(p ucPage, key *passkeytest.Authenticator, userHandle string) *http.Response {
	f.t.Helper()
	f.requireType(p, authnpasskey.PromptType)
	challenge, err := base64.StdEncoding.DecodeString(stringOf(p.data()["challenge"]))
	if err != nil || len(challenge) == 0 {
		f.t.Fatalf("passkey challenge %v: %v", p.data()["challenge"], err)
	}
	response := key.Assert(f.t, challenge, ucOrigin, []byte(userHandle), true)
	return f.post(p, map[string]string{authnpasskey.ResponseFieldName: string(response)})
}

func TestEndToEnd_PasswordlessPasskey_DiscoverableLogin(t *testing.T) {
	t.Parallel()
	f := newPasskeyFixture(t)
	key := f.enrollPasskey(ucSubject)

	p := f.open(ucClient)
	if allow, _ := p.data()["allow_credentials"].([]any); len(allow) != 0 {
		t.Fatalf("allow_credentials = %v, want empty for a discoverable ceremony", allow)
	}
	claims := f.idToken(ucClient, f.code(f.terminal(p, f.assertPasskey(p, key, ucSubject)))) //nolint:bodyclose // terminal closes the body.

	if claims["sub"] != ucSubject {
		t.Fatalf("sub = %v, want %s", claims["sub"], ucSubject)
	}
	if claims["acr"] != op.AAL2.ACRURI() {
		t.Fatalf("acr = %v, want %s", claims["acr"], op.AAL2.ACRURI())
	}
	if amr, _ := claims["amr"].([]any); !reflect.DeepEqual(amr, []any{"hwk"}) {
		t.Fatalf("amr = %v, want [hwk]", claims["amr"])
	}
}

func TestEndToEnd_PasswordlessPasskey_UnknownCredentialReprompts(t *testing.T) {
	t.Parallel()
	f := newPasskeyFixture(t)
	f.enrollPasskey(ucSubject)
	stranger := passkeytest.New(t, ucRPID)

	p := f.open(ucClient)
	next := f.page(f.assertPasskey(p, stranger, ucSubject), p.target, p.csrf) //nolint:bodyclose // page closes the body.
	f.requireType(next, authnpasskey.PromptType)
}

func TestEndToEnd_PasswordlessPasskey_UserHandleMismatchReprompts(t *testing.T) {
	t.Parallel()
	f := newPasskeyFixture(t)
	key := f.enrollPasskey(ucSubject)
	f.enrollPasskey("user-mallory")

	p := f.open(ucClient)
	next := f.page(f.assertPasskey(p, key, "user-mallory"), p.target, p.csrf) //nolint:bodyclose // the callee closes the body.
	f.requireType(next, authnpasskey.PromptType)
}

// --- StepOneOf ---

type ucOneOfRow struct {
	primary    bool
	enrolled   int // 0, 1, 2 (many)
	policy     op.UnenrolledPolicy
	submission string // "offered", "unoffered", "none"
}

// runOneOfRow drives one model row. After Primary the one-of step is
// TOTP | passkey | recovery code, and "one" enrolls TOTP while "many"
// enrolls TOTP and a passkey, so recovery_code is the kind never offered.
// At Primary it is password | passkey, offered without a probe.
func runOneOfRow(t *testing.T, row ucOneOfRow) {
	t.Helper()
	f := newUCFixture(t, ucJSONDriver, func(f *ucFixture) op.LoginFlow {
		if row.primary {
			return op.LoginFlow{Primary: op.StepOneOf{
				Steps:          []op.Step{f.passwordStep(), f.passkeyStep()},
				IfNoneEnrolled: row.policy,
			}}
		}
		return op.LoginFlow{
			Primary: f.passwordStep(),
			Rules: []op.Rule{op.RuleAlways(op.StepOneOf{
				Steps:          []op.Step{f.totpStep(), f.passkeyStep(), op.StepRecoveryCode{Store: f.st.RecoveryCodes()}},
				IfNoneEnrolled: row.policy,
			})},
		}
	})
	f.seedArgonUser()
	if !row.primary {
		if row.enrolled >= 1 {
			f.enrollTOTP()
		}
		if row.enrolled >= 2 {
			f.enrollPasskey(ucSubject)
		}
	}

	p := f.open(ucClient)
	wantOffered := []string{"password", "passkey"}
	if !row.primary {
		wantOffered = []string{"totp", "passkey"}
		f.requireType(p, authnpassword.PromptType)
		resp := f.post(p, ucCredentials()) //nolint:bodyclose // the callee closes the body.
		switch {
		case row.enrolled == 0 && row.policy == op.UnenrolledDeny:
			f.requireStatus(resp, 400, 499)
			return
		case row.enrolled == 0:
			f.code(f.terminal(p, resp))
			return
		case row.enrolled == 1:
			p = f.page(resp, p.target, p.csrf)
			f.requireType(p, authntotp.PromptType)
			f.code(f.finish(p, f.totpCode()))
			return
		}
		p = f.page(resp, p.target, p.csrf)
	}

	f.requireType(p, interaction.PromptTypeChooseFactor)
	if got := p.options(); !slices.Equal(got, wantOffered) {
		t.Fatalf("offered = %v, want %v", got, wantOffered)
	}
	switch row.submission {
	case "unoffered":
		// Refused the way a stale state_ref is.
		f.requireStatus(f.post(p, map[string]string{interaction.FactorChoiceField: "recovery_code"}), //nolint:bodyclose // the callee closes the body.
			http.StatusForbidden, http.StatusForbidden)
	case "offered":
		if row.primary {
			p = f.answer(p, map[string]string{interaction.FactorChoiceField: "password"})
			f.requireType(p, authnpassword.PromptType)
			f.code(f.finish(p, ucCredentials()))
			return
		}
		p = f.answer(p, map[string]string{interaction.FactorChoiceField: "totp"})
		f.requireType(p, authntotp.PromptType)
		f.code(f.finish(p, f.totpCode()))
	}
}

func TestEndToEnd_OneOf_Row01_PostPrimaryNoneEnrolledDeny(t *testing.T) {
	t.Parallel()
	runOneOfRow(t, ucOneOfRow{enrolled: 0, policy: op.UnenrolledDeny, submission: "none"})
}

func TestEndToEnd_OneOf_Row02_PostPrimaryOneEnrolledSkip(t *testing.T) {
	t.Parallel()
	runOneOfRow(t, ucOneOfRow{enrolled: 1, policy: op.UnenrolledSkip, submission: "none"})
}

func TestEndToEnd_OneOf_Row03_PostPrimaryManySkipOffered(t *testing.T) {
	t.Parallel()
	runOneOfRow(t, ucOneOfRow{enrolled: 2, policy: op.UnenrolledSkip, submission: "offered"})
}

func TestEndToEnd_OneOf_Row04_PostPrimaryManyDenyUnoffered(t *testing.T) {
	t.Parallel()
	runOneOfRow(t, ucOneOfRow{enrolled: 2, policy: op.UnenrolledDeny, submission: "unoffered"})
}

func TestEndToEnd_OneOf_Row05_PostPrimaryManySkipUnoffered(t *testing.T) {
	t.Parallel()
	runOneOfRow(t, ucOneOfRow{enrolled: 2, policy: op.UnenrolledSkip, submission: "unoffered"})
}

func TestEndToEnd_OneOf_Row06_PrimaryDenyOffered(t *testing.T) {
	t.Parallel()
	runOneOfRow(t, ucOneOfRow{primary: true, enrolled: 2, policy: op.UnenrolledDeny, submission: "offered"})
}

func TestEndToEnd_OneOf_Row07_PrimaryDenyUnoffered(t *testing.T) {
	t.Parallel()
	runOneOfRow(t, ucOneOfRow{primary: true, enrolled: 2, policy: op.UnenrolledDeny, submission: "unoffered"})
}

func TestEndToEnd_OneOf_Row08_PrimaryDenyNoChoice(t *testing.T) {
	t.Parallel()
	runOneOfRow(t, ucOneOfRow{primary: true, enrolled: 2, policy: op.UnenrolledDeny, submission: "none"})
}

func TestEndToEnd_OneOf_Row09_PostPrimaryOneEnrolledDeny(t *testing.T) {
	t.Parallel()
	runOneOfRow(t, ucOneOfRow{enrolled: 1, policy: op.UnenrolledDeny, submission: "none"})
}

func TestEndToEnd_OneOf_Row10_PostPrimaryNoneEnrolledSkip(t *testing.T) {
	t.Parallel()
	runOneOfRow(t, ucOneOfRow{enrolled: 0, policy: op.UnenrolledSkip, submission: "none"})
}

func TestEndToEnd_OneOf_SkipDoesNotBlockPromptNone(t *testing.T) {
	t.Parallel()
	f := newUCFixture(t, ucJSONDriver, func(f *ucFixture) op.LoginFlow {
		return op.LoginFlow{
			Primary: f.passwordStep(),
			Rules: []op.Rule{op.RuleAlways(op.StepOneOf{
				Steps:          []op.Step{f.totpStep(), op.StepRecoveryCode{Store: f.st.RecoveryCodes()}},
				IfNoneEnrolled: op.UnenrolledSkip,
			})},
		}
	})
	f.seedArgonUser()
	f.code(f.finish(f.open(ucClient), ucCredentials()))

	loc := f.authorize(ucClient, url.Values{"prompt": {"none"}})
	if e := loc.Query().Get("error"); e != "" {
		t.Fatalf("prompt=none answered error=%s, want a code for a subject enrolled in none of the steps", e)
	}
	f.code(loc)
}

// --- Session reuse ---

func TestEndToEnd_SessionReuse_TOTPSessionSkipsRule(t *testing.T) {
	t.Parallel()
	f := newUCFixture(t, ucJSONDriver, func(f *ucFixture) op.LoginFlow {
		return op.LoginFlow{Primary: f.passwordStep(), Rules: []op.Rule{op.RuleAlways(f.totpStep())}}
	})
	f.seedArgonUser()
	f.enrollTOTP()

	p := f.answer(f.open(ucClient), ucCredentials())
	f.requireType(p, authntotp.PromptType)
	f.code(f.finish(p, f.totpCode()))

	f.code(f.authorize(ucClient, nil))
}

func TestEndToEnd_SessionReuse_PasswordSessionRequiresTOTP(t *testing.T) {
	t.Parallel()
	f := newUCFixture(t, ucJSONDriver, func(f *ucFixture) op.LoginFlow {
		return op.LoginFlow{Primary: f.passwordStep(), Rules: []op.Rule{op.RuleClient(ucAdmin, f.totpStep())}}
	})
	f.seedArgonUser()
	f.enrollTOTP()
	f.code(f.finish(f.open(ucClient), ucCredentials()))

	// The password session stands in for Primary only: TOTP is asked, not the password.
	p := f.openAt(f.authorize(ucAdmin, nil))
	f.requireType(p, authntotp.PromptType)
}

func TestEndToEnd_SessionReuse_OneOfSatisfiedByAMR(t *testing.T) {
	t.Parallel()
	f := newUCFixture(t, ucJSONDriver, func(f *ucFixture) op.LoginFlow {
		return op.LoginFlow{
			Primary: f.passwordStep(),
			Rules: []op.Rule{op.RuleAlways(op.StepOneOf{
				Steps: []op.Step{f.totpStep(), op.StepRecoveryCode{Store: f.st.RecoveryCodes()}},
			})},
		}
	})
	f.seedArgonUser()
	f.enrollTOTP()

	p := f.answer(f.open(ucClient), ucCredentials())
	f.requireType(p, authntotp.PromptType)
	f.code(f.finish(p, f.totpCode()))

	f.code(f.authorize(ucClient, nil))
}

func TestEndToEnd_SessionReuse_PromptNoneWithSatisfiedRule(t *testing.T) {
	t.Parallel()
	f := newUCFixture(t, ucJSONDriver, func(f *ucFixture) op.LoginFlow {
		return op.LoginFlow{Primary: f.passwordStep(), Rules: []op.Rule{op.RuleAlways(f.totpStep())}}
	})
	f.seedArgonUser()
	f.enrollTOTP()
	p := f.answer(f.open(ucClient), ucCredentials())
	f.code(f.finish(p, f.totpCode()))

	loc := f.authorize(ucClient, url.Values{"prompt": {"none"}})
	if e := loc.Query().Get("error"); e != "" {
		t.Fatalf("prompt=none answered error=%s, want a code from the TOTP session", e)
	}
	f.code(loc)
}

func TestEndToEnd_SessionReuse_ExternalStepNeverSatisfiedByAMR(t *testing.T) {
	t.Parallel()
	ext := &ucExternal{}
	f := newUCFixture(t, ucJSONDriver, func(f *ucFixture) op.LoginFlow {
		return op.LoginFlow{Primary: f.passwordStep(), Rules: []op.Rule{op.RuleAlways(ucExternalStep(ext, false))}}
	})
	f.seedArgonUser()

	p := f.answer(f.open(ucClient), ucCredentials())
	f.requireType(p, ucExternalPrompt)
	f.code(f.finish(p, map[string]string{ucExternalField: "ok"}))

	// The session's amr carries "pwd", the amr the factor claims for
	// itself; the factor still runs again.
	p = f.openAt(f.authorize(ucClient, nil))
	f.requireType(p, ucExternalPrompt)
}

func TestEndToEnd_SessionReuse_ExternalStepCannotSwitchSubject(t *testing.T) {
	t.Parallel()
	ext := &ucExternal{}
	f := newUCFixture(t, ucJSONDriver, func(f *ucFixture) op.LoginFlow {
		return op.LoginFlow{Primary: f.passwordStep(), Rules: []op.Rule{op.RuleAlways(ucExternalStep(ext, false))}}
	})
	f.seedArgonUser()

	p := f.answer(f.open(ucClient), ucCredentials())
	f.code(f.finish(p, map[string]string{ucExternalField: "ok"}))

	// The chain stands on the session's subject; a result naming another
	// account ends it instead of signing that account in.
	p = f.openAt(f.authorize(ucClient, nil))
	f.requireType(p, ucExternalPrompt)
	f.requireStatus(f.post(p, map[string]string{ucExternalField: "other"}), 400, 499) //nolint:bodyclose // the callee closes the body.
}

// --- Begin failure audit ---

func TestEndToEnd_StepBeginFailed_NotEnrolled(t *testing.T) {
	t.Parallel()
	f := newUCFixture(t, ucJSONDriver, func(f *ucFixture) op.LoginFlow {
		return op.LoginFlow{Primary: f.passwordStep(), Rules: []op.Rule{op.RuleAlways(f.totpStep())}}
	})
	f.seedArgonUser()

	f.requireStatus(f.post(f.open(ucClient), ucCredentials()), 400, 499) //nolint:bodyclose // the callee closes the body.
	f.requireBeginFailed(op.StepKindTOTP, "not_enrolled")
}

func TestEndToEnd_StepBeginFailed_Aborted(t *testing.T) {
	t.Parallel()
	ext := &ucExternal{beginErr: fmt.Errorf("uctest: device revoked: %w", op.ErrFactorAbort)}
	f := newUCFixture(t, ucJSONDriver, func(f *ucFixture) op.LoginFlow {
		return op.LoginFlow{Primary: f.passwordStep(), Rules: []op.Rule{op.RuleAlways(ucExternalStep(ext, false))}}
	})
	f.seedArgonUser()

	f.requireStatus(f.post(f.open(ucClient), ucCredentials()), 400, 499) //nolint:bodyclose // the callee closes the body.
	f.requireBeginFailed(ucExternalKind, "aborted")
}

func TestEndToEnd_StepBeginFailed_NotEnrolledSkipped(t *testing.T) {
	t.Parallel()
	oneOf := func(f *ucFixture) op.StepOneOf {
		return op.StepOneOf{Steps: []op.Step{f.totpStep()}, IfNoneEnrolled: op.UnenrolledSkip}
	}
	f := newUCFixture(t, ucJSONDriver, func(f *ucFixture) op.LoginFlow {
		return op.LoginFlow{Primary: f.passwordStep(), Rules: []op.Rule{op.RuleAlways(oneOf(f))}}
	})
	f.seedArgonUser()

	f.code(f.finish(f.open(ucClient), ucCredentials()))
	f.requireBeginFailed(oneOf(f).Kind(), "not_enrolled_skipped")
}

func TestEndToEnd_StepBeginFailed_Error(t *testing.T) {
	t.Parallel()
	ext := &ucExternal{beginErr: errors.New("uctest: backend unavailable")}
	f := newUCFixture(t, ucJSONDriver, func(f *ucFixture) op.LoginFlow {
		return op.LoginFlow{Primary: f.passwordStep(), Rules: []op.Rule{op.RuleAlways(ucExternalStep(ext, false))}}
	})
	f.seedArgonUser()

	f.requireStatus(f.post(f.open(ucClient), ucCredentials()), 500, 599) //nolint:bodyclose // the callee closes the body.
	f.requireBeginFailed(ucExternalKind, "error")
}

// --- ExternalStep lockout ---

func TestEndToEnd_ExternalStepLockout_CountsRetry(t *testing.T) {
	t.Parallel()
	ext := &ucExternal{}
	f := newUCFixture(t, ucJSONDriver, func(f *ucFixture) op.LoginFlow {
		return op.LoginFlow{Primary: f.passwordStep(), Rules: []op.Rule{op.RuleAlways(ucExternalStep(ext, true))}}
	})
	f.seedArgonUser()

	p := f.answer(f.open(ucClient), ucCredentials())
	f.requireType(p, ucExternalPrompt)

	p = f.answer(p, map[string]string{ucExternalField: "wrong"})
	f.requireType(p, ucExternalPrompt)
	if got := f.failedCount(); got != 1 {
		t.Fatalf("lockout count after a rejected code = %d, want 1", got)
	}
	p = f.answer(p, map[string]string{ucExternalField: "again"})
	f.requireType(p, ucExternalPrompt)
	if got := f.failedCount(); got != 2 {
		t.Fatalf("lockout count after a rejected code that re-prompts = %d, want 2", got)
	}

	f.code(f.finish(p, map[string]string{ucExternalField: "ok"}))
	if got := f.failedCount(); got != 0 {
		t.Fatalf("lockout count after completion = %d, want 0", got)
	}
}

func TestEndToEnd_ExternalStepLockout_LockedRefusesBegin(t *testing.T) {
	t.Parallel()
	ext := &ucExternal{}
	f := newUCFixture(t, ucJSONDriver, func(*ucFixture) op.LoginFlow {
		return op.LoginFlow{
			Primary: op.ExternalStep{Authenticator: testkit.SubjectAuthenticator{}, KindLabel: "testkit.subject"},
			Rules:   []op.Rule{op.RuleAlways(ucExternalStep(ext, true))},
		}
	})
	f.st.PutUser(context.Background(), &store.User{Subject: ucSubject})
	now := f.clock.Now()
	if ok, err := f.st.AuthnLockouts().CompareAndSwap(context.Background(), 0, &store.AuthnLockoutRecord{
		Subject:        ucSubject,
		FailedCount:    30,
		FirstFailureAt: now,
		LockedUntil:    now.Add(time.Hour),
	}); err != nil || !ok {
		t.Fatalf("seed lockout: ok=%v err=%v", ok, err)
	}

	p := f.open(ucClient)
	f.requireStatus(f.post(p, map[string]string{testkit.SubjectFieldName: ucSubject}), 400, 499) //nolint:bodyclose // the callee closes the body.
	if got := ext.begins.Load(); got != 0 {
		t.Fatalf("Begin ran %d times for a locked subject, want 0", got)
	}
	f.requireBeginFailed(ucExternalKind, "locked")
}

// --- LoginContext session view ---

// ucSessionView is the part of a LoginContext describing the session.
type ucSessionView struct {
	AAL      op.AAL
	Reused   bool
	AMR      []string
	ACR      string
	AuthTime int64
}

func ucViewOf(lc op.LoginContext) ucSessionView {
	ac := lc.Identity.AuthenticationContext
	return ucSessionView{AAL: lc.AAL, Reused: lc.SessionReused, AMR: ac.AMR, ACR: ac.ACR, AuthTime: ac.AuthTime}
}

// ucRecorder keeps the last LoginContext it saw.
type ucRecorder struct {
	mu   sync.Mutex
	last op.LoginContext
	seen bool
}

func (r *ucRecorder) record(lc op.LoginContext) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last, r.seen = lc, true
}

// take returns the last view and forgets it.
func (r *ucRecorder) take(t *testing.T, who string) ucSessionView {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.seen {
		t.Fatalf("%s saw no LoginContext", who)
	}
	r.seen = false
	return ucViewOf(r.last)
}

// ucRecordingPolicy is DefaultACRPolicy recording what Resolve sees.
type ucRecordingPolicy struct{ ucRecorder }

func (p *ucRecordingPolicy) Resolve(ctx context.Context, lc op.LoginContext, internal op.AAL) (string, []string, bool) {
	p.record(lc)
	return op.DefaultACRPolicy{}.Resolve(ctx, lc, internal)
}

func (p *ucRecordingPolicy) Satisfies(ctx context.Context, requested string, internal op.AAL, completed []op.StepKind) bool {
	return op.DefaultACRPolicy{}.Satisfies(ctx, requested, internal, completed)
}

// newSessionViewFixture is a password login whose one rule never fires
// but records what its predicate sees, beside a recording ACR policy.
func newSessionViewFixture(t *testing.T) (*ucFixture, *ucRecorder, *ucRecordingPolicy) {
	t.Helper()
	predicate := &ucRecorder{}
	policy := &ucRecordingPolicy{}
	f := newUCFixture(t, ucJSONDriver, func(f *ucFixture) op.LoginFlow {
		return op.LoginFlow{
			Primary: f.passwordStep(),
			Rules: []op.Rule{op.RuleWhen(func(lc op.LoginContext) bool {
				predicate.record(lc)
				return false
			}, ucExternalStep(&ucExternal{}, false))},
		}
	}, op.WithACRPolicy(policy))
	f.seedArgonUser()
	return f, predicate, policy
}

func TestLoginContext_SessionAuth_Fresh(t *testing.T) {
	t.Parallel()
	f, predicate, _ := newSessionViewFixture(t)
	f.code(f.finish(f.open(ucClient), ucCredentials()))

	want := ucSessionView{AAL: op.AAL1, AMR: []string{"pwd"}, ACR: op.AAL1.ACRURI()}
	if got := predicate.take(t, "predicate"); !reflect.DeepEqual(got, want) {
		t.Fatalf("fresh login view = %+v, want %+v", got, want)
	}
}

func TestLoginContext_SessionAuth_Reused(t *testing.T) {
	t.Parallel()
	f, predicate, _ := newSessionViewFixture(t)
	f.code(f.finish(f.open(ucClient), ucCredentials()))
	predicate.take(t, "predicate")

	f.code(f.authorize(ucClient, nil))
	want := ucSessionView{
		AAL:      op.AAL1,
		Reused:   true,
		AMR:      []string{"pwd"},
		ACR:      op.AAL1.ACRURI(),
		AuthTime: f.clock.Now().Unix(),
	}
	if got := predicate.take(t, "predicate"); !reflect.DeepEqual(got, want) {
		t.Fatalf("reused session view = %+v, want %+v", got, want)
	}
}

func TestLoginContext_SessionAuth_ResolverMatchesPredicate(t *testing.T) {
	t.Parallel()
	f, predicate, policy := newSessionViewFixture(t)

	f.code(f.finish(f.open(ucClient), ucCredentials()))
	if p, r := predicate.take(t, "predicate"), policy.take(t, "ACR policy"); !reflect.DeepEqual(p, r) {
		t.Fatalf("fresh login: predicate saw %+v, Resolve saw %+v", p, r)
	}

	f.code(f.authorize(ucClient, nil))
	p, r := predicate.take(t, "predicate"), policy.take(t, "ACR policy")
	if !p.Reused || !reflect.DeepEqual(p, r) {
		t.Fatalf("reused session: predicate saw %+v, Resolve saw %+v", p, r)
	}
}
