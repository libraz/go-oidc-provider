package authorizeendpoint_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
)

// silentConflictFault fails the grant amendment of the leading silent-mint
// attempts and records what each attempt tried to persist. It faults the
// grant write rather than the commit because that is where a
// version-checking backend reports the loser of a read-modify-write race:
// the read that planned the amendment is stale by the time the write lands.
type silentConflictFault struct {
	// err is returned in place of the grant write while the fault is active.
	err error
	// failures caps how many leading grant writes fail; a negative value
	// fails every one.
	failures int

	grantSaves atomic.Int32

	mu              sync.Mutex
	savedCodes      []string
	consumedRequest []string
}

func (f *silentConflictFault) nextGrantSaveFails() bool {
	attempt := int(f.grantSaves.Add(1))
	return f.failures < 0 || attempt <= f.failures
}

// attempts reports how many times the endpoint ran the silent commit far
// enough to write the grant, which is one per transaction it opened.
func (f *silentConflictFault) attempts() int {
	return int(f.grantSaves.Load())
}

func (f *silentConflictFault) recordSavedCode(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.savedCodes = append(f.savedCodes, id)
}

// savedCodeIDs returns the distinct authorization-code identifiers every
// attempt offered to the store. A retry re-derives the identifier the
// caller drew once, so a run that minted a second code shows up here as a
// second entry even though the losing attempt's write was rolled back.
func (f *silentConflictFault) savedCodeIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := slices.Clone(f.savedCodes)
	slices.Sort(ids)
	return slices.Compact(ids)
}

func (f *silentConflictFault) recordConsumedRequestURI(uri string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.consumedRequest = append(f.consumedRequest, uri)
}

// successfulPARConsumes counts the consumptions that actually redeemed the
// request_uri, which RFC 9126 §2.2 caps at one however many attempts the
// request took.
func (f *silentConflictFault) successfulPARConsumes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.consumedRequest)
}

type silentConflictTransactional struct {
	store.Transactional
	fault *silentConflictFault
}

func (s silentConflictTransactional) BeginTx(ctx context.Context) (store.Tx, error) {
	tx, err := s.Transactional.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	return silentConflictTx{Tx: tx, fault: s.fault}, nil
}

type silentConflictTx struct {
	store.Tx
	fault *silentConflictFault
}

func (tx silentConflictTx) Grants() store.GrantStore {
	return silentConflictGrantStore{GrantStore: tx.Tx.Grants(), fault: tx.fault}
}

func (tx silentConflictTx) AuthorizationCodes() store.AuthorizationCodeStore {
	return silentConflictCodeStore{
		AuthorizationCodeStore: tx.Tx.AuthorizationCodes(),
		fault:                  tx.fault,
	}
}

func (tx silentConflictTx) PushedAuthRequests() store.PushedAuthRequestStore {
	return silentConflictPARStore{
		PushedAuthRequestStore: tx.Tx.PushedAuthRequests(),
		fault:                  tx.fault,
	}
}

type silentConflictGrantStore struct {
	store.GrantStore
	fault *silentConflictFault
}

func (s silentConflictGrantStore) Save(ctx context.Context, grant *store.Grant) error {
	if s.fault.nextGrantSaveFails() {
		return s.fault.err
	}
	return s.GrantStore.Save(ctx, grant)
}

type silentConflictCodeStore struct {
	store.AuthorizationCodeStore
	fault *silentConflictFault
}

func (s silentConflictCodeStore) Save(ctx context.Context, code *store.AuthorizationCode) error {
	s.fault.recordSavedCode(code.ID)
	return s.AuthorizationCodeStore.Save(ctx, code)
}

type silentConflictPARStore struct {
	store.PushedAuthRequestStore
	fault *silentConflictFault
}

func (s silentConflictPARStore) Consume(ctx context.Context, uri string) (*store.PushedAuthRequest, error) {
	rec, err := s.PushedAuthRequestStore.Consume(ctx, uri)
	if err == nil {
		s.fault.recordConsumedRequestURI(uri)
	}
	return rec, err
}

// armSilentConflict installs the fault-injecting transactional store and
// rebuilds the handler so the silent mint runs against it.
func armSilentConflict(t *testing.T, h *firstPartyHarness, fault *silentConflictFault) {
	t.Helper()
	h.deps.Transactions = silentConflictTransactional{
		Transactional: h.store,
		fault:         fault,
	}
	h.handler = authorizeendpoint.Handler(h.deps)
}

// silentMintSession issues the session a first-party silent mint needs.
func silentMintSession(t *testing.T, h *firstPartyHarness) sessions.Outcome {
	t.Helper()
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
		AMR:      []string{"pwd"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return out
}

// doSilentAuthorize drives the same-origin GET that a session-bound
// first-party client takes straight to a code redirect.
func doSilentAuthorize(t *testing.T, h *firstPartyHarness, cookieValue string, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+values.Encode(), http.NoBody)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, r)
	return rr
}

// TestAuthorize_SilentMint_LostGrantAmendmentConflictStillMintsCode pins
// that the silent mint survives a lost optimistic-lock race exactly as the
// interaction-completion path does. Two tabs opening the same first-party
// app amend one (subject, client) grant concurrently, and a backend that
// versions the record fails whichever transaction read first. Nothing about
// that request was invalid, so failing it with server_error would break a
// flow the user never saw a prompt for; the loser re-reads and re-applies
// instead.
func TestAuthorize_SilentMint_LostGrantAmendmentConflictStillMintsCode(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t)
	session := silentMintSession(t, h)
	fault := &silentConflictFault{err: conflictError(), failures: 1}
	armSilentConflict(t, h, fault)

	rr := doSilentAuthorize(t, h, session.Cookie, goodAuthorizeValues())
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d want 302 body=%s", rr.Code, rr.Body.String())
	}
	location := mustParseLocation(t, rr.Result())
	if got := location.Query().Get("error"); got != "" {
		t.Fatalf("error=%q; a grant amendment conflict must not reach the client", got)
	}
	codeID := location.Query().Get("code")
	if codeID == "" {
		t.Fatalf("Location=%s carries no code", location.String())
	}
	if got := fault.attempts(); got != 2 {
		t.Fatalf("commit attempts=%d want 2 (the conflict must actually be injected)", got)
	}

	// The identifier is drawn once per request, so a retry rewrites it
	// rather than leaving a second redeemable code behind.
	if ids := fault.savedCodeIDs(); len(ids) != 1 || ids[0] != codeID {
		t.Fatalf("attempts persisted code IDs %v, want exactly the redirected %q", ids, codeID)
	}
	code, err := h.store.AuthorizationCodes().Find(context.Background(), codeID)
	if err != nil {
		t.Fatalf("Find authorization code: %v", err)
	}

	// A retried amendment must land on the one grant the subject has with
	// this client, not widen into a second record.
	grants, err := h.store.Grants().ListBySubject(context.Background(), "user-fp")
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if len(grants) != 1 || grants[0].ID != code.GrantID {
		t.Fatalf("grants=%v want exactly the code's grant %q", grants, code.GrantID)
	}

	// The redirect is only worth issuing if the RP can redeem it.
	consumed, err := h.store.AuthorizationCodes().Consume(context.Background(), codeID)
	if err != nil {
		t.Fatalf("Consume retried code: %v", err)
	}
	if consumed.GrantID != code.GrantID {
		t.Fatalf("consumed GrantID=%q want %q", consumed.GrantID, code.GrantID)
	}
}

// TestAuthorize_SilentMint_RetryRedeemsRequestURIOnce pins the RFC 9126
// §2.2 one-time-use guarantee across a retry. The consumption is staged in
// the same transaction as the code, so the attempt that lost the race gave
// the request_uri back; if it had not, the retry would answer access_denied
// on a request_uri its own predecessor had spent.
func TestAuthorize_SilentMint_RetryRedeemsRequestURIOnce(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t)
	session := silentMintSession(t, h)

	const requestURI = "urn:ietf:params:oauth:request_uri:silent-retry"
	values := goodAuthorizeValues()
	snapshot := authorize.RequestSnapshot{
		ClientID:            values.Get("client_id"),
		ResponseType:        values.Get("response_type"),
		RedirectURI:         values.Get("redirect_uri"),
		State:               values.Get("state"),
		Nonce:               values.Get("nonce"),
		CodeChallenge:       values.Get("code_challenge"),
		CodeChallengeMethod: values.Get("code_challenge_method"),
		Scope:               []string{"openid", "profile"},
		CreatedUnix:         h.clock.now.Unix(),
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal PAR snapshot: %v", err)
	}
	if err := h.store.PushedAuthRequests().Save(context.Background(), &store.PushedAuthRequest{
		URI:       requestURI,
		ClientID:  snapshot.ClientID,
		RawParams: raw,
		ExpiresAt: h.clock.now.Add(time.Minute),
		CreatedAt: h.clock.now,
	}); err != nil {
		t.Fatalf("Save PAR: %v", err)
	}
	h.deps.PARs = h.store.PushedAuthRequests()

	fault := &silentConflictFault{err: conflictError(), failures: 1}
	armSilentConflict(t, h, fault)

	rr := doSilentAuthorize(t, h, session.Cookie, url.Values{
		"client_id":   {snapshot.ClientID},
		"request_uri": {requestURI},
	})
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d want 302 body=%s", rr.Code, rr.Body.String())
	}
	location := mustParseLocation(t, rr.Result())
	if got := location.Query().Get("error"); got != "" {
		t.Fatalf("error=%q; the retry must not surface the conflict or a spent request_uri", got)
	}
	if location.Query().Get("code") == "" {
		t.Fatalf("Location=%s carries no code", location.String())
	}
	if got := fault.attempts(); got != 2 {
		t.Fatalf("commit attempts=%d want 2 (the conflict must actually be injected)", got)
	}
	if got := fault.successfulPARConsumes(); got != 1 {
		t.Fatalf("request_uri redeemed %d times, want exactly 1", got)
	}
	rec, err := h.store.PushedAuthRequests().Find(context.Background(), requestURI)
	if err != nil {
		t.Fatalf("Find PAR: %v", err)
	}
	if rec.ConsumedAt == nil {
		t.Fatal("request_uri is still redeemable after a code was issued from it")
	}
}

// TestAuthorize_SilentMint_PersistentConflictStopsAtAttemptBound pins that
// the silent retry is bounded the same way the completion retry is: a grant
// that stays contended past the bound fails the request instead of spinning,
// and leaves no code behind.
func TestAuthorize_SilentMint_PersistentConflictStopsAtAttemptBound(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t)
	session := silentMintSession(t, h)
	fault := &silentConflictFault{err: conflictError(), failures: -1}
	armSilentConflict(t, h, fault)

	rr := doSilentAuthorize(t, h, session.Cookie, goodAuthorizeValues())
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d want 302 body=%s", rr.Code, rr.Body.String())
	}
	if got := mustParseLocation(t, rr.Result()).Query().Get("error"); got != "server_error" {
		t.Fatalf("error=%q want server_error", got)
	}
	if got := fault.attempts(); got != authorizeendpoint.MaxCommitAttempts {
		t.Fatalf("commit attempts=%d want %d", got, authorizeendpoint.MaxCommitAttempts)
	}
	for _, id := range fault.savedCodeIDs() {
		if _, err := h.store.AuthorizationCodes().Find(context.Background(), id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("code %q survived an unresolved conflict: %v", id, err)
		}
	}
}

// TestAuthorize_SilentMint_NonConflictFailureIsNotRetried pins the other
// half of the retry predicate: only a conflict earns another attempt, so a
// backend that is simply failing sees one transaction rather than three.
func TestAuthorize_SilentMint_NonConflictFailureIsNotRetried(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t)
	session := silentMintSession(t, h)
	fault := &silentConflictFault{err: errors.New("injected grant write failure"), failures: -1}
	armSilentConflict(t, h, fault)

	rr := doSilentAuthorize(t, h, session.Cookie, goodAuthorizeValues())
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d want 302 body=%s", rr.Code, rr.Body.String())
	}
	if got := mustParseLocation(t, rr.Result()).Query().Get("error"); got != "server_error" {
		t.Fatalf("error=%q want server_error", got)
	}
	if got := fault.attempts(); got != 1 {
		t.Fatalf("commit attempts=%d want 1 (a non-conflict failure must not be retried)", got)
	}
}
