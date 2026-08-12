package authorizeendpoint_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// conflictError models what a grant-versioning backend surfaces when a
// second authorization for the same (subject, client) amended the grant
// between this transaction's read and its commit: a backend-worded error
// that wraps [store.ErrConflict] rather than being it, so a retry loop
// comparing with == would never fire.
func conflictError() error {
	return fmt.Errorf("injected grant amendment conflict: %w", store.ErrConflict)
}

// commitConflictFault fails the completion transaction at its commit
// boundary and records what each attempt tried to write. It is separate
// from completionFault because that harness arms a single one-shot fault
// per boundary, whereas the retry bound can only be observed by a fault
// that decides per attempt whether to keep failing.
type commitConflictFault struct {
	// err is returned in place of a commit while the fault is active.
	err error
	// failures caps how many leading commits fail; a negative value
	// fails every commit.
	failures int

	commits atomic.Int32

	mu    sync.Mutex
	saved []string
}

// nextCommitFails records one commit attempt and reports whether the
// fault swallows it.
func (f *commitConflictFault) nextCommitFails() bool {
	attempt := int(f.commits.Add(1))
	return f.failures < 0 || attempt <= f.failures
}

// commitAttempts reports how many times the endpoint ran the completion
// transaction through to its commit.
func (f *commitConflictFault) commitAttempts() int {
	return int(f.commits.Load())
}

func (f *commitConflictFault) recordSavedCode(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saved = append(f.saved, id)
}

// savedCodeIDs returns the distinct authorization-code identifiers every
// attempt tried to persist. Retries reuse the stable completion code id,
// so a run that minted a second code shows up as a second entry here even
// though the losing attempt's write was rolled back.
func (f *commitConflictFault) savedCodeIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := slices.Clone(f.saved)
	slices.Sort(ids)
	return slices.Compact(ids)
}

type commitConflictTransactional struct {
	store.Transactional
	fault *commitConflictFault
}

func (s commitConflictTransactional) BeginTx(ctx context.Context) (store.Tx, error) {
	tx, err := s.Transactional.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	return commitConflictTx{Tx: tx, fault: s.fault}, nil
}

type commitConflictTx struct {
	store.Tx
	fault *commitConflictFault
}

func (tx commitConflictTx) AuthorizationCodes() store.AuthorizationCodeStore {
	return commitConflictCodeStore{
		AuthorizationCodeStore: tx.Tx.AuthorizationCodes(),
		fault:                  tx.fault,
	}
}

func (tx commitConflictTx) Commit() error {
	if tx.fault.nextCommitFails() {
		return tx.fault.err
	}
	return tx.Tx.Commit()
}

type commitConflictCodeStore struct {
	store.AuthorizationCodeStore
	fault *commitConflictFault
}

func (s commitConflictCodeStore) Save(ctx context.Context, code *store.AuthorizationCode) error {
	s.fault.recordSavedCode(code.ID)
	return s.AuthorizationCodeStore.Save(ctx, code)
}

// armCommitConflict installs the fault-injecting transactional store and
// rebuilds the handler so only the terminal POST runs against it.
func armCommitConflict(t *testing.T, h *testHarness, fault *commitConflictFault) {
	t.Helper()
	h.deps.Transactions = commitConflictTransactional{
		Transactional: h.store,
		fault:         fault,
	}
	h.handler = authorizeendpoint.Handler(h.deps)
}

// completionFlow bundles the state the terminal POST needs so a test can
// install its store wrappers between the interaction GET and the
// submission that drives completion.
type completionFlow struct {
	start      interactionStart
	stateRef   string
	csrfCookie *http.Cookie
}

// startCompletionFlow drives GET /authorize and GET /interaction so the
// caller holds a submission-ready flow.
func startCompletionFlow(t *testing.T, h *testHarness) completionFlow {
	t.Helper()
	start := startInteractionFlow(t, h)
	getResp := doInteractionGet(t, h, start)
	defer getResp.Body.Close()
	stateRef, csrfCookie := readPromptStateRef(t, getResp)
	return completionFlow{start: start, stateRef: stateRef, csrfCookie: csrfCookie}
}

// submitCompletion posts the terminal submission that binds the subject
// and drives the durable completion transaction.
func submitCompletion(t *testing.T, h *testHarness, flow completionFlow) *httptest.ResponseRecorder {
	t.Helper()
	return postSubmission(t, h, flow.start, flow.csrfCookie, interaction.FormSubmission{
		StateRef: flow.stateRef,
		Values:   map[string]string{testkit.SubjectFieldName: "user-1"},
	})
}

// codeFromRedirect extracts the authorization code the terminal response
// handed back to the RP.
func codeFromRedirect(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	location, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatalf("Location carries no code: %q", location.String())
	}
	return code
}

// completionCodeShape drops the two identifiers a fresh flow necessarily
// regenerates — both the code id and the grant id derive from the
// per-request interaction id — so codes minted by independent runs can be
// compared field by field.
func completionCodeShape(code *store.AuthorizationCode) store.AuthorizationCode {
	shape := *code
	shape.ID = ""
	shape.GrantID = ""
	return shape
}

// conflictFreeCompletionCode runs the same flow on untouched
// infrastructure and returns the authorization code it produced, giving
// the retry tests a reference for what a completion is supposed to look
// like.
func conflictFreeCompletionCode(t *testing.T) *store.AuthorizationCode {
	t.Helper()
	h := newHarness(t)
	flow := startCompletionFlow(t, h)
	rr := submitCompletion(t, h, flow)
	if rr.Code != http.StatusFound {
		t.Fatalf("conflict-free status=%d body=%s", rr.Code, rr.Body.String())
	}
	code, err := h.store.AuthorizationCodes().Find(context.Background(), codeFromRedirect(t, rr))
	if err != nil {
		t.Fatalf("conflict-free Find authorization code: %v", err)
	}
	return code
}

// TestInteractionCompletion_LostGrantAmendmentConflictStillIssuesCode
// pins that losing one optimistic-lock race on the grant amendment costs
// the user nothing: the request that lost re-runs its transaction and
// still terminates with a redirect carrying an authorization code
// indistinguishable from one an uncontended run produces. Nothing about
// such a request was invalid — a concurrent authorization for the same
// subject and client simply amended the grant first — so surfacing the
// conflict would fail a request that only had to re-read and re-apply.
func TestInteractionCompletion_LostGrantAmendmentConflictStillIssuesCode(t *testing.T) {
	t.Parallel()

	reference := conflictFreeCompletionCode(t)

	h := newHarness(t)
	flow := startCompletionFlow(t, h)
	fault := &commitConflictFault{err: conflictError(), failures: 1}
	armCommitConflict(t, h, fault)

	rr := submitCompletion(t, h, flow)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d want 302 body=%s", rr.Code, rr.Body.String())
	}
	if got := fault.commitAttempts(); got != 2 {
		t.Fatalf("commit attempts=%d want 2 (the conflict must actually be injected)", got)
	}

	codeID := codeFromRedirect(t, rr)
	code, err := h.store.AuthorizationCodes().Find(context.Background(), codeID)
	if err != nil {
		t.Fatalf("Find authorization code: %v", err)
	}
	if code.ID != codeID {
		t.Fatalf("stored code ID=%q want %q", code.ID, codeID)
	}
	if code.ConsumedAt != nil {
		t.Fatalf("code arrives already consumed: %v", code.ConsumedAt)
	}
	if got, want := completionCodeShape(code), completionCodeShape(reference); !reflect.DeepEqual(got, want) {
		t.Fatalf("retried code=%+v want conflict-free shape %+v", got, want)
	}

	grants, err := h.store.Grants().ListBySubject(context.Background(), "user-1")
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

// TestInteractionCompletion_RetriedCompletionMintsSingleCode pins the
// property the stable completion code id exists for: a retried
// transaction re-derives the same identifier instead of minting a second
// code, so a contended authorization leaves exactly one redeemable code
// behind rather than one per attempt.
func TestInteractionCompletion_RetriedCompletionMintsSingleCode(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	flow := startCompletionFlow(t, h)
	fault := &commitConflictFault{err: conflictError(), failures: 1}
	armCommitConflict(t, h, fault)

	rr := submitCompletion(t, h, flow)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d want 302 body=%s", rr.Code, rr.Body.String())
	}
	if got := fault.commitAttempts(); got != 2 {
		t.Fatalf("commit attempts=%d want 2 (the conflict must actually be injected)", got)
	}

	// Every authorization code the endpoint can produce is written
	// through the transaction's code store, so the distinct identifiers
	// offered to it enumerate the codes this flow could have minted.
	ids := fault.savedCodeIDs()
	if len(ids) != 1 {
		t.Fatalf("attempts persisted %d distinct code IDs (%v), want 1", len(ids), ids)
	}
	codeID := codeFromRedirect(t, rr)
	if ids[0] != codeID {
		t.Fatalf("persisted code ID=%q want the redirected code %q", ids[0], codeID)
	}
	if _, err := h.store.AuthorizationCodes().Find(context.Background(), codeID); err != nil {
		t.Fatalf("Find redirected code: %v", err)
	}
}

// TestInteractionCompletion_PersistentConflictStopsAtAttemptBound pins
// that the retry is bounded: a grant that stays contended past the bound
// fails the request instead of spinning, and it does so after exactly
// [authorizeendpoint.MaxCompletionAttempts] transactions. The conflict is
// not observable to the RP — the endpoint answers 500 rather than
// exposing a storage-layer sentinel — and no code is left behind.
func TestInteractionCompletion_PersistentConflictStopsAtAttemptBound(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	flow := startCompletionFlow(t, h)
	fault := &commitConflictFault{err: conflictError(), failures: -1}
	armCommitConflict(t, h, fault)

	rr := submitCompletion(t, h, flow)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s Location=%q",
			rr.Code, rr.Body.String(), rr.Header().Get("Location"))
	}
	if got := fault.commitAttempts(); got != authorizeendpoint.MaxCompletionAttempts {
		t.Fatalf("commit attempts=%d want %d", got, authorizeendpoint.MaxCompletionAttempts)
	}
	for _, id := range fault.savedCodeIDs() {
		if _, err := h.store.AuthorizationCodes().Find(context.Background(), id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("code %q survived an unresolved conflict: %v", id, err)
		}
	}
}

// TestInteractionCompletion_NonConflictCommitFailureIsNotRetried pins the
// other half of the retry predicate: only a conflict earns another
// attempt. An ordinary storage failure is returned on the first one, so
// the bound cannot turn a single fault into three transactions against an
// already-struggling backend.
func TestInteractionCompletion_NonConflictCommitFailureIsNotRetried(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	flow := startCompletionFlow(t, h)
	fault := &commitConflictFault{
		err:      errors.New("injected commit failure"),
		failures: -1,
	}
	armCommitConflict(t, h, fault)

	rr := submitCompletion(t, h, flow)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s Location=%q",
			rr.Code, rr.Body.String(), rr.Header().Get("Location"))
	}
	if got := fault.commitAttempts(); got != 1 {
		t.Fatalf("commit attempts=%d want 1 (a non-conflict failure must not be retried)", got)
	}
}
