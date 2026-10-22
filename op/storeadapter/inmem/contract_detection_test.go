package inmem_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// The tests in this file check the contract harness rather than the
// adapter: each wraps the reference store so that one operation reads,
// decides in application code and writes back, and asserts that the
// harness case written for that operation fails against it. A case that
// a check-then-act backend passes is a case that cannot see the defect it
// exists for.
//
// A failing *testing.T cannot be observed from the test that owns it, so
// each check re-runs this test binary filtered to the one case and
// expects the child to fail on it.

// detectionChildEnv marks the re-executed test binary that runs the
// harness against the broken backend.
const detectionChildEnv = "OIDC_CONTRACT_DETECTION_CHILD"

const (
	// raceWindow is how long a broken operation waits between its read
	// and its write: a network round trip, widened so every racer has
	// read before the first one writes.
	raceWindow = 20 * time.Millisecond
	// poolDial and poolRTT shape [lazyPool]: a dial costs far more than
	// the operation it precedes, as a TCP or TLS handshake does.
	poolDial = 50 * time.Millisecond
	poolRTT  = time.Millisecond
)

func TestContractDetectsNonAtomicBackends(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// failing is the path, under the entry point run invokes, of the
		// case the broken backend must fail.
		failing string
		run     func(t *testing.T)
	}{
		{
			name:    "AuthorizationCodeConsumeBehindLazyPool",
			failing: "Concurrency/AuthorizationCodeConsumeHasOneWinner",
			run: func(t *testing.T) {
				contract.Run(t, brokenFactory(func(s *overriddenStore) {
					s.codes = checkThenConsumeCodes{AuthorizationCodeStore: s.Store.AuthorizationCodes(), pool: &lazyPool{}}
				}))
			},
		},
		{
			name:    "RefreshRotationSave",
			failing: "Concurrency/RefreshRotationRacingRevokeChainLeavesNoLiveDescendant",
			run: func(t *testing.T) {
				contract.Run(t, brokenFactory(func(s *overriddenStore) {
					s.refreshes = checkThenInsertRefreshes{RefreshTokenStore: s.Store.RefreshTokens()}
				}))
			},
		},
		{
			name:    "DeviceCodeUserCodeSave",
			failing: "Concurrency/DeviceCodeSameUserCodeSaveHasOneWinner",
			run:     runWithBrokenDeviceCodes,
		},
		{
			name:    "DeviceCodeCounters",
			failing: "DeviceCodeStore/ConcurrentCountersRecordEveryIncrement",
			run:     runWithBrokenDeviceCodes,
		},
		{
			name:    "DeviceCodeStrikesByUserCode",
			failing: "DeviceCodeStore/ConcurrentUserCodeStrikesByUserCodeRecordEveryIncrement",
			run:     runWithBrokenDeviceCodes,
		},
		{
			name:    "CIBAPollViolations",
			failing: "CIBARequestStore/ConcurrentPollViolationsRecordEveryIncrement",
			run: func(t *testing.T) {
				contract.Run(t, brokenFactory(func(s *overriddenStore) {
					s.ciba = readModifyWriteCIBA{CIBARequestStore: s.Store.CIBARequests()}
				}))
			},
		},
		{
			name:    "TOTPAccept",
			failing: "ConcurrentAcceptHasOneWinner",
			run: func(t *testing.T) {
				contract.RunTOTPs(t, func(*testing.T) contract.TOTPBackend {
					return contract.TOTPBackend{Store: checkThenPutTOTPs{TOTPStore: inmem.New().TOTPs()}}
				})
			},
		},
		{
			name:    "PasskeyPut",
			failing: "ConcurrentCrossSubjectPutHasOneOwner",
			run:     runWithBrokenPasskeys,
		},
		{
			name:    "PasskeyUpdateAssertion",
			failing: "ConcurrentUpdateAssertionKeepsHighestSignCount",
			run:     runWithBrokenPasskeys,
		},
	}

	child := os.Getenv(detectionChildEnv) != ""
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if child {
				tc.run(t)
				return
			}
			assertChildFails(t, tc.name, tc.failing)
		})
	}
}

// assertChildFails re-runs this test binary filtered to the named
// detection case and the harness case beneath it, and fails unless that
// harness case is reported failed.
func assertChildFails(t *testing.T, name, failing string) {
	t.Helper()
	path := "TestContractDetectsNonAtomicBackends/" + name + "/" + failing
	pattern := "^" + strings.Join(strings.Split(path, "/"), "$/^") + "$"

	//nolint:gosec // re-executes this test binary; the arguments are fixed case names.
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run="+pattern, "-test.count=1")
	cmd.Env = append(os.Environ(), detectionChildEnv+"=1")
	out, err := cmd.CombinedOutput()

	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("the harness passed a backend that is not atomic where %s races it (err=%v):\n%s",
			failing, err, out)
	}
	if !strings.Contains(string(out), "--- FAIL: "+path+" (") {
		t.Fatalf("the child run failed, but not on %s:\n%s", path, out)
	}
}

func runWithBrokenDeviceCodes(t *testing.T) {
	contract.Run(t, brokenFactory(func(s *overriddenStore) {
		s.deviceCodes = checkThenWriteDeviceCodes{DeviceCodeStore: s.Store.DeviceCodes()}
	}))
}

func runWithBrokenPasskeys(t *testing.T) {
	contract.RunPasskeys(t, func(*testing.T) store.PasskeyStore {
		return checkThenPutPasskeys{PasskeyStore: inmem.New().Passkeys()}
	})
}

// brokenFactory is [newFactory] with the store handed to override before
// the harness sees it.
func brokenFactory(override func(*overriddenStore)) contract.Factory {
	base := newFactory(contract.Reference)
	return func(t *testing.T) contract.Backend {
		t.Helper()
		b := base(t)
		s := &overriddenStore{Store: b.Store}
		override(s)
		b.Store = s
		return b
	}
}

// overriddenStore serves the substores set on it in place of the ones
// the embedded store provides.
type overriddenStore struct {
	store.Store
	codes       store.AuthorizationCodeStore
	refreshes   store.RefreshTokenStore
	deviceCodes store.DeviceCodeStore
	ciba        store.CIBARequestStore
}

func (s *overriddenStore) AuthorizationCodes() store.AuthorizationCodeStore {
	if s.codes != nil {
		return s.codes
	}
	return s.Store.AuthorizationCodes()
}

func (s *overriddenStore) RefreshTokens() store.RefreshTokenStore {
	if s.refreshes != nil {
		return s.refreshes
	}
	return s.Store.RefreshTokens()
}

func (s *overriddenStore) DeviceCodes() store.DeviceCodeStore {
	if s.deviceCodes != nil {
		return s.deviceCodes
	}
	return s.Store.DeviceCodes()
}

func (s *overriddenStore) CIBARequests() store.CIBARequestStore {
	if s.ciba != nil {
		return s.ciba
	}
	return s.Store.CIBARequests()
}

// lazyPool models a connection pool that dials on demand: an operation
// that finds no idle connection pays [poolDial] first, and every
// operation holds its connection for at least [poolRTT]. Without a
// warm-up, the first racer gets the one connection a preceding write
// left idle and finishes before any other racer has dialled.
type lazyPool struct {
	mu   sync.Mutex
	idle int
}

func (p *lazyPool) do(fn func()) {
	p.mu.Lock()
	if p.idle > 0 {
		p.idle--
		p.mu.Unlock()
	} else {
		p.mu.Unlock()
		time.Sleep(poolDial)
	}
	time.Sleep(poolRTT)
	fn()
	p.mu.Lock()
	p.idle++
	p.mu.Unlock()
}

// checkThenConsumeCodes redeems a code with a SELECT followed by an
// unconditional UPDATE, behind a [lazyPool].
type checkThenConsumeCodes struct {
	store.AuthorizationCodeStore
	pool *lazyPool
}

func (c checkThenConsumeCodes) Save(ctx context.Context, code *store.AuthorizationCode) (err error) {
	c.pool.do(func() { err = c.AuthorizationCodeStore.Save(ctx, code) })
	return err
}

func (c checkThenConsumeCodes) Find(ctx context.Context, id string) (got *store.AuthorizationCode, err error) {
	c.pool.do(func() { got, err = c.AuthorizationCodeStore.Find(ctx, id) })
	return got, err
}

func (c checkThenConsumeCodes) Consume(ctx context.Context, id string) (got *store.AuthorizationCode, err error) {
	c.pool.do(func() {
		got, err = c.AuthorizationCodeStore.Find(ctx, id)
		if err != nil {
			return
		}
		if got.ConsumedAt != nil {
			err = store.ErrAlreadyConsumed
			return
		}
		time.Sleep(raceWindow)
		// The UPDATE does not re-check: a row already consumed is written again.
		if _, cerr := c.AuthorizationCodeStore.Consume(ctx, id); cerr != nil && !errors.Is(cerr, store.ErrAlreadyConsumed) {
			err = cerr
		}
	})
	return got, err
}

// checkThenInsertRefreshes checks a rotation's parent and then inserts
// the successor without re-checking it.
type checkThenInsertRefreshes struct {
	store.RefreshTokenStore
}

func (r checkThenInsertRefreshes) Save(ctx context.Context, token *store.RefreshToken) error {
	if token.ParentID == nil {
		return r.RefreshTokenStore.Save(ctx, token)
	}
	if parent, err := r.Find(ctx, *token.ParentID); err == nil && parent.Revoked {
		return store.ErrAlreadyConsumed
	}
	time.Sleep(raceWindow)
	// The reference Save re-checks the parent itself; dropping the link
	// stands in for an insert that does not.
	detached := *token
	detached.ParentID = nil
	return r.RefreshTokenStore.Save(ctx, &detached)
}

// RevokeChain lands inside the window between Save's check and its
// insert, as a cascade that takes longer than the rotation's read does.
func (r checkThenInsertRefreshes) RevokeChain(ctx context.Context, rootID string) error {
	time.Sleep(raceWindow / 2)
	return r.RefreshTokenStore.RevokeChain(ctx, rootID)
}

// checkThenWriteDeviceCodes looks a user_code up before inserting it and
// keeps both brute-force counters as read-modify-write.
type checkThenWriteDeviceCodes struct {
	store.DeviceCodeStore
}

func (d checkThenWriteDeviceCodes) Save(ctx context.Context, code *store.DeviceCode) error {
	if _, err := d.FindByUserCode(ctx, code.UserCode); err == nil {
		return store.ErrAlreadyExists
	}
	time.Sleep(raceWindow)
	err := d.DeviceCodeStore.Save(ctx, code)
	if errors.Is(err, store.ErrAlreadyExists) {
		// Stands in for an insert into a table without the unique
		// constraint: the duplicate lands and the caller is told so.
		return nil
	}
	return err
}

func (d checkThenWriteDeviceCodes) IncrementUserCodeStrike(ctx context.Context, deviceCode string) (uint8, error) {
	read := func() (uint8, error) {
		rec, err := d.FindByDeviceCode(ctx, deviceCode)
		if err != nil {
			return 0, err
		}
		return rec.UserCodeStrikes, nil
	}
	return readModifyWrite(read, func() error {
		_, err := d.DeviceCodeStore.IncrementUserCodeStrike(ctx, deviceCode)
		return err
	})
}

func (d checkThenWriteDeviceCodes) IncrementUserCodeStrikeByUserCode(ctx context.Context, userCode string) (uint8, error) {
	read := func() (uint8, error) {
		rec, err := d.FindByUserCode(ctx, userCode)
		if err != nil {
			return 0, err
		}
		return rec.UserCodeStrikes, nil
	}
	return readModifyWrite(read, func() error {
		_, err := d.DeviceCodeStore.IncrementUserCodeStrikeByUserCode(ctx, userCode)
		return err
	})
}

func (d checkThenWriteDeviceCodes) IncrementPollViolation(ctx context.Context, deviceCode string) (uint8, error) {
	read := func() (uint8, error) {
		rec, err := d.FindByDeviceCode(ctx, deviceCode)
		if err != nil {
			return 0, err
		}
		return rec.PollViolations, nil
	}
	return readModifyWrite(read, func() error {
		_, err := d.DeviceCodeStore.IncrementPollViolation(ctx, deviceCode)
		return err
	})
}

// readModifyWriteCIBA keeps the poll-violation counter as
// read-modify-write.
type readModifyWriteCIBA struct {
	store.CIBARequestStore
}

func (c readModifyWriteCIBA) IncrementPollViolation(ctx context.Context, authReqID string) (uint8, error) {
	read := func() (uint8, error) {
		rec, err := c.FindByAuthReqID(ctx, authReqID)
		if err != nil {
			return 0, err
		}
		return rec.PollViolations, nil
	}
	return readModifyWrite(read, func() error {
		_, err := c.CIBARequestStore.IncrementPollViolation(ctx, authReqID)
		return err
	})
}

// readModifyWrite reads a counter, waits [raceWindow], and writes back
// the value it read plus one. The reference store exposes only its own
// atomic increment, so the write raises the counter to that value and
// leaves a higher one alone: every update another racer made in the
// window is lost.
func readModifyWrite(read func() (uint8, error), increment func() error) (uint8, error) {
	v, err := read()
	if err != nil {
		return 0, err
	}
	target := v + 1
	time.Sleep(raceWindow)
	for {
		current, err := read()
		if err != nil {
			return 0, err
		}
		if current >= target {
			return target, nil
		}
		if err := increment(); err != nil {
			return 0, err
		}
	}
}

// checkThenPutTOTPs accepts a step by reading the stored one, comparing,
// and replacing the record.
type checkThenPutTOTPs struct {
	store.TOTPStore
}

func (s checkThenPutTOTPs) Accept(ctx context.Context, r *store.TOTPRecord) error {
	current, err := s.Get(ctx, r.Subject)
	if err != nil {
		return err
	}
	if current.LastAcceptedStep >= r.LastAcceptedStep {
		return store.ErrAlreadyConsumed
	}
	time.Sleep(raceWindow)
	return s.Put(ctx, r)
}

// checkThenPutPasskeys checks a credential's owner before writing it,
// and applies an assertion by reading, deciding, and writing the record
// back.
type checkThenPutPasskeys struct {
	store.PasskeyStore
}

func (s checkThenPutPasskeys) Put(ctx context.Context, r *store.PasskeyRecord) error {
	if current, err := s.Get(ctx, r.CredentialID); err == nil && current.Subject != r.Subject {
		return store.ErrAlreadyExists
	}
	time.Sleep(raceWindow)
	return s.overwrite(ctx, r)
}

func (s checkThenPutPasskeys) UpdateAssertion(
	ctx context.Context,
	credentialID []byte,
	update store.PasskeyAssertionUpdate,
) (*store.PasskeyRecord, error) {
	current, err := s.Get(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	next := *current
	if update.SignCount > current.SignCount {
		next.SignCount = update.SignCount
		next.UserPresent = update.UserPresent
		next.UserVerified = update.UserVerified
		next.BackupState = update.BackupState
	}
	next.CloneWarning = current.CloneWarning || update.CloneWarning
	time.Sleep(raceWindow)
	if err := s.overwrite(ctx, &next); err != nil {
		return nil, err
	}
	return &next, nil
}

// overwrite replaces whatever is stored under r.CredentialID. The
// reference Put refuses a cross-subject write itself, so the record is
// removed first and the pair retried until the write lands.
func (s checkThenPutPasskeys) overwrite(ctx context.Context, r *store.PasskeyRecord) error {
	for {
		_ = s.Delete(ctx, r.CredentialID)
		err := s.PasskeyStore.Put(ctx, r)
		if !errors.Is(err, store.ErrAlreadyExists) {
			return err
		}
	}
}
