package remotecache

import (
	"context"
	"errors"
	"sync"
)

// DefaultMaxInflight bounds the number of distinct remote URL loads that may be
// in flight across every client-controlled URL resolver in this process. The
// gate fails closed when saturated; callers can retry without turning a burst
// of client-supplied URLs into an unbounded socket/goroutine fanout.
const DefaultMaxInflight = 64

// ErrOverloaded identifies a refusal caused by the in-flight URL-load bound.
// It is local capacity pressure, not an upstream failure, so callers must not
// negative-cache it.
var ErrOverloaded = errors.New("remotecache: URL-load capacity exhausted")

// processLoadSlots is the process-wide hard ceiling every [LoadGate] draws
// from. The per-limit groups provide tighter local budgets while this channel
// keeps independently configured resolvers from exceeding the safe process
// default in aggregate.
//
//nolint:gochecknoglobals // one process-wide capacity gate is the contract.
var (
	processLoadSlots = make(chan struct{}, DefaultMaxInflight)
	loadGroupsMu     sync.Mutex
	loadGroups       = map[int]chan struct{}{}
)

// LoadGate is a local in-flight budget inside the process-wide ceiling. The
// zero value is not usable; obtain one from [SharedLoadGate].
type LoadGate struct {
	group chan struct{}
}

// SharedLoadGate returns the gate for limit concurrent loads. Gates asked for
// with the same limit share one budget. A non-positive limit, or one above
// [DefaultMaxInflight], selects [DefaultMaxInflight].
func SharedLoadGate(limit int) LoadGate {
	if limit <= 0 || limit > DefaultMaxInflight {
		limit = DefaultMaxInflight
	}
	loadGroupsMu.Lock()
	defer loadGroupsMu.Unlock()
	group := loadGroups[limit]
	if group == nil {
		group = make(chan struct{}, limit)
		loadGroups[limit] = group
	}
	return LoadGate{group: group}
}

// Acquire takes one slot from both the process-wide ceiling and g's group. It
// never blocks: when either is saturated it returns [ErrOverloaded] rather than
// queuing goroutines behind a semaphore. The release function returns both
// slots and must be called exactly once.
func (g LoadGate) Acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case processLoadSlots <- struct{}{}:
	default:
		return nil, ErrOverloaded
	}
	select {
	case g.group <- struct{}{}:
		return func() {
			<-g.group
			<-processLoadSlots
		}, nil
	default:
		<-processLoadSlots
		return nil, ErrOverloaded
	}
}
