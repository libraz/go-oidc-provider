package inmem

import "math"

// maxCounter is the ceiling of the uint8 abuse counters (user-code
// strikes, poll violations). The brute-force and poll-abuse gates trip
// well before it, so saturating here only guards against overflow.
const maxCounter = math.MaxUint8

// saturatingIncrement adds one to *c unless it already sits at
// [maxCounter], and returns the resulting value.
func saturatingIncrement(c *uint8) uint8 {
	if *c < maxCounter {
		*c++
	}
	return *c
}

// incrementCounter bumps the counter that counterOf selects on the record
// transition resolves, and returns its new value. transition applies the
// mutation under the substore's lock and reports a missing or expired
// record.
func incrementCounter[R any](
	transition func(mutate func(*R) error) error,
	counterOf func(*R) *uint8,
) (uint8, error) {
	var n uint8
	err := transition(func(rec *R) error {
		n = saturatingIncrement(counterOf(rec))
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}
