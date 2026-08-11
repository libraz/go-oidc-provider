//nolint:testpackage // reads maxConcurrentDerivations to compare the gate against the measured curve.
package argon2id

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

// BenchmarkDerivationConcurrency measures aggregate derivation
// throughput and peak heap as a function of how many derivations run at
// once, at the library's production parameters (m=64 MiB, t=3, p=1).
// It calls [argon2.IDKey] directly rather than [Key] so the curve it
// reports is the ungated one — the evidence the gate's capacity is
// chosen from, which would be circular if the benchmark were itself
// gated.
//
// Measured on an 18-core Apple Silicon host (GOMAXPROCS=18),
// go1.26.5, -benchtime=36x -count=2:
//
//	concurrency   derivations/s     peak heap
//	          1     11.2            129 MiB
//	          2     20.8 – 21.4     257 MiB
//	          4     34.9 – 35.4     513 MiB
//	          8     50.8 – 52.2   1,025 MiB
//	         16     65.7 – 72.7   1,793 – 1,986 MiB
//	         18     75.3 – 78.4   1,858 – 2,050 MiB
//	         36     72.5 – 72.8   2,306 MiB
//
// Throughput rises to GOMAXPROCS and stops. Across every sample taken,
// 36 concurrent derivations served no more than 18 did — the run-to-run
// spread at the top of the curve is wide enough that the apparent
// regression should not be quoted as one, but the ceiling is not in
// doubt. Peak heap, meanwhile, keeps climbing: each in-flight
// derivation holds its own 64 MiB block for its whole duration, and up
// to concurrency 8 the peak tracks that linearly (at twice the naive
// figure, since a finished block stays resident until the collector
// reaches it). Past that the collector intervenes and the process pays
// the same pressure in CPU instead.
//
// So oversubscription buys nothing and costs 64 MiB a caller, which is
// what makes GOMAXPROCS the capacity: it is the smallest bound that
// gives up no throughput. The curve does bend below it — the last nine
// slots add far less than the first nine, because Argon2id is built to
// saturate exactly the memory bandwidth they contend for — but a
// tighter bound would trade real throughput for memory, and that is the
// operator's call to make, not a default to hard-code.
func BenchmarkDerivationConcurrency(b *testing.B) {
	for _, c := range concurrencyLevels() {
		b.Run(fmt.Sprintf("concurrency=%d", c), func(b *testing.B) {
			benchmarkDerivationsAt(b, c, ungatedDerive)
		})
	}
}

// BenchmarkGatedVsUngated fans out past the gate's capacity and reports
// what the gate buys, holding everything else equal. It is the direct
// evidence for the claim [Key] is built on — that peak memory stops
// being a function of how many callers arrive.
//
// Measured on the same host as BenchmarkDerivationConcurrency
// (GOMAXPROCS=18), -count=3:
//
//	                    callers   derivations/s   peak heap
//	without_gate x4          72    61.1 – 94.1    4,610 MiB
//	   with_gate x4          72    62.0 – 69.9    2,562 MiB
//	   with_gate x8         144    51.0 – 62.7    2,306 – 2,498 MiB
//
// Throughput at the top of the curve is noisy enough that the three
// rows cannot be separated — which is the finding. The gate costs
// nothing, because the CPU a queued caller waits for is already busy
// deriving; it reorders the work rather than adding to it. Memory does
// separate. Ungated, the peak is 72 × 64 MiB almost exactly: it is set
// by how many callers arrive, and nothing in the OP bounds that.
// Gated, doubling the callers to 144 moves the peak by nothing at all,
// which is the property being bought.
//
// The residual factor of two between the gated peak and the naive
// 18 × 64 MiB is the collector: a finished derivation's block stays
// resident until it is reached. It appears at every concurrency,
// including 1 (129 MiB for a single 64 MiB derivation), so it is a
// constant of the allocator rather than anything the gate governs.
//
// There is deliberately no ungated x8 row. Running it would commit
// around 9 GiB to make a point the x4 row already makes, and an
// operator who wants that measurement can read it off the slope.
func BenchmarkGatedVsUngated(b *testing.B) {
	maxProcs := runtime.GOMAXPROCS(0)
	b.Run("without_gate_x4", func(b *testing.B) { benchmarkDerivationsAt(b, maxProcs*4, ungatedDerive) })
	b.Run("with_gate_x4", func(b *testing.B) { benchmarkDerivationsAt(b, maxProcs*4, Key) })
	b.Run("with_gate_x8", func(b *testing.B) { benchmarkDerivationsAt(b, maxProcs*8, Key) })
}

// deriveFunc is the derivation under measurement: either [Key] or the
// raw library call it wraps. Both halves of BenchmarkGatedVsUngated run
// the identical harness so the only difference between the two rows is
// the gate.
type deriveFunc func(password, salt []byte, iterations, memory uint32, parallelism uint8, keyLength uint32) []byte

// ungatedDerive is the pre-gate behaviour, kept callable from the
// benchmark so the capacity can be justified against the curve the
// library would have had.
func ungatedDerive(password, salt []byte, iterations, memory uint32, parallelism uint8, keyLength uint32) []byte {
	return argon2.IDKey(password, salt, iterations, memory, parallelism, keyLength)
}

// concurrencyLevels returns the fan-out points the benchmark samples:
// powers of two up to GOMAXPROCS, plus GOMAXPROCS itself and double it.
// Deriving them from the host rather than hard-coding keeps the
// "throughput stops at GOMAXPROCS" claim testable on a machine whose
// core count differs from the one in the doc comment.
func concurrencyLevels() []int {
	maxProcs := runtime.GOMAXPROCS(0)
	levels := []int{1}
	for c := 2; c < maxProcs; c *= 2 {
		levels = append(levels, c)
	}
	return append(levels, maxProcs, maxProcs*2)
}

// benchmarkDerivationsAt runs b.N derivations spread over c goroutines
// and reports throughput plus the peak heap observed while they ran.
//
// ns/op from the framework is wall-clock divided by b.N, which at
// concurrency > 1 is the inverse of throughput rather than the latency
// of one derivation. The explicit derivations/s metric is reported so
// the number does not have to be re-derived by hand, and peak_heap_MiB
// so the memory half of the trade-off is visible in the same row.
func benchmarkDerivationsAt(b *testing.B, c int, derive deriveFunc) {
	salt := make([]byte, 16)
	work := make(chan struct{}, b.N)
	for range b.N {
		work <- struct{}{}
	}
	close(work)

	stop := make(chan struct{})
	peak := sampleHeapPeak(stop)

	var wg sync.WaitGroup
	b.ResetTimer()
	start := time.Now()
	for range c {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range work {
				key := derive([]byte("benchmark-secret"), salt, 3, 64*1024, 1, 32)
				sinkKey.Store(&key)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	b.StopTimer()
	close(stop)

	b.ReportMetric(float64(b.N)/elapsed.Seconds(), "derivations/s")
	b.ReportMetric(float64(peak.Load())/(1024*1024), "peak_heap_MiB")
}

// sampleHeapPeak polls the heap while a benchmark body runs and returns
// the running maximum. [runtime.ReadMemStats] stops the world, so the
// interval is coarse enough not to distort the timing it is measured
// alongside; a derivation takes ~90 ms, so 5 ms samples still catch the
// plateau every in-flight derivation contributes to.
func sampleHeapPeak(stop <-chan struct{}) *atomic.Uint64 {
	peak := new(atomic.Uint64)
	go func() {
		var stats runtime.MemStats
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				runtime.ReadMemStats(&stats)
				for {
					seen := peak.Load()
					if stats.HeapInuse <= seen || peak.CompareAndSwap(seen, stats.HeapInuse) {
						break
					}
				}
			}
		}
	}()
	return peak
}

// sinkKey keeps the derived key reachable so the compiler cannot elide
// the derivation, and — more importantly here — so the 64 MiB scratch
// buffer's lifetime matches production, where the caller holds the
// result while comparing it.
var sinkKey atomic.Pointer[[]byte]
