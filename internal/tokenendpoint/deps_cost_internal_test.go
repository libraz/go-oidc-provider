package tokenendpoint

import "testing"

// The handler threads [Deps] by value through the whole request. The
// struct is 464 bytes and the authorization_code path copies it seven
// times (eleven on /end_session), which reads like an obvious thing to
// convert to a pointer. It is not worth doing, and these benchmarks are
// here so the next reader can re-derive that in one command rather than
// re-litigating it from the struct size.
//
// Measured on an Apple M5 Max: seven copies cost 55 ns, the pointer
// equivalent 6 ns, so the whole conversion is worth ~49 ns per request.
// A public-client refresh exchange — the cheapest real token request
// this OP serves, no password hashing anywhere in it — costs 98 µs end
// to end (BenchmarkTokenEndpointRefreshPublicClient). The copies are
// 0.05% of that, and runtime.memmove does not appear anywhere in the
// CPU profile of that benchmark: the request is spent in syscalls, the
// scheduler and GC.
//
// The value semantics are also worth something on their own. Every
// callee holds a snapshot it cannot mutate for its caller, across seven
// frames of a security-sensitive path. Trading that for 49 ns would be
// a bad exchange even if the nanoseconds were free.

// depsChainValue recurses n frames deep, copying Deps at every call.
//
//go:noinline
func depsChainValue(d Deps, n int) string {
	if n == 0 {
		return d.Issuer
	}
	return depsChainValue(d, n-1)
}

// depsChainPointer is the same chain with the copy removed.
//
//go:noinline
func depsChainPointer(d *Deps, n int) string {
	if n == 0 {
		return d.Issuer
	}
	return depsChainPointer(d, n-1)
}

// sink defeats dead-store elimination; the chain returns a field so the
// copy cannot be optimised away as unused.
var sink string

func BenchmarkDepsByValue7(b *testing.B) {
	d := Deps{Issuer: "https://op.example.com"}
	b.ResetTimer()
	for range b.N {
		sink = depsChainValue(d, 7)
	}
}

func BenchmarkDepsByPointer7(b *testing.B) {
	d := Deps{Issuer: "https://op.example.com"}
	b.ResetTimer()
	for range b.N {
		sink = depsChainPointer(&d, 7)
	}
}

// BenchmarkDepsByValue11 covers the deepest chain in the library, the
// one /end_session drives.
func BenchmarkDepsByValue11(b *testing.B) {
	d := Deps{Issuer: "https://op.example.com"}
	b.ResetTimer()
	for range b.N {
		sink = depsChainValue(d, 11)
	}
}
