package contract

import (
	"reflect"
	"slices"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// This file derives what the harness is required to drive from the
// interface declarations in
// [github.com/libraz/go-oidc-provider/op/store], instead of from a list
// of cases somebody wrote by hand.
//
// The distinction decides what a green run means. A case table that
// names its own scope answers only for what its author thought of, and
// every gap in it is invisible: the suite passes, the substore nobody
// wrote a case for is simply never driven, and a backend that gets it
// wrong ships. The tables below are checked against the method sets they
// claim to exercise, so widening an interface — another substore
// accessor on [store.Tx], another Consume, another compare-and-swap —
// fails the harness until a case names it.
//
// Three surfaces are derived here:
//
//   - the substore accessors of [store.Tx], which every settled-handle
//     assertion has to cover (see contract_tx.go);
//   - the id-keyed Consume of every substore [store.Store] exposes,
//     which the redemption-state matrix has to cover (contract_consume.go);
//   - the single-winner surface, the methods whose contract is "at most
//     one of several concurrent callers succeeds", which the concurrency
//     group has to cover (contract_concurrency.go).

// allStoreInterfaces is every exported interface the store package
// declares. The single-winner scan walks it, so an interface missing
// from the list would have its conditional writes silently excused.
//
// TestStoreInterfaceRegistryIsComplete parses the package's own
// declarations and fails when this list drifts from them, which is what
// makes a derived surface derived rather than another hand-kept list.
//
//nolint:gochecknoglobals // registry of interface types; declared once and read-only.
var allStoreInterfaces = []reflect.Type{
	typeOf[store.AccessTokenRegistry](),
	typeOf[store.AuthnLockoutStore](),
	typeOf[store.AuthorizationCodeStore](),
	typeOf[store.CIBARequestStore](),
	typeOf[store.ClientRegistry](),
	typeOf[store.ClientStore](),
	typeOf[store.ConsumedJTIStore](),
	typeOf[store.DeviceCodeStore](),
	typeOf[store.EmailOTPStore](),
	typeOf[store.GrantClientLister](),
	typeOf[store.GrantRevocationStore](),
	typeOf[store.GrantStore](),
	typeOf[store.GrantSubjectLister](),
	typeOf[store.InitialAccessTokenStore](),
	typeOf[store.InteractionStore](),
	typeOf[store.InteractionStoreCAS](),
	typeOf[store.MetadataStore](),
	typeOf[store.OpaqueAccessTokenStore](),
	typeOf[store.PasskeyStore](),
	typeOf[store.PushedAuthRequestStore](),
	typeOf[store.RecoveryStore](),
	typeOf[store.RefreshChainResolver](),
	typeOf[store.RefreshRetryResponseStore](),
	typeOf[store.RefreshTokenStore](),
	typeOf[store.RegistrationAccessTokenStore](),
	typeOf[store.RevokeByClient](),
	typeOf[store.SessionStore](),
	typeOf[store.StaticClientReconciler](),
	typeOf[store.Store](),
	typeOf[store.TOTPStore](),
	typeOf[store.Transactional](),
	typeOf[store.Tx](),
	typeOf[store.UserPasswordStore](),
	typeOf[store.UserStore](),
}

// singleWinnerNames are the five spellings the store package uses for a
// write whose effect is conditional on the state the caller read:
// redemption (Consume), replacement (CompareAndSwap), conditional
// removal (DeleteIfUnchanged), first-writer-wins marking (Mark), and a
// counter with a ceiling (IncrementUses).
//
// Every one of them declares, in its own godoc, that concurrent callers
// resolve to a bounded number of winners, and every one of them is
// satisfiable by a read-decide-write implementation that passes the
// sequential cases. Matching by name rather than by an enumerated list
// of methods is what makes a new one arrive with its coverage gap
// visible: the method is in the surface the moment it is declared.
//
//nolint:gochecknoglobals // derived surface vocabulary; declared once and read-only.
var singleWinnerNames = []string{
	"CompareAndSwap",
	"Consume",
	"DeleteIfUnchanged",
	"IncrementUses",
	"Mark",
}

// methodRef names one method of one interface.
type methodRef struct {
	iface  string
	method string
}

func (m methodRef) String() string { return m.iface + "." + m.method }

// typeOf reports the [reflect.Type] of the interface T names. Interface
// types have no value the harness could take the type of directly, so
// the nil-pointer-to-T detour is the idiom.
func typeOf[T any]() reflect.Type { return reflect.TypeOf((*T)(nil)).Elem() }

//nolint:gochecknoglobals // sentinel type used to filter accessor signatures.
var errorType = typeOf[error]()

// accessorMethods reports the substore accessors an aggregate interface
// declares: the methods that take nothing and return a single non-error
// interface value.
//
// The filter is structural rather than an allow-list because an
// allow-list is the thing that drifts. [store.Tx.Commit] and
// [store.Tx.Rollback] take nothing too, but they answer with an error;
// every substore operation takes a context. Nothing else in the package
// has the shape.
func accessorMethods(iface reflect.Type) []string {
	var out []string
	for i := range iface.NumMethod() {
		m := iface.Method(i)
		if m.Type.NumIn() != 0 || m.Type.NumOut() != 1 {
			continue
		}
		ret := m.Type.Out(0)
		if ret.Kind() != reflect.Interface || ret == errorType {
			continue
		}
		out = append(out, m.Name)
	}
	return out
}

// substoreType reports the interface type the named [store.Store]
// accessor returns.
func substoreType(accessor string) reflect.Type {
	m, ok := typeOf[store.Store]().MethodByName(accessor)
	if !ok {
		return nil
	}
	return m.Type.Out(0)
}

// declaresIDKeyedConsume reports whether iface declares the redemption
// shape the single-use matrix drives: Consume(ctx, id) (*T, error).
//
// The record-keyed redemptions elsewhere in the package
// ([store.EmailOTPStore.Consume], [store.RecoveryStore.Consume]) take
// the record the caller already read, so their state is an argument
// rather than something the matrix can arrange by id; they are covered
// by their own substore's suite.
func declaresIDKeyedConsume(iface reflect.Type) bool {
	m, ok := iface.MethodByName("Consume")
	if !ok {
		return false
	}
	sig := m.Type
	if sig.NumIn() != 2 || sig.NumOut() != 2 {
		return false
	}
	return sig.In(1).Kind() == reflect.String &&
		sig.Out(0).Kind() == reflect.Pointer &&
		sig.Out(1) == errorType
}

// idKeyedConsumeAccessors reports the [store.Store] accessors whose
// substore declares an id-keyed Consume, in declaration order.
func idKeyedConsumeAccessors() []string {
	var out []string
	for _, accessor := range accessorMethods(typeOf[store.Store]()) {
		if declaresIDKeyedConsume(substoreType(accessor)) {
			out = append(out, accessor)
		}
	}
	return out
}

// singleWinnerSurface reports every (interface, method) pair in the
// store package whose name is one of [singleWinnerNames].
func singleWinnerSurface() []methodRef {
	var out []methodRef
	for _, iface := range allStoreInterfaces {
		for i := range iface.NumMethod() {
			name := iface.Method(i).Name
			if slices.Contains(singleWinnerNames, name) {
				out = append(out, methodRef{iface: iface.Name(), method: name})
			}
		}
	}
	return out
}

// assertCovers fails when the harness drives no case for something the
// interfaces declare. covered is keyed by whatever want holds, so the
// failure can name the case that is missing rather than a count.
func assertCovers[K comparable](t *testing.T, subject string, want []K, covered map[K]string) {
	t.Helper()
	var missing []K
	for _, w := range want {
		if _, ok := covered[w]; !ok {
			missing = append(missing, w)
		}
	}
	if len(missing) == 0 {
		return
	}
	t.Fatalf("%s: the interfaces declare %v, and the harness drives no case for them. "+
		"A backend that gets one wrong passes the whole suite, so the gap has to be closed in the "+
		"table rather than tolerated here", subject, missing)
}
