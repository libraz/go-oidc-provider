package op

import (
	"context"
	"encoding"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"sync"

	"github.com/libraz/go-oidc-provider/op/store"
)

// claimKind is the JSON type OpenID Connect Core §5.1 fixes for a
// standard claim.
type claimKind int

const (
	claimString claimKind = iota
	claimBool
	claimNumber
	claimObject
)

//nolint:gochecknoglobals // closed mapping per OpenID Connect Core §5.1; read-only.
var standardClaimKinds = map[string]claimKind{
	"name":                  claimString,
	"given_name":            claimString,
	"family_name":           claimString,
	"middle_name":           claimString,
	"nickname":              claimString,
	"preferred_username":    claimString,
	"profile":               claimString,
	"picture":               claimString,
	"website":               claimString,
	"email":                 claimString,
	"email_verified":        claimBool,
	"gender":                claimString,
	"birthdate":             claimString,
	"zoneinfo":              claimString,
	"locale":                claimString,
	"phone_number":          claimString,
	"phone_number_verified": claimBool,
	"address":               claimObject,
	"updated_at":            claimNumber,
}

// claimTypeGuard is the [store.UserStore] the claim-releasing endpoints
// read through. It drops a standard claim whose Go value does not encode
// as the JSON type §5.1 fixes, and warns once per claim name. Passing the
// value through instead would put, say, email_verified "false" or 0 on
// the wire, which a relying party testing truthiness reads as verified.
//
// Only FindBySubject is consumed on this path, so wrapping cannot hide an
// optional capability of the embedder's store.
type claimTypeGuard struct {
	inner  store.UserStore
	logger *slog.Logger
	warned sync.Map // claim name → struct{}
}

func newClaimTypeGuard(inner store.UserStore, logger *slog.Logger) *claimTypeGuard {
	return &claimTypeGuard{inner: inner, logger: logger}
}

// FindBySubject implements [store.UserStore].
func (g *claimTypeGuard) FindBySubject(ctx context.Context, sub string) (*store.User, error) {
	u, err := g.inner.FindBySubject(ctx, sub)
	if err != nil || u == nil {
		return u, err
	}
	var bad []string
	for name, v := range u.Claims {
		if kind, ok := standardClaimKinds[name]; ok && !claimValueIs(kind, v) {
			bad = append(bad, name)
		}
	}
	if len(bad) == 0 {
		return u, nil
	}
	claims := make(map[string]any, len(u.Claims))
	for k, v := range u.Claims {
		claims[k] = v
	}
	for _, name := range bad {
		g.warnOnce(name, claims[name])
		delete(claims, name)
	}
	out := *u
	out.Claims = claims
	return &out, nil
}

func (g *claimTypeGuard) warnOnce(name string, v any) {
	if g.logger == nil {
		return
	}
	if _, seen := g.warned.LoadOrStore(name, struct{}{}); seen {
		return
	}
	g.logger.Warn(
		"a standard claim from the user store has the wrong JSON type and is left out of the ID Token and /userinfo; "+
			"convert it in FindBySubject (for example a TINYINT email_verified to bool)",
		"claim", name,
		"go_type", fmt.Sprintf("%T", v),
	)
}

// claimValueIs reports whether v encodes as the JSON type kind. Kinds
// are checked rather than concrete types so a named string or a struct
// address is accepted. A nil value encodes as null, which no standard
// claim admits, and a struct with its own marshaller (time.Time) is not
// assumed to encode as an object.
func claimValueIs(kind claimKind, v any) bool {
	if n, ok := v.(json.Number); ok {
		return kind == claimNumber && n != ""
	}
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return false
		}
		rv = rv.Elem()
	}
	switch kind {
	case claimString:
		return rv.Kind() == reflect.String
	case claimBool:
		return rv.Kind() == reflect.Bool
	case claimNumber:
		return rv.CanInt() || rv.CanUint() || rv.CanFloat()
	case claimObject:
		if rv.Kind() == reflect.Map {
			return rv.Type().Key().Kind() == reflect.String
		}
		if rv.Kind() != reflect.Struct {
			return false
		}
		switch rv.Interface().(type) {
		case json.Marshaler, encoding.TextMarshaler:
			return false
		}
		return true
	}
	return false
}
