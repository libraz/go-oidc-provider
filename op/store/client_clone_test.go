package store_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// fillClient sets every field of c to a distinct non-zero value.
func fillClient(t *testing.T, c *store.Client) {
	t.Helper()
	v := reflect.ValueOf(c).Elem()
	for i := range v.NumField() {
		f := v.Field(i)
		name := v.Type().Field(i).Name
		switch f.Kind() {
		case reflect.String:
			f.SetString(name + "-v")
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Int64:
			f.SetInt(int64(i) + 7)
		case reflect.Slice:
			switch f.Type().Elem().Kind() {
			case reflect.String:
				f.Set(reflect.ValueOf([]string{name + "-a", name + "-b"}).Convert(f.Type()))
			case reflect.Uint8:
				f.SetBytes([]byte(`{"keys":[]}`))
			default:
				t.Fatalf("field %s: unhandled slice kind", name)
			}
		case reflect.Pointer:
			n := int64(42)
			f.Set(reflect.ValueOf(&n))
		case reflect.Struct:
			if f.Type() != reflect.TypeFor[time.Time]() {
				t.Fatalf("field %s: unhandled struct", name)
			}
			f.Set(reflect.ValueOf(time.Unix(1_700_000_000, 0).UTC()))
		default:
			t.Fatalf("field %s: unhandled kind %s", name, f.Kind())
		}
	}
}

// scribble mutates every field of v in place, reaching through slices and pointers.
func scribble(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		v.SetString(v.String() + "!")
	case reflect.Bool:
		v.SetBool(!v.Bool())
	case reflect.Int64:
		v.SetInt(v.Int() + 1)
	case reflect.Uint8:
		v.SetUint(v.Uint() + 1)
	case reflect.Slice:
		for i := range v.Len() {
			scribble(v.Index(i))
		}
	case reflect.Pointer:
		scribble(v.Elem())
	case reflect.Struct:
		if t, ok := v.Interface().(time.Time); ok {
			v.Set(reflect.ValueOf(t.Add(time.Hour)))
			return
		}
		for i := range v.NumField() {
			scribble(v.Field(i))
		}
	}
}

func TestClientClone_IsDeepCopy(t *testing.T) {
	t.Parallel()

	var orig, pristine store.Client
	fillClient(t, &orig)
	fillClient(t, &pristine)

	clone := orig.Clone()
	if !reflect.DeepEqual(*clone, orig) {
		t.Fatalf("clone differs from original:\n got %+v\nwant %+v", *clone, orig)
	}

	scribble(reflect.ValueOf(clone).Elem())
	if reflect.DeepEqual(*clone, orig) {
		t.Fatal("scribble did not alter the clone")
	}
	if !reflect.DeepEqual(orig, pristine) {
		t.Fatalf("mutating the clone reached the original:\n got %+v\nwant %+v", orig, pristine)
	}
}

func TestClientClone_Nil(t *testing.T) {
	t.Parallel()

	var c *store.Client
	if got := c.Clone(); got != nil {
		t.Fatalf("Clone of nil = %v, want nil", got)
	}
}

func TestClientClone_PreservesNilAndEmpty(t *testing.T) {
	t.Parallel()

	c := &store.Client{ID: "rp", Scopes: []string{}}
	got := c.Clone()
	if got.RedirectURIs != nil || got.JWKs != nil || got.DefaultMaxAge != nil {
		t.Fatalf("nil fields became non-nil: %+v", got)
	}
	if got.Scopes == nil {
		t.Fatal("empty non-nil slice became nil")
	}
}
