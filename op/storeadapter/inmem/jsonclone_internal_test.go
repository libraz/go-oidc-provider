package inmem

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestCloneJSONValueDeepCopiesFastPath(t *testing.T) {
	t.Parallel()

	src := map[string]any{
		"s":   "x",
		"n":   1.5,
		"num": json.Number("7"),
		"b":   true,
		"nil": nil,
		"obj": map[string]any{"k": []any{"a", map[string]any{"deep": "v"}}},
		"arr": []any{"one", []any{"two"}},
	}
	got := cloneJSONValue(src).(map[string]any)
	if !reflect.DeepEqual(got, src) {
		t.Fatalf("clone differs from source: %v vs %v", got, src)
	}
	got["obj"].(map[string]any)["k"].([]any)[1].(map[string]any)["deep"] = "changed"
	got["obj"].(map[string]any)["new"] = 1
	got["arr"].([]any)[1].([]any)[0] = "changed"
	got["arr"].([]any)[0] = "changed"
	if src["obj"].(map[string]any)["k"].([]any)[1].(map[string]any)["deep"] != "v" ||
		len(src["obj"].(map[string]any)) != 1 ||
		src["arr"].([]any)[1].([]any)[0] != "two" ||
		src["arr"].([]any)[0] != "one" {
		t.Fatalf("mutating the clone reached the source: %v", src)
	}
}

func TestCloneJSONValueDeepCopiesReflectPath(t *testing.T) {
	t.Parallel()

	src := map[string]any{
		"strs":  []string{"a", "b"},
		"typed": map[string][]any{"k": {"v", map[string]any{"deep": "v"}}},
	}
	got := cloneJSONValue(src).(map[string]any)
	if !reflect.DeepEqual(got, src) {
		t.Fatalf("clone differs from source: %v vs %v", got, src)
	}
	got["strs"].([]string)[0] = "changed"
	got["typed"].(map[string][]any)["k"][1].(map[string]any)["deep"] = "changed"
	got["typed"].(map[string][]any)["k"][0] = "changed"
	if src["strs"].([]string)[0] != "a" ||
		src["typed"].(map[string][]any)["k"][0] != "v" ||
		src["typed"].(map[string][]any)["k"][1].(map[string]any)["deep"] != "v" {
		t.Fatalf("mutating the clone reached the source: %v", src)
	}
}

func TestCloneJSONValueKeepsNilAndEmptyShapes(t *testing.T) {
	t.Parallel()

	if got := cloneJSONValue(nil); got != nil {
		t.Errorf("nil: got %v", got)
	}
	if got := cloneJSONValue(map[string]any(nil)); got == nil || got.(map[string]any) != nil {
		t.Errorf("typed nil map: got %#v", got)
	}
	if got := cloneJSONValue([]any(nil)); got == nil || got.([]any) != nil {
		t.Errorf("typed nil slice: got %#v", got)
	}
	if got := cloneJSONValue(map[string]any{}).(map[string]any); got == nil || len(got) != 0 {
		t.Errorf("empty map: got %#v", got)
	}
}

func BenchmarkCloneJSONValue(b *testing.B) {
	src := map[string]any{
		"acr":  "urn:mace:incommon:iap:silver",
		"auth": 1700000000.0,
		"amr":  []any{"pwd", "otp"},
		"addr": map[string]any{"country": "JP", "region": "Tokyo", "geo": []any{35.6, 139.7}},
	}
	b.ReportAllocs()
	for b.Loop() {
		cloneJSONValue(src)
	}
}
