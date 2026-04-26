package httpx_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/testutil/golden"
)

// TestErrorBody_Golden_Full pins the wire shape of the OAuth 2.0 / OIDC
// error envelope including the optional uri field. RPs build their error
// catalogues against this contract; reordering or renaming a key is a
// breaking change.
func TestErrorBody_Golden_Full(t *testing.T) {
	t.Parallel()

	body := httpx.ErrorBody{
		Error:            "invalid_grant",
		ErrorDescription: "code already consumed",
		ErrorURI:         "https://idp.example.com/oidc/errors/invalid_grant",
	}
	golden.JSON(t, body, "testdata/error_full.golden.json")
}

// TestErrorBody_Golden_Minimal pins the shape of the most common error
// shape: just a code, no description, no URI. The omitempty tags must keep
// optional fields from leaking when unused.
func TestErrorBody_Golden_Minimal(t *testing.T) {
	t.Parallel()

	body := httpx.ErrorBody{Error: "invalid_request"}
	golden.JSON(t, body, "testdata/error_minimal.golden.json")
}

// TestWriteError_Golden_ResponseBytes pins the actual byte stream the OP
// emits — Content-Type, no-store, and the JSON encoding pipeline. Locking
// the byte stream catches drift in indentation, trailing newlines, or the
// charset suffix.
func TestWriteError_Golden_ResponseBytes(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	if err := httpx.WriteError(rec, 400, "invalid_grant", "code already consumed"); err != nil {
		t.Fatalf("WriteError: %v", err)
	}
	res := rec.Result()
	defer res.Body.Close()

	type capture struct {
		Status      int               `json:"status"`
		ContentType string            `json:"content_type"`
		CacheCtrl   string            `json:"cache_control"`
		Body        httpx.ErrorBody   `json:"body"`
		Raw         json.RawMessage   `json:"raw_body"`
		Headers     map[string]string `json:"headers"`
	}
	got := capture{
		Status:      res.StatusCode,
		ContentType: res.Header.Get("Content-Type"),
		CacheCtrl:   res.Header.Get("Cache-Control"),
		Headers:     map[string]string{},
		Raw:         rec.Body.Bytes(),
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got.Body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	golden.JSON(t, got, "testdata/error_response.golden.json")
}
