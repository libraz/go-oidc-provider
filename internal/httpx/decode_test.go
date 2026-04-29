package httpx_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

// newRequestForm builds a POST request carrying the supplied body and
// content type.
func newRequestForm(tb testing.TB, contentType, body string) *http.Request {
	tb.Helper()
	r := httptest.NewRequestWithContext(
		context.Background(), http.MethodPost, "/x",
		io.NopCloser(strings.NewReader(body)),
	)
	r.Header.Set("Content-Type", contentType)
	return r
}

func TestDecodeForm_Parses(t *testing.T) {
	t.Parallel()

	r := newRequestForm(t, "application/x-www-form-urlencoded", "grant_type=authorization_code&code=abc")
	v, err := httpx.DecodeForm(r)
	if err != nil {
		t.Fatalf("DecodeForm: %v", err)
	}
	if v.Get("grant_type") != "authorization_code" {
		t.Errorf("grant_type=%q", v.Get("grant_type"))
	}
	if v.Get("code") != "abc" {
		t.Errorf("code=%q", v.Get("code"))
	}
}

func TestDecodeForm_TolerantOfCharsetParameter(t *testing.T) {
	t.Parallel()

	r := newRequestForm(t,
		"application/x-www-form-urlencoded; charset=utf-8",
		"grant_type=client_credentials",
	)
	if _, err := httpx.DecodeForm(r); err != nil {
		t.Fatalf("DecodeForm rejected charset parameter: %v", err)
	}
}

func TestDecodeForm_RejectsWrongContentType(t *testing.T) {
	t.Parallel()

	r := newRequestForm(t, "application/json", `{"grant_type":"x"}`)
	_, err := httpx.DecodeForm(r)
	if !errors.Is(err, httpx.ErrUnsupportedMediaType) {
		t.Errorf("err=%v want ErrUnsupportedMediaType", err)
	}
}

func TestDecodeForm_RejectsMissingContentType(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequestWithContext(
		context.Background(), http.MethodPost, "/x",
		strings.NewReader("a=1"),
	)
	if _, err := httpx.DecodeForm(r); !errors.Is(err, httpx.ErrUnsupportedMediaType) {
		t.Errorf("err=%v want ErrUnsupportedMediaType", err)
	}
}

func TestDecodeForm_RejectsOversizeBody(t *testing.T) {
	t.Parallel()

	big := bytes.Repeat([]byte("a"), httpx.MaxFormBytes+1)
	r := httptest.NewRequestWithContext(
		context.Background(), http.MethodPost, "/x",
		bytes.NewReader(big),
	)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := httpx.DecodeForm(r); !errors.Is(err, httpx.ErrBodyTooLarge) {
		t.Errorf("err=%v want ErrBodyTooLarge", err)
	}
}

func TestDecodeForm_RejectsMalformedBody(t *testing.T) {
	t.Parallel()

	r := newRequestForm(t, "application/x-www-form-urlencoded", "%ZZ=oops")
	if _, err := httpx.DecodeForm(r); !errors.Is(err, httpx.ErrInvalidBody) {
		t.Errorf("err=%v want ErrInvalidBody", err)
	}
}

type loginPayload struct {
	Type   string `json:"type"`
	Method string `json:"method"`
}

func TestDecodeJSON_Parses(t *testing.T) {
	t.Parallel()

	r := newRequestForm(t, "application/json", `{"type":"password","method":"login"}`)
	var p loginPayload
	if err := httpx.DecodeJSON(r, &p); err != nil {
		t.Fatalf("DecodeJSON: %v", err)
	}
	if p.Type != "password" || p.Method != "login" {
		t.Errorf("p=%+v", p)
	}
}

func TestDecodeJSON_RejectsUnknownFields(t *testing.T) {
	t.Parallel()

	r := newRequestForm(t, "application/json", `{"type":"x","unexpected":1}`)
	var p loginPayload
	if err := httpx.DecodeJSON(r, &p); !errors.Is(err, httpx.ErrInvalidBody) {
		t.Errorf("err=%v want ErrInvalidBody (unknown field)", err)
	}
}

func TestDecodeJSON_RejectsTrailingDocs(t *testing.T) {
	t.Parallel()

	// Two JSON documents in one body — RFC 8259 forbids and parser
	// confusion has been a real exploit class.
	r := newRequestForm(t, "application/json", `{"type":"x"}{"type":"y"}`)
	var p loginPayload
	if err := httpx.DecodeJSON(r, &p); !errors.Is(err, httpx.ErrInvalidBody) {
		t.Errorf("err=%v want ErrInvalidBody (trailing doc)", err)
	}
}

func TestDecodeJSON_RejectsWrongContentType(t *testing.T) {
	t.Parallel()

	r := newRequestForm(t, "text/plain", `{"type":"x"}`)
	var p loginPayload
	if err := httpx.DecodeJSON(r, &p); !errors.Is(err, httpx.ErrUnsupportedMediaType) {
		t.Errorf("err=%v want ErrUnsupportedMediaType", err)
	}
}

func TestDecodeJSON_RejectsOversizeBody(t *testing.T) {
	t.Parallel()

	big := bytes.Repeat([]byte("a"), httpx.MaxJSONBytes+1)
	r := httptest.NewRequestWithContext(
		context.Background(), http.MethodPost, "/x",
		bytes.NewReader(big),
	)
	r.Header.Set("Content-Type", "application/json")
	var p loginPayload
	if err := httpx.DecodeJSON(r, &p); !errors.Is(err, httpx.ErrBodyTooLarge) {
		t.Errorf("err=%v want ErrBodyTooLarge", err)
	}
}

func TestDecodeJSON_RejectsMalformed(t *testing.T) {
	t.Parallel()

	r := newRequestForm(t, "application/json", `{not json}`)
	var p loginPayload
	if err := httpx.DecodeJSON(r, &p); !errors.Is(err, httpx.ErrInvalidBody) {
		t.Errorf("err=%v want ErrInvalidBody", err)
	}
}

// closeTrackingBody wraps an [io.Reader] with a closer that records whether
// Close was invoked. It exists so the test can assert the body was drained
// via [defer body.Close()] inside readBounded.
type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (c *closeTrackingBody) Close() error {
	c.closed = true
	return nil
}

func TestDecodeJSON_ClosesBody(t *testing.T) {
	t.Parallel()

	body := &closeTrackingBody{Reader: strings.NewReader(`{"type":"x","method":"y"}`)}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", http.NoBody)
	r.Header.Set("Content-Type", "application/json")
	r.Body = body

	var p loginPayload
	if err := httpx.DecodeJSON(r, &p); err != nil {
		t.Fatalf("DecodeJSON: %v", err)
	}
	if !body.closed {
		t.Error("body.Close was not invoked")
	}
}

func TestDecodeForm_ClosesBody(t *testing.T) {
	t.Parallel()

	body := &closeTrackingBody{Reader: strings.NewReader("a=1")}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", http.NoBody)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Body = body

	if _, err := httpx.DecodeForm(r); err != nil {
		t.Fatalf("DecodeForm: %v", err)
	}
	if !body.closed {
		t.Error("body.Close was not invoked")
	}
}
