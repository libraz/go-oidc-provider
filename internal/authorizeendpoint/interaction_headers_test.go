package authorizeendpoint_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// ceremonyHardeningHeaders is the set every dynamic ceremony response
// carries. They are asserted as a set rather than one at a time because
// the defect they guard against is losing the whole group by swapping
// the component that used to stamp them.
var ceremonyHardeningHeaders = map[string]string{
	"X-Frame-Options":        "DENY",
	"X-Content-Type-Options": "nosniff",
	"Referrer-Policy":        "same-origin",
}

// bareDriver renders a prompt with nothing but a Content-Type. It models
// the SPA / framework Drivers the library does not write, which is where
// the guarantee has to hold: before the endpoint owned these headers,
// the only responses that carried them were the ones the bundled HTML
// driver produced, so replacing the driver silently dropped the framing
// and sniffing protections from the page that holds the CSRF token and
// the continuation reference.
type bareDriver struct{}

func (bareDriver) Render(w http.ResponseWriter, _ *http.Request, _ interaction.Prompt) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(`{}`))
	return err
}

func (bareDriver) ParseSubmission(_ *http.Request) (interaction.FormSubmission, error) {
	return interaction.FormSubmission{}, nil
}

// TestInteractionResponse_CarriesHardeningHeadersForEveryDriver drives
// GET /interaction/{uid} through three Drivers with three different
// ideas about response headers and asserts the same set on all of them.
func TestInteractionResponse_CarriesHardeningHeadersForEveryDriver(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		driver interaction.Driver
	}{
		{"bundled html driver", interaction.HTMLDriver{}},
		{"bundled json driver", interaction.JSONDriver{}},
		{"embedder driver that stamps nothing", bareDriver{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, func(d *authorizeendpoint.Deps) { d.Driver = tc.driver })
			start := startInteractionFlow(t, h)
			rr := interactionGET(t, h, start)
			if rr.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			for header, want := range ceremonyHardeningHeaders {
				if got := rr.Header().Get(header); got != want {
					t.Errorf("%s=%q want %q", header, got, want)
				}
			}
		})
	}
}

// TestInteractionResponse_CarriesHardeningHeadersOnRejection extends the
// guarantee to the responses no Driver ever sees. A 404 for an unknown
// uid and a 403 for a rejected origin are still pages a browser renders
// on the OP's origin, and the endpoint stamps them from the same place.
func TestInteractionResponse_CarriesHardeningHeadersOnRejection(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	start := startInteractionFlow(t, h)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		h.interactionPth+"/does-not-exist", http.NoBody)
	req.AddCookie(start.interactionCk)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404", rr.Code)
	}
	for header, want := range ceremonyHardeningHeaders {
		if got := rr.Header().Get(header); got != want {
			t.Errorf("%s=%q want %q", header, got, want)
		}
	}
}
