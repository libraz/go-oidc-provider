package registrationendpoint

import (
	"net/http/httptest"
	"testing"
)

// The registration endpoint's challenge must pass the same sanitiser every
// other WWW-Authenticate value does, realm included.
func TestWriteInvalidToken_SanitisesEveryChallengeValue(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	writeInvalidToken(w, "https://op.example/\"x\\\r\nX-Injected: 1", `token "bad"`)

	got := w.Header().Get("WWW-Authenticate")
	want := `Bearer realm="https://op.example/xX-Injected: 1", error="invalid_token", error_description="token bad"`
	if got != want {
		t.Fatalf("WWW-Authenticate=%q\nwant %q", got, want)
	}
}
