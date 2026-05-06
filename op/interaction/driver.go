package interaction

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// maxSubmissionBytes caps the body size [JSONDriver.ParseSubmission]
// reads. Submissions carry [FormSubmission] only; a few KiB is far
// above any legitimate payload while bounding memory use against
// pathological inputs (gosec G120).
const maxSubmissionBytes = 32 * 1024

// Driver is the contract a caller implements to plug a UI into the
// [op.Provider]. The new shape is intentionally thin: every protocol-visible decision
// — factor sequencing, captcha gating, risk routing, prompt
// validation — is the orchestrator's. The Driver only renders the
// orchestrator's chosen [Prompt] for the SPA and parses the SPA's
// reply back into a [FormSubmission].
// Implementations MUST be safe for concurrent use; the library calls
// every method from request-scoped goroutines.
type Driver interface {
	// Render writes the response for prompt to w. The Driver picks
	// the content type (JSON for SPA, HTML for SSR) and sets the
	// matching Content-Type header before any bytes are written.
	// The orchestrator has already populated [Prompt.StateRef]
	// with a fresh continuation token by the time Render runs;
	// implementations MUST echo it back to the SPA so the next
	// submission round-trips correctly.
	Render(w http.ResponseWriter, r *http.Request, prompt Prompt) error

	// ParseSubmission reads the SPA's reply from r and returns the
	// resulting [FormSubmission]. The Driver chooses the wire
	// format; the orchestrator validates the returned values
	// against the active [Prompt.Inputs] before dispatching to
	// the [op.Authenticator]. The function MUST NOT consume more
	// than a few KiB from r.Body.
	ParseSubmission(r *http.Request) (FormSubmission, error)
}

// JSONDriver is the default [Driver] implementation. It speaks JSON
// over HTTP: [JSONDriver.Render] writes the [Prompt] as
// application/json and [JSONDriver.ParseSubmission] decodes a
// [FormSubmission] from the request body. Embedders that ship a SPA
// can use it as-is; SSR or framework-specific Drivers replace it.
// JSONDriver is safe for concurrent use; it carries no state.
type JSONDriver struct{}

// Compile-time confirmation that JSONDriver satisfies Driver.
var _ Driver = JSONDriver{}

// ErrSubmissionMalformed is returned by [JSONDriver.ParseSubmission]
// when the body cannot be decoded into a [FormSubmission]. The error
// is intentionally opaque: the orchestrator translates it to a 400 /
// 403 without echoing the parse error back to the SPA, so a
// malicious caller cannot probe the format through error messages.
var ErrSubmissionMalformed = errors.New("interaction: submission malformed")

// Render implements [Driver]. The function writes the Prompt as
// JSON and stamps Content-Type before the first byte; callers MUST
// NOT have written headers themselves.
func (JSONDriver) Render(w http.ResponseWriter, _ *http.Request, prompt Prompt) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(prompt); err != nil {
		return fmt.Errorf("interaction: render prompt: %w", err)
	}
	return nil
}

// ParseSubmission implements [Driver]. It reads at most
// [maxSubmissionBytes] from r.Body, decodes the [FormSubmission]
// envelope, and returns the result. Unknown fields produce
// [ErrSubmissionMalformed].
func (JSONDriver) ParseSubmission(r *http.Request) (FormSubmission, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, maxSubmissionBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var body FormSubmission
	if err := dec.Decode(&body); err != nil {
		if errors.Is(err, io.EOF) {
			return FormSubmission{}, ErrSubmissionMalformed
		}
		return FormSubmission{}, fmt.Errorf("%w: %w", ErrSubmissionMalformed, err)
	}
	// Reject any trailing JSON document. Multiple objects in one
	// body is a parser-confusion vector — a reverse proxy / WAF /
	// audit sink that scans the full body sees a different shape
	// than the OP consumed. Mirrors the guard applied in
	// [httpx.DecodeJSON] and the DCR metadata parser.
	if dec.More() {
		return FormSubmission{}, ErrSubmissionMalformed
	}
	return body, nil
}
