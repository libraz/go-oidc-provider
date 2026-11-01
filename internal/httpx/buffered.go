package httpx

import (
	"bytes"
	"net/http"
)

// BufferedWriter is an in-memory [http.ResponseWriter] for handlers that must
// finish other work before exposing a response. Headers and body are held
// until [BufferedWriter.Commit] copies them to the real writer; it avoids
// importing net/http/httptest into production code.
type BufferedWriter struct {
	header        http.Header
	body          bytes.Buffer
	status        int
	defaultStatus int
}

// NewBufferedWriter returns a writer whose committed status is defaultStatus
// when the handler wrote neither a header nor a body.
func NewBufferedWriter(defaultStatus int) *BufferedWriter {
	return &BufferedWriter{header: make(http.Header), defaultStatus: defaultStatus}
}

// Header returns the buffered header map.
func (w *BufferedWriter) Header() http.Header { return w.header }

// WriteHeader records the first status; later calls are ignored.
func (w *BufferedWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

// Status returns the status the handler wrote, or 0 when it wrote none.
func (w *BufferedWriter) Status() int { return w.status }

// Write appends to the buffered body, implying 200 when no status was set.
func (w *BufferedWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}

// Commit copies the buffered headers, status and body to dst and returns the
// body write error.
func (w *BufferedWriter) Commit(dst http.ResponseWriter) error {
	for key, values := range w.header {
		dst.Header()[key] = append([]string(nil), values...)
	}
	status := w.status
	if status == 0 {
		status = w.defaultStatus
	}
	dst.WriteHeader(status)
	_, err := dst.Write(w.body.Bytes())
	return err
}
