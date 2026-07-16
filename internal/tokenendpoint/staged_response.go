package tokenendpoint

import (
	"bytes"
	"net/http"
)

// stagedResponseWriter is a minimal in-memory ResponseWriter used where a
// handler must commit storage before exposing a success response. It preserves
// normal headers and body semantics without importing net/http/httptest into
// production code.
type stagedResponseWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newStagedResponseWriter() *stagedResponseWriter {
	return &stagedResponseWriter{header: make(http.Header)}
}

func (w *stagedResponseWriter) Header() http.Header { return w.header }

func (w *stagedResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *stagedResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}

func (w *stagedResponseWriter) copyTo(dst http.ResponseWriter) {
	for key, values := range w.header {
		dst.Header()[key] = append([]string(nil), values...)
	}
	status := w.status
	if status == 0 {
		status = http.StatusInternalServerError
	}
	dst.WriteHeader(status)
	_, _ = dst.Write(w.body.Bytes())
}
