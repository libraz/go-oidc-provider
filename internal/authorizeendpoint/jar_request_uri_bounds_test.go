//nolint:testpackage // drives fetchJARRequestURI with a narrowed load gate.
package authorizeendpoint

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/remotecache"
)

// TestFetchJARRequestURI_LoadsAreBoundedByTheSharedGate pins that a
// request_uri fetch holds a slot of the URL-load gate the JWKS fetcher
// also draws from: with every slot of the gate taken, a further fetch is
// refused as a transient server_error without opening a socket.
func TestFetchJARRequestURI_LoadsAreBoundedByTheSharedGate(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	entered := make(chan struct{}, 1)
	unblock := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		entered <- struct{}{}
		<-unblock
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte("eyJhbGciOiJSUzI1NiJ9.PAYLOAD.SIGNATURE"))
	}))
	defer srv.Close()

	deps := jarFetchDeps(true)
	// A one-slot group stands in for a saturated process: the gate's
	// behaviour at its limit does not depend on the limit's size.
	deps.jarLoads = remotecache.SharedLoadGate(1)

	first := srv.URL + "/held"
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rec := httptest.NewRecorder()
		if _, ok := fetchJARRequestURI(rec, jarFetchRequest(), deps, fakeClient(first), first, ""); !ok {
			t.Errorf("held fetch failed: status=%d body=%q", rec.Code, rec.Body.String())
		}
	}()
	<-entered

	second := srv.URL + "/refused"
	rec := httptest.NewRecorder()
	if _, ok := fetchJARRequestURI(rec, jarFetchRequest(), deps, fakeClient(second), second, ""); ok {
		t.Fatal("fetch beyond the gate's slots succeeded")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status=%d want 503", rec.Code)
	}
	if code, _ := decodeWireError(t, rec); code != errServerError {
		t.Errorf("error=%q want %s", code, errServerError)
	}
	close(unblock)
	wg.Wait()
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hits=%d want 1: the refused fetch must not reach the network", got)
	}

	// Capacity pressure is not remembered: once the slot is free the same
	// URI is fetched normally.
	rec = httptest.NewRecorder()
	if _, ok := fetchJARRequestURI(rec, jarFetchRequest(), deps, fakeClient(second), second, ""); !ok {
		t.Fatalf("fetch after release failed: status=%d body=%q", rec.Code, rec.Body.String())
	}
}

// TestFetchJARRequestURI_FailureIsNegativeCachedSuccessIsNot pins the
// cache semantics a request object needs: a failing URI is fetched once
// per negative window however many requests name it, while a working URI
// is fetched on every use because a request object must not be replayed
// from a cache.
func TestFetchJARRequestURI_FailureIsNegativeCachedSuccessIsNot(t *testing.T) {
	t.Parallel()

	var failing, working atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/failing" {
			failing.Add(1)
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		working.Add(1)
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte("eyJhbGciOiJSUzI1NiJ9.PAYLOAD.SIGNATURE"))
	}))
	defer srv.Close()

	deps := jarFetchDeps(true)
	failingURI := srv.URL + "/failing"
	descriptions := make([]string, 0, 3)
	for range 3 {
		rec := httptest.NewRecorder()
		if _, ok := fetchJARRequestURI(rec, jarFetchRequest(), deps, fakeClient(failingURI), failingURI, ""); ok {
			t.Fatal("failing request_uri was accepted")
		}
		code, desc := decodeWireError(t, rec)
		if code != errInvalidRequestURI {
			t.Fatalf("error=%q want %s", code, errInvalidRequestURI)
		}
		descriptions = append(descriptions, desc)
	}
	if got := failing.Load(); got != 1 {
		t.Errorf("failing upstream hits=%d want 1 inside the negative window", got)
	}
	if descriptions[0] != descriptions[1] || descriptions[1] != descriptions[2] {
		t.Errorf("cached failure changed its description: %q", descriptions)
	}

	workingURI := srv.URL + "/working"
	for range 2 {
		rec := httptest.NewRecorder()
		if _, ok := fetchJARRequestURI(rec, jarFetchRequest(), deps, fakeClient(workingURI), workingURI, ""); !ok {
			t.Fatalf("working fetch failed: status=%d body=%q", rec.Code, rec.Body.String())
		}
	}
	if got := working.Load(); got != 2 {
		t.Errorf("working upstream hits=%d want 2: a request object must be fetched on every use", got)
	}
}
