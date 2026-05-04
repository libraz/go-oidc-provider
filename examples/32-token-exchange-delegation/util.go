//go:build example

// util.go — shared HTTP plumbing for example
// 32-token-exchange-delegation.
//
// These helpers do not belong to any single role: doGET, decodeJSONBody,
// and findCookie are used by service_a's auth-code flow and could be
// reused by future helpers. They live in their own file so role files
// stay focused on their wire role rather than HTTP plumbing.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// doGET issues a GET against rawURL with ctx propagation. It exists
// so the call sites stay short while still routing every request
// through a context-aware helper.
func doGET(ctx context.Context, client *http.Client, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build GET %s: %w", rawURL, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	return resp, nil
}

// decodeJSONBody reads resp.Body as a JSON object. Empty bodies map
// to an empty map; transport / decode errors propagate. The function
// does NOT close resp.Body — the caller owns the lifecycle.
func decodeJSONBody(resp *http.Response) (map[string]any, error) {
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode body %q: %w", string(raw), err)
	}
	return out, nil
}

// findCookie returns the cookie matching name, or nil. Used to
// thread the OP's CSRF cookie between the GET / POST hops on
// /interaction/{uid}.
func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}
