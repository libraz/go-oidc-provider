// Package cimd resolves URL-form client_id values through OAuth Client ID
// Metadata Documents (draft-ietf-oauth-client-id-metadata-document-02).
//
// [New] returns a [store.ClientStore] decorator. A registered client (static
// or dynamic) always wins; only an inner [store.ErrNotFound] for an id that
// passes the draft's URL rules leads to a fetch.
// Every failure on the way — URL rule, Allow hook, transport, status, body,
// validation — surfaces as [store.ErrNotFound], so the endpoint cannot be used
// as an existence oracle; the cause is recorded only in the audit stream. Local
// fetch-capacity pressure is the one exception and surfaces as [ErrUnavailable].
//
// Fetches go through the SSRF-hardened securefetch envelope (dial-time
// deny-list, no redirects, 5 KiB body cap, 5 s timeout) under the process-wide
// remotecache load gate. Documents are cached per exact id string for the
// Cache-Control / Expires lifetime clamped to [60 s, 24 h]; failures are
// negative-cached for five seconds and never used as a document.
//
// The returned store is safe for concurrent use and is meant to be built once
// per Provider so its cache and singleflight are shared by every endpoint.
package cimd
