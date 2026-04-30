package authorizeendpoint

import (
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// expectedUIDLength is the byte length every base64-url-no-pad encoding
// of [uidByteLength] random bytes always carries. The SPA shell handler
// refuses to serve index.html for any value that does not match this
// exact shape because the URL is the continuation token's only carrier;
// a relaxed match would let the handler double as a probing oracle for
// arbitrary static-file paths colliding with the {uid} pattern.
const expectedUIDLength = 22

// spaCacheControl is the cache directive stamped on every shell
// response. The shell HTML is coupled to in-flight interaction state,
// so cache reuse — even within the same browser session — would be
// incorrect. Asset responses do not share this header: their cacheing
// posture (long-cache vs no-store) depends on whether the embedder's
// build emits content hashes, and that decision is the embedder's.
const spaCacheControl = "no-store, no-cache, must-revalidate"

// looksLikeUID reports whether s could be a base64-url-no-pad encoding
// of [uidByteLength] random bytes. The check is byte-class based; a
// false return is the only sentinel the caller needs to refuse the
// request. The function does not consult any server-side state and
// therefore cannot leak information about uid existence.
func looksLikeUID(s string) bool {
	if len(s) != expectedUIDLength {
		return false
	}
	for i := range s {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

// newSPAShellHandler returns the HTTP handler responsible for serving
// the SPA's index.html at SPALoginMount/{uid}. The handler:
//
//   - rejects requests whose {uid} path value does not match the
//     base64-url-no-pad shape;
//   - rejects requests whose __Host-oidc_interaction cookie does not
//     seal the same UID, mirroring the JSON state surface so a
//     URL-only probe cannot distinguish "uid exists" from "uid
//     unknown";
//   - stamps the same X-Frame-Options / Cache-Control / nosniff
//     hardening the OP applies to the JSON state surface.
//
// The handler reads index.html from disk on every request so the
// embedder can hot-swap the bundle without restarting the OP; the
// per-request stat is bounded by safeFS.
func newSPAShellHandler(deps resolved) http.Handler {
	indexPath := filepath.Join(deps.SPAStaticDir, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid := r.PathValue("uid")
		if !looksLikeUID(uid) {
			http.NotFound(w, r)
			return
		}
		if !verifyInteractionCookie(r, deps, uid) {
			http.NotFound(w, r)
			return
		}
		info, err := os.Stat(indexPath)
		if err != nil || info.IsDir() {
			http.NotFound(w, r)
			return
		}
		stampSPAShellHeaders(w)
		http.ServeFile(w, r, indexPath)
	})
}

// stampSPAShellHeaders applies the OP's standard hardening header set
// to a SPA shell response. The list mirrors HTMLDriver.Render so an
// embedder cannot "lose" hardening by switching to the SPA wiring.
// Content-Type is set explicitly even though http.ServeFile would
// derive it from the .html extension because http.ServeFile only
// stamps Content-Type when the header is absent and the embedder may
// have wrapped the handler in middleware that pre-populates it.
func stampSPAShellHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", spaCacheControl)
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
}

// newSPAAssetHandler returns the HTTP handler that serves the SPA
// bundle's static assets under SPALoginMount/assets/. The handler
// re-mounts the request URL through the standard library's
// [http.FileServer] backed by [safeFS], a hardened
// [http.FileSystem] that:
//
//   - rejects basename entries beginning with "." (dotfiles such as
//     .env, .git, .DS_Store committed to StaticDir by accident);
//   - returns "not found" for directory targets (no auto-listing,
//     no index.html fallback under /assets/);
//   - rejects symlinks whose resolved target lies outside the
//     configured StaticDir.
//
// Cache-Control is intentionally NOT stamped: the long-cache vs
// no-store choice depends on whether the embedder's build emits
// content-hashed filenames, and the embedder decides via reverse
// proxy. The handler always emits X-Content-Type-Options: nosniff so
// a misnamed asset cannot be re-typed by a hostile browser.
func newSPAAssetHandler(deps resolved) http.Handler {
	root := deps.SPAStaticDir
	fileServer := http.FileServer(safeFS{root: root})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := r.PathValue("path")
		if rel == "" {
			http.NotFound(w, r)
			return
		}
		// Re-construct the URL the FileServer expects. {path...} in
		// the mux pattern delivers the path-segment list joined by
		// "/", URL-decoded. Forwarding it under "/assets/" keeps the
		// FileServer rooted at StaticDir while routing only the
		// /assets subtree through it.
		req := r.Clone(r.Context())
		req.URL.Path = "/assets/" + rel
		req.URL.RawPath = ""
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fileServer.ServeHTTP(w, req)
	})
}

// safeFS is the hardened [http.FileSystem] backing the SPA asset
// handler. The wrapper enforces three rules the standard library's
// [http.Dir] does not:
//
//  1. Dotfile rejection. A basename starting with "." resolves to
//     [fs.ErrNotExist]. The check applies to every segment so a
//     request like "/assets/.env" is rejected even if no path
//     traversal is involved. Defense against committed secrets and
//     metadata files (e.g., .git, .DS_Store).
//  2. Directory rejection. An [os.Lstat] target whose mode is a
//     directory resolves to [fs.ErrNotExist]. The asset handler
//     never serves directory listings or auto-index pages — those
//     are the SPA shell's responsibility.
//  3. Symlink containment. An [os.Lstat] target whose mode includes
//     [os.ModeSymlink] is followed via [filepath.EvalSymlinks]; a
//     resolved target outside the configured root resolves to
//     [fs.ErrNotExist]. Defense against build-tool symlinks (npm /
//     pnpm workspace links) that would expose dependency
//     directories or the host filesystem.
//
// The wrapper does NOT attempt to enforce a per-file allowlist; the
// embedder is trusted to populate StaticDir with public assets only.
type safeFS struct {
	// root is the absolute or relative on-disk path the SPA bundle
	// lives under. Every Open call resolves names relative to root.
	root string
}

// Open implements [http.FileSystem]. The function is the single
// chokepoint where dotfile / directory / symlink rules are applied.
// All three checks short-circuit the os.Open call so a denied entry
// is indistinguishable from a missing file at the byte level.
func (f safeFS) Open(name string) (http.File, error) {
	cleaned := path.Clean(name)
	if !validAssetPath(cleaned) {
		return nil, fs.ErrNotExist
	}
	abs := filepath.Join(f.root, filepath.FromSlash(cleaned))
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fs.ErrNotExist
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if err := assertSymlinkWithin(f.root, abs); err != nil {
			return nil, err
		}
	}
	// abs is the join of the embedder-supplied SPAStaticDir (rooted
	// at boot, validated for existence by op.WithSPAUI) and a name
	// that has already passed validAssetPath plus the directory and
	// symlink-containment checks above. The remaining surface for
	// G304 is "embedder pointed StaticDir at a sensitive location",
	// which is a configuration concern outside the runtime guard's
	// reach; the safeFS contract documents that StaticDir must
	// hold public assets only.
	file, err := os.Open(abs) //nolint:gosec // path validated by safeFS guards above.
	if err != nil {
		return nil, err
	}
	return file, nil
}

// validAssetPath reports whether cleaned (path.Clean'd, slash-
// separated) contains no dotfile segment and no empty segment past
// the leading slash. http.FileServer always cleans the request URL
// before calling Open, so this check is defense-in-depth: a future
// regression that bypasses the cleaning step still cannot reach a
// dotfile.
func validAssetPath(cleaned string) bool {
	if cleaned == "" {
		return false
	}
	for _, seg := range strings.Split(cleaned, "/") {
		if seg == "" {
			continue
		}
		if strings.HasPrefix(seg, ".") {
			return false
		}
	}
	return true
}

// assertSymlinkWithin returns nil when the symlink at abs resolves
// to a path beneath root, and [fs.ErrNotExist] otherwise. The
// helper resolves the entire chain via [filepath.EvalSymlinks] for
// both target and root so a link-to-link-to-outside is rejected
// and an OS that prefixes the temp directory with a platform
// symlink (e.g., /var → /private/var on macOS) does not produce a
// false-negative containment check. Absolute targets and "../"
// escapes are normalised by the same call.
func assertSymlinkWithin(root, abs string) error {
	target, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return err
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	rootResolved, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		// Root is the embedder-supplied StaticDir; a missing or
		// inaccessible root surfaces here as fs.ErrNotExist so the
		// asset handler returns 404 rather than leaking the
		// underlying error.
		return fs.ErrNotExist
	}
	rel, err := filepath.Rel(rootResolved, target)
	if err != nil {
		return fs.ErrNotExist
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fs.ErrNotExist
	}
	return nil
}
