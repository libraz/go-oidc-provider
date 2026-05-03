package dpop

import (
	"context"
	"errors"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

// RFC 6749 §5.2 / RFC 9449 §8 wire codes the DPoP error path emits.
// The set is closed: ad-hoc codes are forbidden so the discoverable
// error surface stays auditable.
const (
	codeInvalidRequest = "invalid_request"
	codeServerError    = "server_error"

	// codeUseDPoPNonce is the RFC 9449 §8 wire code an endpoint emits
	// when the request must be retried with a fresh server-supplied
	// DPoP nonce. The companion "DPoP-Nonce" response header carries
	// the value the client should embed in the next proof's "nonce"
	// claim.
	codeUseDPoPNonce = "use_dpop_nonce"
)

// NonceSource is the contract the [WriteError] helper consults when
// it needs to stamp a fresh "DPoP-Nonce" response header on the
// `use_dpop_nonce` challenge. Any value implementing [NonceIssuer]
// satisfies this interface; [WriteError] accepts the broader contract
// (taking [context.Context]) so embedders that want a request-scoped
// nonce pipeline can plug in directly without an adapter. A nil value
// omits the header — the JSON envelope still carries
// error="use_dpop_nonce" so a debugger can see the gate triggered.
type NonceSource interface {
	NextNonce(ctx context.Context) (string, error)
}

// nonceIssuerSource adapts a [NonceIssuer] onto the [NonceSource]
// contract so handler code that already wires a [NonceIssuer] can
// hand the value to [WriteError] without an explicit adapter at the
// call site.
type nonceIssuerSource struct{ issuer NonceIssuer }

// NextNonce implements [NonceSource] by delegating to the wrapped
// [NonceIssuer]. The context is ignored because [NonceIssuer.IssueNonce]
// is expected to be a synchronous, in-memory call.
func (n nonceIssuerSource) NextNonce(_ context.Context) (string, error) {
	return n.issuer.IssueNonce(), nil
}

// NonceSourceFromIssuer adapts a [NonceIssuer] onto the [NonceSource]
// contract. The helper exists so handler code can pass the same
// implementation to both [VerifierConfig.Nonces] and [WriteError]
// without duplicating the adapter at every call site. A nil issuer
// returns nil so the caller can pass [Deps.DPoPNonces] verbatim.
//
// The function returns an interface; ireturn is suppressed because
// the alternative (returning the concrete unexported adapter type)
// would force every caller to import a package-internal symbol just
// to declare the variable type, defeating the adapter's purpose.
//
//nolint:ireturn // adapter contract requires the interface return.
func NonceSourceFromIssuer(issuer NonceIssuer) NonceSource {
	if issuer == nil {
		return nil
	}
	return nonceIssuerSource{issuer: issuer}
}

// WriteError translates a [Err*] sentinel (or a wrapper around one)
// onto the canonical RFC 9449 §6 / RFC 6749 §5.2 wire form. RFC 9449
// §7 prescribes "invalid_dpop_proof" but the library re-uses the OAuth
// "invalid_request" envelope already shared by /token, /par, and
// every other endpoint that processes form posts so RP libraries that
// key off the OAuth codes do not need to learn a new code class. The
// description echoes the closest RFC 9449 wording; the wrapped
// sentinel cause is dropped to avoid leaking timing-side-channel
// signal.
//
// The nonce sentinels ([ErrProofNonceMissing] / [ErrProofNonceInvalid])
// take a separate code: §8 defines "use_dpop_nonce" specifically so
// the client knows to retry with the fresh value carried in the
// companion "DPoP-Nonce" response header. nonceSrc is consulted only
// on those two sentinels — supply nil to omit the header (the issuer
// is offline) but the JSON envelope still carries
// error="use_dpop_nonce" so a debugger can see the gate fired.
func WriteError(ctx context.Context, w http.ResponseWriter, err error, nonceSrc NonceSource) {
	if IsNonceError(err) {
		writeUseDPoPNonce(ctx, w, nonceSrc)
		return
	}
	switch {
	case errors.Is(err, ErrProofMalformed),
		errors.Is(err, ErrProofMissingJTI):
		_ = httpx.WriteError(w, http.StatusBadRequest, codeInvalidRequest, "DPoP proof malformed")
	case errors.Is(err, ErrProofSignature):
		_ = httpx.WriteError(w, http.StatusBadRequest, codeInvalidRequest, "DPoP proof signature invalid")
	case errors.Is(err, ErrProofIatWindow):
		_ = httpx.WriteError(w, http.StatusBadRequest, codeInvalidRequest, "DPoP proof iat outside acceptable window")
	case errors.Is(err, ErrProofReplayed):
		_ = httpx.WriteError(w, http.StatusBadRequest, codeInvalidRequest, "DPoP proof replayed")
	case errors.Is(err, ErrProofHTMMismatch),
		errors.Is(err, ErrProofHTUMismatch):
		_ = httpx.WriteError(w, http.StatusBadRequest, codeInvalidRequest, "DPoP proof does not bind to this request")
	case errors.Is(err, ErrProofATHMismatch):
		_ = httpx.WriteError(w, http.StatusBadRequest, codeInvalidRequest, "DPoP proof does not bind to the access token")
	default:
		_ = httpx.WriteError(w, http.StatusInternalServerError, codeServerError, "")
	}
}

// writeUseDPoPNonce emits the RFC 9449 §8 nonce challenge: a 400
// JSON envelope with error="use_dpop_nonce" plus a "DPoP-Nonce"
// response header carrying a fresh value the client should embed in
// the next proof's "nonce" claim. A nil nonceSrc omits the header
// (the issuer is offline) but still emits the JSON body so a debugger
// can see the gate fired; the client then has no nonce to retry
// with, which is the most truthful signal the server can give in
// that misconfiguration. The same helper backs the /token and /par
// endpoints so the two issue nonces interchangeably from the same
// rotation pipeline.
func writeUseDPoPNonce(ctx context.Context, w http.ResponseWriter, nonceSrc NonceSource) {
	if nonceSrc != nil {
		if nonce, err := nonceSrc.NextNonce(ctx); err == nil && nonce != "" {
			w.Header().Set("DPoP-Nonce", nonce)
		}
	}
	_ = httpx.WriteError(w, http.StatusBadRequest, codeUseDPoPNonce,
		"DPoP proof requires a server-supplied nonce; retry using the value in the DPoP-Nonce response header")
}
