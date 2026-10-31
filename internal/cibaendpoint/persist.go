package cibaendpoint

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Tunables the handler uses when [Deps] omits the corresponding
// field.
const (
	// authReqIDByteLength is the entropy of the wire auth_req_id.
	// 32 bytes (256 bits) matches the posture the library uses for
	// authorization codes, refresh tokens, and device codes — well
	// above any "guessing infeasible" bar.
	authReqIDByteLength = 32
)

// successResponse is the CIBA Core §7.3 backchannel-authentication
// response body.
type successResponse struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int64  `json:"expires_in"`
	Interval  int64  `json:"interval"`
}

// persistInput bundles the parameters [persist] consumes. The
// struct exists to keep [serve]'s call site readable under the
// project's gocognit cap.
type persistInput struct {
	Client         *store.Client
	Subject        string
	HintKind       ciba.HintKind
	Scope          []string
	Resource       []string
	ACRValues      []string
	BindingMessage string
	UserCode       string
	ExpiresIn      time.Duration
	DPoPJKT        string
	MTLSThumbprint string
}

// persist mints the auth_req_id, writes the record, and emits the
// success envelope. Save collisions on the auth_req_id are treated
// as fatal randomness faults: the 256-bit space makes a collision
// inside an active record's TTL astronomically rare, so a single
// failure short-circuits to server_error rather than retrying.
func persist(ctx context.Context, w http.ResponseWriter, deps Deps, in persistInput) {
	authReqID, err := newAuthReqID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "could not allocate auth_req_id")
		return
	}
	now := deps.now().UTC()
	expiresAt := now.Add(in.ExpiresIn)
	interval := deps.pollInterval()
	rec := &store.CIBARequest{
		ID:             authReqID,
		ClientID:       in.Client.ID,
		Subject:        in.Subject,
		Scope:          in.Scope,
		Resource:       in.Resource,
		ACRValues:      in.ACRValues,
		BindingMessage: in.BindingMessage,
		UserCode:       in.UserCode,
		DPoPJKT:        in.DPoPJKT,
		MTLSCertS256:   in.MTLSThumbprint,
		Interval:       interval,
		IssuedAt:       now,
		ExpiresAt:      expiresAt,
		Status:         store.CIBARequestStatusPending,
	}
	if err := deps.CIBARequests.Save(ctx, rec); err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "could not persist ciba request")
		return
	}
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:     ciba.AuditAuthorizationIssued,
		Level:    audit.LevelInfo,
		Message:  "backchannel-authentication issued",
		ClientID: in.Client.ID,
		ActorID:  in.Subject,
		Extras: map[string]any{
			"client_id":  in.Client.ID,
			"scope":      append([]string(nil), in.Scope...),
			"resource":   append([]string(nil), in.Resource...),
			"expires_in": int64(in.ExpiresIn.Seconds()),
			"interval":   int64(interval.Seconds()),
			"binding":    bindingLabel(in.DPoPJKT, in.MTLSThumbprint),
			"hint_kind":  in.HintKind.String(),
		},
	})
	stampNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(successResponse{
		AuthReqID: authReqID,
		ExpiresIn: int64(in.ExpiresIn.Seconds()),
		Interval:  int64(interval.Seconds()),
	})
}

// newAuthReqID returns a freshly generated auth_req_id: 32 bytes
// of crypto/rand encoded as base64url-no-pad (256 bits of
// entropy). The body lives in this package rather than
// internal/ciba because the wire-secret path is owned by the
// issuer side; the helper packages stay free of HTTP / I/O
// concerns.
func newAuthReqID() (string, error) {
	buf := make([]byte, authReqIDByteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("cibaendpoint: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// bindingLabel returns the audit-extras label naming which sender
// constraint the issued record carries: "dpop", "mtls", or
// "bearer".
func bindingLabel(dpopJKT, mtlsThumbprint string) string {
	switch {
	case dpopJKT != "":
		return "dpop"
	case mtlsThumbprint != "":
		return "mtls"
	default:
		return "bearer"
	}
}
