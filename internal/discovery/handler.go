package discovery

import (
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

// Handler returns an [http.Handler] that serves the OpenID Connect
// Discovery 1.0 metadata at /.well-known/openid-configuration. The
// document body is marshalled once and cached for the lifetime of the
// returned handler.
func Handler(doc Document) (http.Handler, error) {
	return httpx.StaticJSONHandler(doc, httpx.StaticDocumentCacheControl)
}
