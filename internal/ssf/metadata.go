package ssf

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

// SpecVersion is the SSF version the transmitter implements (SSF 1.0 §7.1).
const SpecVersion = "1_0"

// Delivery method URNs (SSF 1.0 §6.1.1).
const (
	DeliveryURNPush = "urn:ietf:rfc:8935"
	DeliveryURNPoll = "urn:ietf:rfc:8936"
)

// authorizationSchemeOAuth names RFC 6749 bearer authorization of the
// management API (SSF 1.0 §7.1.1).
const authorizationSchemeOAuth = "urn:ietf:rfc:6749"

// wellKnownSuffix is the transmitter configuration metadata path.
const wellKnownSuffix = "/.well-known/ssf-configuration"

// MetadataDeps are the absolute URLs the transmitter metadata advertises.
// Every field is required.
type MetadataDeps struct {
	Issuer                string
	JWKSURI               string
	ConfigurationEndpoint string
	StatusEndpoint        string
	VerificationEndpoint  string
}

type metadataDocument struct {
	SpecVersion              string                `json:"spec_version"`
	Issuer                   string                `json:"issuer"`
	JWKSURI                  string                `json:"jwks_uri"`
	DeliveryMethodsSupported []string              `json:"delivery_methods_supported"`
	ConfigurationEndpoint    string                `json:"configuration_endpoint"`
	StatusEndpoint           string                `json:"status_endpoint"`
	VerificationEndpoint     string                `json:"verification_endpoint"`
	AuthorizationSchemes     []metadataAuthzScheme `json:"authorization_schemes"`
	DefaultSubjects          string                `json:"default_subjects"`
}

type metadataAuthzScheme struct {
	SpecURN string `json:"spec_urn"`
}

// NewMetadataHandler serves the transmitter configuration metadata
// (SSF 1.0 §7.1) on GET / HEAD.
func NewMetadataHandler(d MetadataDeps) (http.Handler, error) {
	if d.Issuer == "" || d.JWKSURI == "" || d.ConfigurationEndpoint == "" ||
		d.StatusEndpoint == "" || d.VerificationEndpoint == "" {
		return nil, errors.New("ssf: every MetadataDeps URL is required")
	}
	doc := metadataDocument{
		SpecVersion:              SpecVersion,
		Issuer:                   d.Issuer,
		JWKSURI:                  d.JWKSURI,
		DeliveryMethodsSupported: []string{DeliveryURNPush, DeliveryURNPoll},
		ConfigurationEndpoint:    d.ConfigurationEndpoint,
		StatusEndpoint:           d.StatusEndpoint,
		VerificationEndpoint:     d.VerificationEndpoint,
		AuthorizationSchemes:     []metadataAuthzScheme{{SpecURN: authorizationSchemeOAuth}},
		// Every subject the receiver holds a grant relationship with.
		DefaultSubjects: "ALL",
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !httpx.EnforceMethod(w, r, http.MethodGet) {
			return
		}
		_ = httpx.WriteJSON(w, http.StatusOK, doc)
	}), nil
}

// WellKnownPath returns the metadata path for issuer: the well-known
// suffix with the issuer's path appended (the RFC 8414 §3.1 form).
func WellKnownPath(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return "", err
	}
	return wellKnownSuffix + strings.TrimSuffix(u.EscapedPath(), "/"), nil
}
