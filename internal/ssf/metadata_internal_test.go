package ssf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func metaDeps(issuer string) MetadataDeps {
	return MetadataDeps{
		Issuer:                issuer,
		JWKSURI:               issuer + "/jwks",
		ConfigurationEndpoint: issuer + "/ssf/streams",
		StatusEndpoint:        issuer + "/ssf/status",
		VerificationEndpoint:  issuer + "/ssf/verify",
	}
}

func TestMetadataDocument(t *testing.T) {
	t.Parallel()
	for _, issuer := range []string{testIssuer, testIssuer + "/tenant-a"} {
		h, err := NewMetadataHandler(metaDeps(issuer))
		if err != nil {
			t.Fatalf("NewMetadataHandler: %v", err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/ssf-configuration", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d", w.Code)
		}
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		want := map[string]any{
			"spec_version":               "1_0",
			"issuer":                     issuer,
			"jwks_uri":                   issuer + "/jwks",
			"delivery_methods_supported": []any{"urn:ietf:rfc:8935", "urn:ietf:rfc:8936"},
			"configuration_endpoint":     issuer + "/ssf/streams",
			"status_endpoint":            issuer + "/ssf/status",
			"verification_endpoint":      issuer + "/ssf/verify",
			"authorization_schemes":      []any{map[string]any{"spec_urn": "urn:ietf:rfc:6749"}},
			"default_subjects":           "ALL",
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("metadata for %s =\n%v\nwant\n%v", issuer, got, want)
		}
	}
}

func TestMetadataMethods(t *testing.T) {
	t.Parallel()
	h, err := NewMetadataHandler(metaDeps(testIssuer))
	if err != nil {
		t.Fatalf("NewMetadataHandler: %v", err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodHead, "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("HEAD status = %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("POST status = %d, Allow %q", w.Code, w.Header().Get("Allow"))
	}
}

func TestMetadataRequiresEveryURL(t *testing.T) {
	t.Parallel()
	for name, edit := range map[string]func(*MetadataDeps){
		"issuer":       func(d *MetadataDeps) { d.Issuer = "" },
		"jwks":         func(d *MetadataDeps) { d.JWKSURI = "" },
		"config":       func(d *MetadataDeps) { d.ConfigurationEndpoint = "" },
		"status":       func(d *MetadataDeps) { d.StatusEndpoint = "" },
		"verification": func(d *MetadataDeps) { d.VerificationEndpoint = "" },
	} {
		d := metaDeps(testIssuer)
		edit(&d)
		if _, err := NewMetadataHandler(d); err == nil {
			t.Errorf("missing %s: NewMetadataHandler succeeded", name)
		}
	}
}

func TestMetadataWellKnownPath(t *testing.T) {
	t.Parallel()
	for issuer, want := range map[string]string{
		"https://op.example.com":          "/.well-known/ssf-configuration",
		"https://op.example.com/":         "/.well-known/ssf-configuration",
		"https://op.example.com/tenant-a": "/.well-known/ssf-configuration/tenant-a",
		"https://op.example.com/a/b/":     "/.well-known/ssf-configuration/a/b",
	} {
		got, err := WellKnownPath(issuer)
		if err != nil || got != want {
			t.Errorf("WellKnownPath(%q) = %q, %v; want %q", issuer, got, err, want)
		}
	}
}
