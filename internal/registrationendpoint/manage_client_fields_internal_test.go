package registrationendpoint

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/op/store"
)

// putDisposition records what PUT /register/{client_id} does with a
// single [store.Client] field.
type putDisposition int

const (
	// dispositionMetadata marks a field taken from the submitted
	// RFC 7591 §2 metadata on every update. An omitted member clears it
	// (RFC 7592 §2.2 defines omission as a request to delete), except
	// where the library holds a documented default for the member — see
	// [minimalUpdateValues].
	dispositionMetadata putDisposition = iota

	// dispositionPreserved marks a field the registration wire shape
	// cannot express. The update copies the stored value forward; an
	// operator who configured it out of band keeps it.
	dispositionPreserved

	// dispositionDerived marks a field the handler recomputes from the
	// resulting authentication posture rather than copying or reading
	// from the metadata.
	dispositionDerived
)

// putFieldDispositions classifies every [store.Client] field for the
// update path. Adding a field to [store.Client] without adding it here
// fails [TestPutDispositionsCoverEveryClientField], which is the point:
// a new field is either something a client can submit or something the
// OP holds on the client's behalf, and getting that wrong silently
// deletes configuration on the RP's next update.
var putFieldDispositions = map[string]putDisposition{
	// Identity the OP minted at creation. A metadata edit never
	// reassigns it.
	"ID":               dispositionPreserved,
	"ClientIDIssuedAt": dispositionPreserved,

	// Provenance, a property of the record's creation. Only a
	// self-registered record reaches the update path at all, so the
	// carried-forward value is the one a restamp would write.
	"Source": dispositionPreserved,

	// Configuration with no member in the registration wire shape. The
	// resource-indicator allow-list is reachable only through the
	// embedder's own administration path and survives a client update.
	"Resources": dispositionPreserved,

	// Credentials and the public/confidential split follow the auth
	// method the update settles on, not a submitted value.
	"SecretHash":   dispositionDerived,
	"PublicClient": dispositionDerived,

	"RedirectURIs":                      dispositionMetadata,
	"PostLogoutRedirectURIs":            dispositionMetadata,
	"BackchannelLogoutURI":              dispositionMetadata,
	"BackchannelLogoutSessionRequired":  dispositionMetadata,
	"GrantTypes":                        dispositionMetadata,
	"ResponseTypes":                     dispositionMetadata,
	"Scopes":                            dispositionMetadata,
	"TokenEndpointAuthMethod":           dispositionMetadata,
	"TokenEndpointAuthSigningAlg":       dispositionMetadata,
	"ApplicationType":                   dispositionMetadata,
	"SubjectType":                       dispositionMetadata,
	"IDTokenSignedResponseAlg":          dispositionMetadata,
	"SectorIdentifierURI":               dispositionMetadata,
	"ClientName":                        dispositionMetadata,
	"ClientURI":                         dispositionMetadata,
	"LogoURI":                           dispositionMetadata,
	"PolicyURI":                         dispositionMetadata,
	"TosURI":                            dispositionMetadata,
	"JWKsURI":                           dispositionMetadata,
	"JWKs":                              dispositionMetadata,
	"Contacts":                          dispositionMetadata,
	"DefaultMaxAge":                     dispositionMetadata,
	"RequireAuthTime":                   dispositionMetadata,
	"DefaultACRValues":                  dispositionMetadata,
	"InitiateLoginURI":                  dispositionMetadata,
	"RequestURIs":                       dispositionMetadata,
	"RequestObjectSigningAlg":           dispositionMetadata,
	"RequestObjectEncryptionAlg":        dispositionMetadata,
	"RequestObjectEncryptionEnc":        dispositionMetadata,
	"IDTokenEncryptedResponseAlg":       dispositionMetadata,
	"IDTokenEncryptedResponseEnc":       dispositionMetadata,
	"UserInfoEncryptedResponseAlg":      dispositionMetadata,
	"UserInfoEncryptedResponseEnc":      dispositionMetadata,
	"AuthorizationEncryptedResponseAlg": dispositionMetadata,
	"AuthorizationEncryptedResponseEnc": dispositionMetadata,
	"IntrospectionSignedResponseAlg":    dispositionMetadata,
	"IntrospectionEncryptedResponseAlg": dispositionMetadata,
	"IntrospectionEncryptedResponseEnc": dispositionMetadata,
}

// TestPutDispositionsCoverEveryClientField holds the classification
// against the struct itself, in both directions: a field with no entry
// is a field nobody decided about, and an entry with no field is a
// leftover that would make the behavioural test below silently weaker.
func TestPutDispositionsCoverEveryClientField(t *testing.T) {
	t.Parallel()

	clientType := reflect.TypeOf(store.Client{})
	present := make(map[string]struct{}, clientType.NumField())
	for i := range clientType.NumField() {
		name := clientType.Field(i).Name
		present[name] = struct{}{}
		if _, ok := putFieldDispositions[name]; !ok {
			t.Errorf("store.Client.%s has no PUT disposition: decide whether an update takes it "+
				"from the submitted metadata or carries the stored value forward, then record it "+
				"in putFieldDispositions", name)
		}
	}
	for name := range putFieldDispositions {
		if _, ok := present[name]; !ok {
			t.Errorf("putFieldDispositions names %q, which store.Client no longer declares", name)
		}
	}
}

// probeRedirectURI is the single member the minimal update document
// carries. The endpoint refuses a document without redirect_uris, so it
// is the one metadata member the probe cannot omit.
const probeRedirectURI = "https://rp.test.invalid/callback"

// minimalUpdateValues names the members that are legitimately non-zero
// after an update document that carries redirect_uris and nothing else:
// the submitted URI, plus the members [applyMetadataDefaults] fills for
// a document that omits them.
//
// Every other metadata member — Scopes above all — must come back zero.
// A default that reaches the update path hands an already-registered
// client authority it never asked for: a client that registered with
// "openid" and then omits the member would collect the OP's whole
// public scope catalog.
var minimalUpdateValues = map[string]any{
	"RedirectURIs":             []string{probeRedirectURI},
	"GrantTypes":               []string{"authorization_code", "refresh_token"},
	"ResponseTypes":            []string{"code"},
	"TokenEndpointAuthMethod":  defaultAuthMethod,
	"SubjectType":              defaultSubjectType,
	"IDTokenSignedResponseAlg": defaultIDTokenAlg,
	"ApplicationType":          defaultApplicationType,
}

// TestUpdateKeepsConfigurationTheMetadataCannotExpress drives the
// endpoint itself with the smallest document PUT /register/{client_id}
// accepts: redirect_uris and nothing else. That submission is the
// strongest probe available — it omits every other member an update can
// express, so whatever the persisted record still carries is exactly
// what the update path decided to put there. Rebuilding the record from
// the metadata instead of copying the stored one turns every preserved
// field zero, and a member the request never named that comes back
// populated is authority the OP granted on its own initiative.
//
// The probe runs through [Handler] rather than the persistence helper:
// the scope defaults live in the validation stage, so a probe that
// starts below it cannot see them.
func TestUpdateKeepsConfigurationTheMetadataCannotExpress(t *testing.T) {
	t.Parallel()

	const clientID = "probe-client"
	const rawRAT = "probe-registration-access-token"

	existing := seedEveryClientField(t)
	existing.ID = clientID
	existing.Source = store.ClientSourceDynamic
	stored := *existing
	registry := &fieldProbeRegistry{client: existing}
	handler := Handler(Deps{
		Issuer:                   "https://op.test.invalid",
		RegisterPath:             "/register",
		Clients:                  registry,
		RegistrationAccessTokens: fieldProbeRATStore{hashedRAT: hashSecret(rawRAT)},
		// A populated catalog is what makes the probe able to fail: with
		// no registered scopes there is nothing for a scope default to
		// widen to.
		Scopes: scoperegistry.New([]scoperegistry.Entry{
			{Name: "openid", Public: true},
			{Name: "profile", Public: true},
			{Name: "email", Public: true},
		}),
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/register/"+clientID,
		strings.NewReader(`{"redirect_uris":["`+probeRedirectURI+`"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+rawRAT)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}
	if registry.updated == nil {
		t.Fatal("the update did not persist a client record")
	}

	got := reflect.ValueOf(*registry.updated)
	want := reflect.ValueOf(stored)
	clientType := got.Type()
	for i := range clientType.NumField() {
		name := clientType.Field(i).Name
		disposition, classified := putFieldDispositions[name]
		if !classified {
			// Reported by TestPutDispositionsCoverEveryClientField;
			// asserting here as well would only add noise.
			continue
		}
		switch disposition {
		case dispositionPreserved:
			if !reflect.DeepEqual(got.Field(i).Interface(), want.Field(i).Interface()) {
				t.Errorf("update dropped store.Client.%s: got %v, stored value was %v; a field the "+
					"registration metadata cannot express must survive an update",
					name, got.Field(i).Interface(), want.Field(i).Interface())
			}
		case dispositionMetadata:
			if expected, defaulted := minimalUpdateValues[name]; defaulted {
				if !reflect.DeepEqual(got.Field(i).Interface(), expected) {
					t.Errorf("update stored store.Client.%s = %v, want %v; the submitted document and the "+
						"library defaults are the only sources an update draws on",
						name, got.Field(i).Interface(), expected)
				}
				continue
			}
			if !got.Field(i).IsZero() {
				t.Errorf("update kept store.Client.%s = %v although the submitted metadata omitted it; "+
					"an omitted member deletes the value and never collects a registration default",
					name, got.Field(i).Interface())
			}
		case dispositionDerived:
			// Asserted explicitly below, where the expected value can
			// be stated against the auth method the update settled on.
		}
	}

	// The document named no authentication method, so it takes the
	// confidential default: the stored secret is carried forward rather
	// than rotated, and the client stays confidential (only "none"
	// produces a public client).
	if registry.updated.SecretHash != stored.SecretHash {
		t.Errorf("SecretHash=%q, want the stored hash %q carried forward: a metadata edit must not rotate "+
			"credentials", registry.updated.SecretHash, stored.SecretHash)
	}
	if registry.updated.PublicClient {
		t.Error("PublicClient=true, want false for an update that defaults to a confidential auth method")
	}
}

// seedEveryClientField returns a [store.Client] with every field set to
// a non-zero value, so the assertions above cannot pass by accident on a
// field the seeder forgot. The switch is deliberately closed: a field
// whose type the seeder cannot fill fails the test rather than being
// left at its zero value.
func seedEveryClientField(t *testing.T) *store.Client {
	t.Helper()

	var seeded store.Client
	value := reflect.ValueOf(&seeded).Elem()
	clientType := value.Type()
	for i := range clientType.NumField() {
		field := value.Field(i)
		name := clientType.Field(i).Name
		switch {
		case field.Type() == reflect.TypeOf(json.RawMessage(nil)):
			field.Set(reflect.ValueOf(json.RawMessage(`{"keys":[]}`)))
		case field.Kind() == reflect.String:
			field.SetString("seed-" + name)
		case field.Kind() == reflect.Bool:
			field.SetBool(true)
		case field.Kind() == reflect.Int64:
			field.SetInt(1)
		case field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.String:
			field.Set(reflect.ValueOf([]string{"seed-" + name}))
		case field.Kind() == reflect.Pointer && field.Type().Elem().Kind() == reflect.Int64:
			seed := int64(1)
			field.Set(reflect.ValueOf(&seed))
		default:
			t.Fatalf("store.Client.%s is a %s, which seedEveryClientField cannot fill; "+
				"extend the seeder so the field is covered", name, field.Type())
		}
	}
	return &seeded
}

// fieldProbeRegistry is a [store.ClientRegistry] that records the record
// handed to UpdateClient.
type fieldProbeRegistry struct {
	client  *store.Client
	updated *store.Client
}

func (r *fieldProbeRegistry) GetClient(_ context.Context, id string) (*store.Client, error) {
	if r.client == nil || r.client.ID != id {
		return nil, store.ErrNotFound
	}
	return r.client, nil
}

func (r *fieldProbeRegistry) RegisterClient(context.Context, *store.Client) error { return nil }

func (r *fieldProbeRegistry) UpdateClient(_ context.Context, c *store.Client) error {
	r.updated = c
	return nil
}

func (r *fieldProbeRegistry) DeleteClient(context.Context, string) error { return nil }

// fieldProbeRATStore answers the management credential check with a
// fixed hash and forgets the rotated token; the rotation itself is
// covered by the management suite.
type fieldProbeRATStore struct {
	hashedRAT string
}

func (fieldProbeRATStore) Put(context.Context, *store.RegistrationAccessToken) error { return nil }

func (s fieldProbeRATStore) GetByClientID(_ context.Context, clientID string) (*store.RegistrationAccessToken, error) {
	if s.hashedRAT == "" {
		return nil, store.ErrNotFound
	}
	return &store.RegistrationAccessToken{ClientID: clientID, HashedValue: s.hashedRAT}, nil
}

func (fieldProbeRATStore) Delete(context.Context, string) error { return nil }
