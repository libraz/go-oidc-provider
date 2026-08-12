package registrationendpoint

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// putDisposition records what PUT /register/{client_id} does with a
// single [store.Client] field.
type putDisposition int

const (
	// dispositionMetadata marks a field taken from the submitted
	// RFC 7591 §2 metadata on every update. An omitted member clears it
	// (RFC 7592 §2.2 defines omission as a request to delete).
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

// TestUpdateKeepsConfigurationTheMetadataCannotExpress drives the
// persistence path with an empty metadata document. That submission is
// the strongest probe available: it clears every field an update can
// express, so whatever still carries its seeded value is exactly what
// the update preserved. Rebuilding the record from the metadata instead
// of copying the stored one turns every preserved field zero and fails
// here.
func TestUpdateKeepsConfigurationTheMetadataCannotExpress(t *testing.T) {
	t.Parallel()

	existing := seedEveryClientField(t)
	stored := *existing
	registry := &fieldProbeRegistry{client: existing}
	deps := Deps{Clients: registry, RegistrationAccessTokens: fieldProbeRATStore{}}

	rotated, ok := rotateAndUpdate(
		context.Background(),
		httptest.NewRecorder(),
		deps,
		existing,
		ClientMetadata{},
	)
	if !ok {
		t.Fatal("rotateAndUpdate reported failure")
	}
	if registry.updated == nil {
		t.Fatal("rotateAndUpdate did not persist a client record")
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
			if !got.Field(i).IsZero() {
				t.Errorf("update kept store.Client.%s = %v although the submitted metadata omitted it; "+
					"an omitted member deletes the value", name, got.Field(i).Interface())
			}
		case dispositionDerived:
			// Asserted explicitly below, where the expected value can
			// be stated against the submitted auth method.
		}
	}

	// The submission named no authentication method, so it is not a
	// confidential registration: the secret is cleared and the client is
	// not marked public either (only "none" produces a public client).
	if registry.updated.SecretHash != "" {
		t.Errorf("SecretHash=%q, want empty for an update that names no confidential auth method",
			registry.updated.SecretHash)
	}
	if registry.updated.PublicClient {
		t.Error("PublicClient=true, want false for an update that names no auth method")
	}
	if rotated.rawRAT == "" {
		t.Error("rotateAndUpdate returned an empty registration access token")
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

// fieldProbeRATStore accepts the rotated registration access token and
// forgets it; the rotation itself is covered by the management suite.
type fieldProbeRATStore struct{}

func (fieldProbeRATStore) Put(context.Context, *store.RegistrationAccessToken) error { return nil }

func (fieldProbeRATStore) GetByClientID(context.Context, string) (*store.RegistrationAccessToken, error) {
	return nil, store.ErrNotFound
}

func (fieldProbeRATStore) Delete(context.Context, string) error { return nil }
