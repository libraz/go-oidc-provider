package store

// StandardClaims is the typed form of the OpenID Connect Core §5.1
// standard claims, for building [User.Claims] from columns of an
// existing users table. Each field has the Go type that encodes as the
// JSON type §5.1 gives the claim, so a projection that goes through it
// cannot release, say, email_verified as a number.
//
// "sub" and "updated_at" are not fields: [User.Subject] and
// [User.UpdatedAt] carry them.
//
//	claims := store.StandardClaims{Name: name, Email: email, EmailVerified: verified}.Map()
//	claims["tenant"] = tenantID // custom claims are added to the map
//	return &store.User{Subject: subject, Claims: claims, UpdatedAt: modified}, nil
//
// Stable since v1.5.
type StandardClaims struct {
	Name              string
	GivenName         string
	FamilyName        string
	MiddleName        string
	Nickname          string
	PreferredUsername string
	Profile           string
	Picture           string
	Website           string
	Email             string
	// EmailVerified is released together with Email and never alone.
	// A table that does not record verification leaves it false, which
	// is what a relying party has to assume anyway.
	EmailVerified bool
	Gender        string
	Birthdate     string
	Zoneinfo      string
	Locale        string
	PhoneNumber   string
	// PhoneNumberVerified is released together with PhoneNumber and
	// never alone.
	PhoneNumberVerified bool
	Address             Address
}

// Address is the OpenID Connect Core §5.1.1 address claim.
//
// Stable since v1.5.
type Address struct {
	Formatted     string
	StreetAddress string
	Locality      string
	Region        string
	PostalCode    string
	Country       string
}

// Map returns a fresh claim map holding only the fields that are set.
// An empty string field is left out, a verified flag follows its
// address or number, and Address is released as an object once any of
// its fields is set.
func (c StandardClaims) Map() map[string]any {
	out := make(map[string]any)
	for _, f := range []struct {
		name, value string
	}{
		{"name", c.Name},
		{"given_name", c.GivenName},
		{"family_name", c.FamilyName},
		{"middle_name", c.MiddleName},
		{"nickname", c.Nickname},
		{"preferred_username", c.PreferredUsername},
		{"profile", c.Profile},
		{"picture", c.Picture},
		{"website", c.Website},
		{"email", c.Email},
		{"gender", c.Gender},
		{"birthdate", c.Birthdate},
		{"zoneinfo", c.Zoneinfo},
		{"locale", c.Locale},
		{"phone_number", c.PhoneNumber},
	} {
		if f.value != "" {
			out[f.name] = f.value
		}
	}
	if c.Email != "" {
		out["email_verified"] = c.EmailVerified
	}
	if c.PhoneNumber != "" {
		out["phone_number_verified"] = c.PhoneNumberVerified
	}
	if addr := c.Address.object(); len(addr) > 0 {
		out["address"] = addr
	}
	return out
}

func (a Address) object() map[string]any {
	out := make(map[string]any)
	for _, f := range []struct {
		name, value string
	}{
		{"formatted", a.Formatted},
		{"street_address", a.StreetAddress},
		{"locality", a.Locality},
		{"region", a.Region},
		{"postal_code", a.PostalCode},
		{"country", a.Country},
	} {
		if f.value != "" {
			out[f.name] = f.value
		}
	}
	return out
}
