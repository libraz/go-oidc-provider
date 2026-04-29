package op

// PublicScope is a two-line constructor that returns a [Scope] with
// Public set to true and the supplied label as the default user-facing
// title. The helper exists so embedders can declare an advertised
// scope without spelling out the struct shape:
//
//	op.WithScope(op.PublicScope("read:projects", "Read your projects"))
//
// [Scope.Public] is the only visibility axis (the field is a `bool`,
// not a new type). The standard OIDC scopes are forced
// Public: true regardless of how they are constructed; this helper
// is therefore safe to use for every scope that should appear in
// `scopes_supported`.
func PublicScope(name, label string) Scope {
	return Scope{
		Name:   name,
		Title:  label,
		Public: true,
	}
}

// InternalScope is a two-line constructor that returns a [Scope] with
// Public set to false. Internal scopes are omitted from the discovery
// document's `scopes_supported` list (RFC 8414 §2 / OIDC Discovery 1.0
// §3 explicitly permits the omission); request-time acceptance is still
// governed by [Scope.AllowedClients].
//
//	op.WithScope(op.InternalScope("internal:metrics"))
//
// Standard OIDC scopes (openid, profile, email, address, phone,
// offline_access) cannot be registered as internal; passing one of
// them to InternalScope and feeding it to [WithScope] causes [New] to
// reject the configuration so the discovery document never violates
// OIDC Discovery 1.0 §3.
func InternalScope(name string) Scope {
	return Scope{
		Name:   name,
		Public: false,
	}
}
