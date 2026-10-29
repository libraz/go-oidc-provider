package interaction

// HiddenField is one hidden form input the logout confirmation form
// must submit back unchanged.
//
// Stable since v1.5.
type HiddenField struct {
	// Name is the form field name.
	Name string

	// Value is the field value. html/template escapes it in an attribute
	// context.
	Value string
}

// LogoutConfirmTemplateData is the data the confirmation template
// registered through op.WithLogoutUI is executed with. The page asks
// the user to confirm an RP-Initiated Logout that arrived without proof
// of intent.
//
// The template MUST render every entry of Fields as a hidden input
// inside a form that submits to SubmitAction with SubmitMethod. The
// double-submit CSRF token is one of them: a template that drops a
// field makes the confirmation POST fail with a 400.
//
// Stable since v1.5.
type LogoutConfirmTemplateData struct {
	// Locale is the BCP 47 tag the strings below were resolved for,
	// suitable for the <html lang> attribute. Empty selects English.
	Locale string

	// Title is the localized page heading.
	Title string

	// Body is the localized explanation of what signing out ends.
	Body string

	// Button is the localized label of the submit button.
	Button string

	// SubmitMethod is the form method. Always "POST".
	SubmitMethod string

	// SubmitAction is the form action, a relative reference that lands
	// back on the end-session endpoint.
	SubmitAction string

	// ClientName is the display name of the requesting client, or empty
	// when no client is identified.
	ClientName string

	// Fields are the hidden inputs the form submits, CSRF token included.
	Fields []HiddenField
}

// LogoutSignedOutTemplateData is the data the signed-out template
// registered through op.WithLogoutUI is executed with. The page is
// shown after a logout that carried no post_logout_redirect_uri.
//
// Stable since v1.5.
type LogoutSignedOutTemplateData struct {
	// Locale is the BCP 47 tag the strings below were resolved for.
	// Empty selects English.
	Locale string

	// Title is the localized page heading.
	Title string

	// Body is the localized confirmation text.
	Body string
}
