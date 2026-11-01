package authorizeendpoint

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/i18n"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// renderPrompt hands the prompt to the configured [interaction.Driver]
// and answers a render failure the Driver did not answer itself.
//
// A Driver that returns an error after committing its own status line
// (a template that failed midway through a body it had already started
// streaming) has already given the browser a response; appending a
// second one would splice an error page onto a half-rendered prompt, so
// the request ends there. A Driver that returns an error without ever
// touching the writer has committed nothing, and leaving it at that is
// what turned a template fault into an empty 200 OK: net/http writes an
// implicit 200 for a handler that returns having written nothing, so the
// browser is told the prompt rendered and shows a blank page. The
// distinction is what [committingResponseWriter] exists to record.
//
// The persisted interaction state is consistent either way — the prompt
// was saved before the render — so the user can reload into the same
// step once the deployment's template fault is fixed.
//
// The audit event rides on the branch the endpoint answers, not on every
// render error: a Driver that committed its own response already told
// the user what happened in whatever terms it chose, and the OP has
// nothing to add to a record of it. Only the branch where the Driver
// produced nothing leaves the cause invisible everywhere except here.
func renderPrompt(w http.ResponseWriter, r *http.Request, deps resolved, clientID string, prompt interaction.Prompt) {
	rw := &committingResponseWriter{ResponseWriter: w}
	err := deps.Driver.Render(rw, r, prompt)
	if err == nil || rw.committed {
		return
	}
	deps.auditEmitter().Emit(r.Context(), audit.Event{
		Name:     opAuditInteractionRenderFailed,
		Level:    audit.LevelWarn,
		Message:  "interaction driver could not render the prompt",
		ClientID: clientID,
		Extras: map[string]any{
			"prompt_type": prompt.Type,
			"error":       err.Error(),
		},
	})
	renderServerError(w, r, deps, "could not render interaction prompt", err)
}

// committingResponseWriter records whether the wrapped writer was
// committed: any WriteHeader, Write or Flush sends the response head, so
// each marks the response as belonging to the code that made the call.
// It wraps the writer only for the duration of a
// [interaction.Driver.Render] call.
type committingResponseWriter struct {
	http.ResponseWriter

	committed bool
}

func (w *committingResponseWriter) WriteHeader(status int) {
	w.committed = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *committingResponseWriter) Write(p []byte) (int, error) {
	w.committed = true
	return w.ResponseWriter.Write(p)
}

// Flush keeps a streaming Driver working through the wrapper. The
// delegation goes through [http.ResponseController] so it reaches the
// real writer whether or not that writer implements [http.Flusher]
// directly.
func (w *committingResponseWriter) Flush() {
	w.committed = true
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// Unwrap exposes the wrapped writer to [http.ResponseController] so a
// Driver reaching for a capability this wrapper does not name (deadline
// control, connection hijacking) still finds it.
func (w *committingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// stampChooserAddAccountURL fills the chooser prompt's "add another
// account" target from the persisted authorize request. The URL carries
// OP-private markers; /authorize honours them only when the browser still
// presents a session cookie for the same chooser group.
//
// The target is a bare query-parameter /authorize URL. When the deployment
// mandates PAR (RequirePAR, e.g. FAPI 2.0) /authorize rejects any request that
// lacks a request_uri before the markers are read, so such a URL is
// unfollowable. Rather than hand the chooser UI a link the OP itself will
// reject, the AddAccountURL is left empty under RequirePAR; a driver renders
// the "add account" affordance only when the field is non-empty. PAR-minted
// add-account re-entry is a separate feature, not wired in this path.
func stampChooserAddAccountURL(deps resolved, prompt *interaction.Prompt, st authn.State, reqState authorize.RequestState) error {
	if prompt == nil || prompt.Type != authn.ChooserPromptType || st.ChooserGroupID == "" {
		return nil
	}
	if deps.RequirePAR {
		return nil
	}
	data, ok := prompt.Data.(interaction.ChooserPromptData)
	if !ok {
		return nil
	}
	values, err := chooserAddAccountValues(reqState.Library, st.ChooserGroupID)
	if err != nil {
		return err
	}
	data.AddAccountURL = deps.AuthorizePath + "?" + values.Encode()
	prompt.Data = data
	return nil
}

func chooserAddAccountValues(s authorize.RequestSnapshot, chooserGroupID string) (url.Values, error) {
	values := url.Values{}
	setIfNotEmpty(values, "client_id", s.ClientID)
	setIfNotEmpty(values, "response_type", s.ResponseType)
	setIfNotEmpty(values, "redirect_uri", s.RedirectURI)
	setIfNotEmpty(values, "state", s.State)
	setIfNotEmpty(values, "nonce", s.Nonce)
	setIfNotEmpty(values, "code_challenge", s.CodeChallenge)
	setIfNotEmpty(values, "code_challenge_method", s.CodeChallengeMethod)
	setIfNotEmpty(values, "scope", strings.Join(s.Scope, " "))
	setIfNotEmpty(values, "resource", s.Resource)
	setIfNotEmpty(values, "acr_values", strings.Join(s.ACRValues, " "))
	setIfNotEmpty(values, "ui_locales", strings.Join(s.UILocales, " "))
	if s.MaxAge != nil {
		values.Set("max_age", strconv.FormatInt(int64(*s.MaxAge), 10))
	}
	setIfNotEmpty(values, "login_hint", s.LoginHint)
	setIfNotEmpty(values, "response_mode", s.ResponseMode)
	setIfNotEmpty(values, "dpop_jkt", s.DPoPJKT)
	if s.Claims != nil {
		raw, err := json.Marshal(s.Claims)
		if err != nil {
			return nil, fmt.Errorf("authorizeendpoint: marshal claims for chooser add-account: %w", err)
		}
		values.Set("claims", string(raw))
	}
	if len(s.AuthorizationDetails) > 0 {
		raw, err := json.Marshal(s.AuthorizationDetails)
		if err != nil {
			return nil, fmt.Errorf("authorizeendpoint: marshal authorization_details for chooser add-account: %w", err)
		}
		values.Set("authorization_details", string(raw))
	}
	setIfNotEmpty(values, "grant_management_action", s.GrantManagementAction)
	setIfNotEmpty(values, "grant_id", s.GrantID)
	values.Set("prompt", interaction.PromptLogin)
	values.Set("_oidc_add_account", "1")
	values.Set("_oidc_chooser_group", chooserGroupID)
	return values, nil
}

func setIfNotEmpty(values url.Values, name, value string) {
	if value != "" {
		values.Set(name, value)
	}
}

// stampPromptLocale walks the locale priority chain through the
// configured [i18n.Resolver] and stamps the result onto prompt.
// A nil resolver leaves the locale fields empty so direct callers
// (unit tests, embedders that do not need i18n) keep the legacy
// shape. The cookie is read from the request unparsed; the resolver
// performs the BCP 47 normalisation.
func stampPromptLocale(r *http.Request, deps resolved, prompt *interaction.Prompt, st authn.State, reqState authorize.RequestState) {
	if deps.LocaleResolver == nil || prompt == nil {
		return
	}
	cookieVal := ""
	if c, err := r.Cookie(cookie.LocaleProfile.Name); err == nil {
		cookieVal = c.Value
	}
	tag := deps.LocaleResolver.Resolve(r.Context(), i18n.Request{
		Subject:        st.Subject,
		UILocales:      reqState.Library.UILocales,
		Cookie:         cookieVal,
		AcceptLanguage: r.Header.Get("Accept-Language"),
	})
	prompt.Locale = string(tag)
	if len(reqState.Library.UILocales) > 0 {
		prompt.UILocalesHint = slices.Clone(reqState.Library.UILocales)
	}
	available := deps.LocaleResolver.Available()
	if len(available) > 0 {
		out := make([]string, len(available))
		for i, t := range available {
			out[i] = string(t)
		}
		prompt.LocalesAvailable = out
	}
	stampPromptText(deps.LocaleResolver, tag, prompt)
}

// stampPromptText resolves the input labels, the factor-choice option
// labels and the prompt error message in tag. It copies every slice and
// struct it writes to, because the prompt is a shallow copy of a value the
// authenticator may reuse. A key the catalogue lacks leaves its text empty.
func stampPromptText(res *i18n.Resolver, tag i18n.Tag, prompt *interaction.Prompt) {
	resolve := func(key string) string {
		if text, ok := res.Message(tag, key, nil); ok {
			return text
		}
		return ""
	}
	if len(prompt.Inputs) > 0 {
		inputs := slices.Clone(prompt.Inputs)
		for i := range inputs {
			inputs[i].LabelText = resolve(inputs[i].Label)
		}
		prompt.Inputs = inputs
	}
	if data, ok := prompt.Data.(interaction.FactorChoicePromptData); ok && len(data.Options) > 0 {
		options := slices.Clone(data.Options)
		for i := range options {
			options[i].LabelText = resolve(options[i].Label)
		}
		data.Options = options
		prompt.Data = data
	}
	if prompt.Error != nil {
		perr := *prompt.Error
		perr.Message = resolve(interaction.PromptErrorMessageKey(perr.Code))
		prompt.Error = &perr
	}
}
