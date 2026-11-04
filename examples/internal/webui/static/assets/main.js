// Vanilla SPA driver for go-oidc-provider's SPAUI mode.
//
// The bundle reads the interaction UID from the URL, fetches the
// orchestrator's prompt JSON, renders the input fields, and POSTs
// submissions back through the same /login/state/{uid} endpoint.
// The CSRF token is taken from the prompt envelope and echoed via
// the X-CSRF-Token header (the server's __Host-oidc_csrf cookie is
// HttpOnly and unreadable from JS).
//
// Every SPA example serves this one directory rather than a copy of
// it, so the bundle handles the whole prompt vocabulary instead of
// only the prompts one example happens to raise. A branch that never
// fires — the passkey ceremony against an OP with no passkey step,
// say — costs nothing and keeps the examples from drifting apart on
// the parts they do share.

const $ = (sel) => document.querySelector(sel);
const statusEl = $("#status");
const formEl = $("#prompt-form");

const uid = location.pathname.split("/").pop();
const stateURL = `/login/state/${uid}`;

main();

async function main() {
  if (!uid) {
    fail("Missing interaction id in URL.");
    return;
  }
  try {
    const prompt = await fetchPrompt();
    if (deliverTerminal(prompt)) return;
    renderPrompt(prompt);
  } catch (err) {
    fail(err.message || String(err));
  }
}

async function fetchPrompt() {
  const r = await fetch(stateURL, {
    method: "GET",
    headers: { Accept: "application/json" },
    credentials: "same-origin",
  });
  if (!r.ok) {
    throw new Error(`Failed to load prompt (HTTP ${r.status}).`);
  }
  return r.json();
}

function renderPrompt(prompt) {
  formEl.replaceChildren();
  formEl.hidden = false;
  // Stamp the prompt type on the form. Field names alone do not
  // identify a prompt — a one-time e-mail code and a recovery code
  // both arrive as a field called "code" — so anything keying off the
  // DOM (styling, analytics, an automated walkthrough) needs the type
  // to tell them apart.
  formEl.dataset.promptType = prompt.type ?? "";
  statusEl.textContent = titleFor(prompt.type);
  applyLocale(prompt);
  renderPromptError(prompt);

  if (prompt.type === "consent.scope") {
    renderConsent(prompt);
    return;
  }

  if (prompt.type === "interaction.chooser") {
    renderChooser(prompt);
    return;
  }

  if (prompt.type === "auth.choose_factor") {
    renderFactorChoice(prompt);
    return;
  }

  if (prompt.type === "captcha") {
    renderCaptcha(prompt);
    return;
  }

  if (prompt.type === "auth.passkey") {
    renderPasskey(prompt);
    return;
  }

  for (const spec of prompt.inputs ?? []) {
    formEl.appendChild(buildField(spec));
  }
  formEl.appendChild(buildSubmit("Continue"));

  formEl.onsubmit = (ev) => {
    ev.preventDefault();
    submitForm(prompt, collectValues(formEl, prompt.inputs ?? []));
  };
}

// renderPromptError puts the rejected-submission notice above the
// fields. prompt.error.message is the OP's text in prompt.locale; it is
// empty when the OP has no locale resolver, so the bundle falls back on
// its own English line rather than showing the bare code.
function renderPromptError(prompt) {
  if (!prompt.error) return;
  const alert = document.createElement("p");
  alert.setAttribute("role", "alert");
  alert.className = "error";
  alert.textContent = prompt.error.message || "The details you entered are incorrect.";
  formEl.appendChild(alert);
}

// renderCaptcha shows a visible text field for the demo's stub
// verifier. A production deployment swaps this for the upstream
// provider's widget (Cloudflare Turnstile / hCaptcha / reCAPTCHA);
// the JS callback populates a hidden #captcha_token input. The
// FieldSpec from the server is type=hidden — overridden here so
// users can type a token manually, since the stub verifier accepts
// any non-empty string.
function renderCaptcha(prompt) {
  const data = prompt.data ?? {};
  if (data.provider) {
    const note = document.createElement("p");
    note.className = "muted";
    note.textContent = "Provider: " + data.provider;
    formEl.appendChild(note);
  }

  const label = document.createElement("label");
  const span = document.createElement("span");
  span.textContent = "Verification token (any non-empty value passes the stub)";
  label.appendChild(span);

  const input = document.createElement("input");
  input.name = "captcha_token";
  input.type = "text";
  input.required = true;
  input.autocomplete = "off";
  label.appendChild(input);
  formEl.appendChild(label);
  formEl.appendChild(buildSubmit("Continue"));

  formEl.onsubmit = (ev) => {
    ev.preventDefault();
    submitForm(prompt, { captcha_token: input.value });
  };
}

// renderPasskey answers the assertion prompt. Unlike every other prompt
// in this bundle it collects nothing from the user: the credential comes
// from navigator.credentials.get(), and the only field the server wants
// is the serialised response.
//
// The button exists because the ceremony has to be user-activated —
// browsers refuse a get() that was not triggered by a gesture, which
// rules out firing it as soon as the prompt renders.
function renderPasskey(prompt) {
  const note = document.createElement("p");
  note.className = "muted";
  note.textContent = "Your browser will ask for the passkey you registered.";
  formEl.appendChild(note);
  formEl.appendChild(buildSubmit("Use passkey"));

  formEl.onsubmit = async (ev) => {
    ev.preventDefault();
    const submit = formEl.querySelector("button[type=submit]");
    if (submit) submit.disabled = true;
    try {
      const assertion = await requestAssertion(prompt.data ?? {});
      submitForm(prompt, { response: JSON.stringify(assertion) });
    } catch (err) {
      fail(err.message || String(err));
    }
  };
}

async function requestAssertion(data) {
  // The prompt carries the challenge and the allow-list as Go []byte
  // values, which encoding/json renders as standard base64 — padded,
  // and with the +/ alphabet rather than the -_ one the WebAuthn wire
  // format uses elsewhere. Decoding is the only translation needed.
  const publicKey = {
    challenge: b64ToBytes(data.challenge),
    allowCredentials: (data.allow_credentials ?? []).map((c) => ({
      type: c.type || "public-key",
      id: b64ToBytes(c.id),
      transports: c.transports?.length ? c.transports : undefined,
    })),
    userVerification: "preferred",
    // rpId is deliberately absent: it defaults to the effective domain
    // of the page, which is the OP's own origin — the same value the
    // credential was registered under. Naming it here would add a
    // second place for it to be wrong.
  };

  const credential = await navigator.credentials.get({ publicKey });
  if (!credential) {
    throw new Error("The browser returned no assertion.");
  }
  return {
    id: credential.id,
    rawId: bytesToB64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bytesToB64url(credential.response.clientDataJSON),
      authenticatorData: bytesToB64url(credential.response.authenticatorData),
      signature: bytesToB64url(credential.response.signature),
      userHandle: credential.response.userHandle
        ? bytesToB64url(credential.response.userHandle)
        : undefined,
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

function b64ToBytes(value) {
  const raw = atob(String(value ?? ""));
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function bytesToB64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// renderConsent draws the scope list the user is being asked to
// approve. The payload members are snake_case ("scopes", "name").
//
// Reading the wrong spelling is not a cosmetic bug: the list renders
// empty, the user approves a dialogue that showed them nothing, and
// the submission carries no scope at all.
function renderConsent(prompt) {
  const data = prompt.data ?? {};
  const scopes = Array.isArray(data.scopes) ? data.scopes : [];
  const client = data.client ?? {};
  const clientName = client.name || "";
  if (clientName) {
    const who = document.createElement("p");
    who.className = "muted";
    who.textContent = clientName + " is requesting access to:";
    formEl.appendChild(who);
  }
  // Set only for a client resolved from a client ID metadata document.
  if (client.metadata_document_host) {
    const host = document.createElement("p");
    host.className = "muted";
    host.textContent = "Client information published by: " + client.metadata_document_host;
    formEl.appendChild(host);
  }
  if (client.redirect_host) {
    const redirect = document.createElement("p");
    redirect.className = "muted";
    redirect.textContent = "You will be returned to: " + client.redirect_host;
    formEl.appendChild(redirect);
  }
  if (client.redirect_loopback) {
    const warning = document.createElement("p");
    warning.setAttribute("role", "alert");
    warning.className = "error";
    warning.textContent =
      "This request returns to an application on this device. Continue only if you started it from an application you trust.";
    formEl.appendChild(warning);
  }
  const list = document.createElement("ul");
  list.className = "scopes";
  for (const s of scopes) {
    const li = document.createElement("li");
    const name = document.createElement("strong");
    name.textContent = s.name ?? "";
    li.appendChild(name);
    const description = s.description;
    if (description) {
      const desc = document.createElement("div");
      desc.className = "muted";
      desc.textContent = description;
      li.appendChild(desc);
    }
    if (s.required) {
      const req = document.createElement("span");
      req.className = "muted";
      req.textContent = " (required)";
      li.appendChild(req);
    }
    list.appendChild(li);
  }
  formEl.appendChild(list);
  formEl.appendChild(buildSubmit("Approve"));
  formEl.onsubmit = (ev) => {
    ev.preventDefault();
    const approved = scopes.map((s) => s.name ?? "").filter(Boolean).join(" ");
    submitForm(prompt, { approved_scopes: approved });
  };
}

// renderChooser draws one button per live account in the chooser
// group plus the "add another account" link. Without this branch the
// generic field loop runs, and since the chooser prompt declares its
// session_id input as hidden the screen shows a bare Continue button
// with nothing to choose.
function renderChooser(prompt) {
  const data = prompt.data ?? {};
  const accounts = Array.isArray(data.accounts) ? data.accounts : [];
  const list = document.createElement("ul");
  list.className = "scopes";
  for (const a of accounts) {
    const sessionID = a.session_id ?? "";
    const li = document.createElement("li");
    const button = document.createElement("button");
    button.type = "submit";
    button.value = sessionID;
    button.textContent = a.display_name || a.subject || sessionID;
    button.onclick = (ev) => {
      ev.preventDefault();
      submitForm(prompt, { session_id: sessionID });
    };
    li.appendChild(button);
    list.appendChild(li);
  }
  formEl.appendChild(list);

  const addURL = data.add_account_url || "";
  if (addURL) {
    const link = document.createElement("a");
    link.href = addURL;
    link.textContent = "Add another account";
    formEl.appendChild(link);
  }
  formEl.onsubmit = (ev) => ev.preventDefault();
}

// renderFactorChoice draws the factor picker as a radio group. Each
// option's label is an i18n key; keys this bundle cannot resolve (an
// external factor's own kind, say) show the kind string as-is.
function renderFactorChoice(prompt) {
  const data = prompt.data ?? {};
  const options = Array.isArray(data.options) ? data.options : [];
  options.forEach((opt, i) => {
    const label = document.createElement("label");
    const input = document.createElement("input");
    input.type = "radio";
    input.name = "factor";
    input.value = opt.kind;
    input.required = true;
    input.checked = i === 0;
    label.appendChild(input);
    const span = document.createElement("span");
    span.textContent = opt.label_text || factorLabelFor(opt.label) || opt.kind;
    label.appendChild(span);
    formEl.appendChild(label);
  });
  formEl.appendChild(buildSubmit("Continue"));
  formEl.onsubmit = (ev) => {
    ev.preventDefault();
    const chosen = new FormData(formEl).get("factor");
    submitForm(prompt, { factor: typeof chosen === "string" ? chosen : "" });
  };
}

function factorLabelFor(key) {
  switch (key) {
    case "auth.factor.password":      return "Password";
    case "auth.factor.passkey":       return "Passkey";
    case "auth.factor.totp":          return "Authenticator app";
    case "auth.factor.email_otp":     return "Email code";
    case "auth.factor.recovery_code": return "Recovery code";
    default:                          return "";
  }
}

function buildField(spec) {
  const label = document.createElement("label");
  const span = document.createElement("span");
  const labelKey = spec.label || "";
  span.textContent = spec.label_text || labelFor(labelKey) || spec.name || labelKey;
  label.appendChild(span);

  const input = document.createElement("input");
  input.name = spec.name;
  input.type = inputTypeFor(spec.kind);
  input.required = !!spec.required;
  if (spec.min_len) input.minLength = spec.min_len;
  if (spec.max_len) input.maxLength = spec.max_len;
  if (spec.pattern) input.pattern = spec.pattern;
  input.autocomplete = autocompleteFor(spec.name);
  label.appendChild(input);
  return label;
}

function buildSubmit(text) {
  const btn = document.createElement("button");
  btn.type = "submit";
  btn.textContent = text;
  return btn;
}

function collectValues(form, inputs) {
  const data = new FormData(form);
  const out = {};
  for (const spec of inputs) {
    const name = spec.name;
    const v = data.get(name);
    if (typeof v === "string") out[name] = v;
  }
  return out;
}

async function submitForm(prompt, values) {
  const submit = formEl.querySelector("button[type=submit]");
  if (submit) submit.disabled = true;
  statusEl.removeAttribute("data-error");
  statusEl.textContent = "Submitting…";

  // The prompt envelope's state_ref MUST round-trip exactly. Wrap the
  // values in a {state_ref, values} envelope per
  // op/interaction.FormSubmission.
  const body = {
    state_ref: prompt.state_ref,
    values,
  };
  let r;
  try {
    r = await fetch(stateURL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": prompt.csrf_token ?? "",
        Accept: "application/json",
      },
      credentials: "same-origin",
      body: JSON.stringify(body),
    });
  } catch (err) {
    fail(err.message || String(err));
    return;
  }

  if (!r.ok) {
    fail(`Submission rejected (HTTP ${r.status}).`);
    return;
  }
  const next = await r.json();
  if (deliverTerminal(next)) return;
  if (next && next.type) {
    renderPrompt(next);
    return;
  }
  fail("Unexpected server response.");
}

// deliverTerminal hands a terminal authorization response to the
// document and reports whether it did. Neither shape can be delivered
// by the fetch() this SPA talks to the OP with — a cross-origin
// redirect is opaque to it, and an auto-submitting HTML document cannot
// execute inside it — so the OP hands both over as envelopes the SPA
// replays at document level instead.
function deliverTerminal(envelope) {
  if (!envelope || typeof envelope.type !== "string") return false;
  if (envelope.type === "redirect" && envelope.location) {
    window.location.href = envelope.location;
    return true;
  }
  if (envelope.type === "form_post" && envelope.action) {
    submitTerminalForm(envelope.action, envelope.fields ?? {});
    return true;
  }
  return false;
}

// submitTerminalForm rebuilds the Form Post Response Mode submission:
// one hidden input per response parameter, posted to the RP's
// redirect_uri at document level. It is the same request the page the
// OP renders on the non-SPA surface auto-submits, and it covers the
// JARM form_post.jwt mode too — that mode is the same shape with a lone
// "response" field.
function submitTerminalForm(action, fields) {
  const form = document.createElement("form");
  form.method = "post";
  form.action = action;
  for (const [name, value] of Object.entries(fields)) {
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = name;
    input.value = value;
    form.appendChild(input);
  }
  document.body.appendChild(form);
  form.submit();
}

function inputTypeFor(kind) {
  // FieldKind arrives as its text name: text, password, otp_code, email, hidden.
  switch (kind) {
    case "password": return "password";
    case "email": return "email";
    case "hidden": return "hidden";
    default: return "text";
  }
}

function autocompleteFor(name) {
  switch (name) {
    case "username": return "username";
    case "password": return "current-password";
    case "code":     return "one-time-code";
    case "email":    return "email";
    default:         return "off";
  }
}

function titleFor(type) {
  switch (type) {
    case "auth.password":          return "Sign in with your password";
    case "auth.totp":              return "Enter your authenticator code";
    case "auth.email_otp.send":    return "Send a code to your email";
    case "auth.email_otp.verify":  return "Enter the code from your email";
    case "auth.recovery_code":     return "Enter a recovery code";
    case "auth.passkey":           return "Use a passkey";
    case "captcha":                return "Verify you are human";
    case "consent.scope":          return "Authorize access";
    case "interaction.chooser":    return "Choose an account";
    case "auth.choose_factor":     return "Choose how to sign in";
    default:                       return type || "Continue";
  }
}

// labelFor mirrors titleFor for FieldSpec.Label values. The library
// emits these as i18n keys and leaves resolution to the SPA; this
// demo ships a minimal English table so per-field labels render as
// "Username" / "Password" / "Authenticator code" rather than the
// raw "auth.password.username" / "auth.totp.code" strings.
function labelFor(key) {
  switch (key) {
    case "auth.password.username":  return "Username";
    case "auth.password.password":  return "Password";
    case "auth.totp.code":          return "Authenticator code";
    case "auth.email_otp.email":    return "Email address";
    case "auth.email_otp.code":     return "Email code";
    case "auth.recovery_code.code": return "Recovery code";
    case "auth.passkey.response":   return "Passkey response";
    case "auth.captcha.token":      return "Verification token";
    default:                        return "";
  }
}

function fail(msg) {
  statusEl.dataset.error = "1";
  statusEl.textContent = msg;
  formEl.hidden = true;
}

// applyLocale stamps the OP-resolved locale onto <html lang> so the
// browser picks the right hyphenation / spell-check rules and any
// downstream Intl API observes the active language. The OP runs the
// locale priority chain (PreferredLocaleStore → ui_locales → cookie →
// Accept-Language → default) before [Driver.Render]; the SPA never
// re-runs the chain. Embedders that want to override the OP's pick
// consult prompt.ui_locales_hint (the RP's raw list) instead.
function applyLocale(prompt) {
  const locale = prompt && prompt.locale;
  if (typeof locale === "string" && locale !== "") {
    document.documentElement.lang = locale;
  }
}
