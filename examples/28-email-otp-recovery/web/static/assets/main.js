// Vanilla SPA driver for go-oidc-provider's WithSPAUI seam.
//
// The bundle reads the interaction UID from the URL, fetches the
// orchestrator's prompt JSON, renders the input fields, and POSTs
// submissions back through the same /login/state/{uid} endpoint.
// The CSRF token is taken from the prompt envelope and echoed via
// the X-CSRF-Token header (the server's __Host-oidc_csrf cookie is
// HttpOnly and unreadable from JS).

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
  // Stamp the prompt type on the form. This flow is the first one where
  // the field names alone do not identify the prompt: the e-mail code and
  // the recovery code both arrive as a field called "code", so anything
  // keying off the DOM — styling, analytics, an automated walkthrough —
  // needs the type to tell them apart.
  formEl.dataset.promptType = prompt.type ?? "";
  statusEl.textContent = titleFor(prompt.type);
  applyLocale(prompt);

  if (prompt.type === "consent.scope") {
    renderConsent(prompt);
    return;
  }

  if (prompt.type === "captcha") {
    renderCaptcha(prompt);
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

// renderCaptcha shows a visible text field for the demo's stub
// verifier. A production deployment swaps this for the upstream
// provider's widget (Cloudflare Turnstile / hCaptcha / reCAPTCHA);
// the JS callback populates a hidden #captcha_token input. The
// FieldSpec from the server is type=hidden — overridden here so
// users can type a token manually, since the stub verifier accepts
// any non-empty string.
function renderCaptcha(prompt) {
  const data = prompt.data ?? {};
  if (data.Provider || data.provider) {
    const note = document.createElement("p");
    note.className = "muted";
    note.textContent = "Provider: " + (data.Provider || data.provider);
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

function renderConsent(prompt) {
  const data = prompt.data ?? {};
  const scopes = Array.isArray(data.scopes) ? data.scopes : [];
  const list = document.createElement("ul");
  list.className = "scopes";
  for (const s of scopes) {
    const li = document.createElement("li");
    const name = document.createElement("strong");
    name.textContent = s.name;
    li.appendChild(name);
    if (s.description) {
      const desc = document.createElement("div");
      desc.className = "muted";
      desc.textContent = s.description;
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
    const approved = scopes.map((s) => s.name).join(" ");
    submitForm(prompt, { approved_scopes: approved });
  };
}

function buildField(spec) {
  const label = document.createElement("label");
  const span = document.createElement("span");
  const labelKey = spec.Label || spec.label || "";
  span.textContent = labelFor(labelKey) || spec.Name || spec.name || labelKey;
  label.appendChild(span);

  const input = document.createElement("input");
  input.name = spec.Name || spec.name;
  input.type = inputTypeFor(spec.Kind ?? spec.kind);
  input.required = !!(spec.Required ?? spec.required);
  if (spec.MinLen ?? spec.minLen) input.minLength = spec.MinLen ?? spec.minLen;
  if (spec.MaxLen ?? spec.maxLen) input.maxLength = spec.MaxLen ?? spec.maxLen;
  if (spec.Pattern ?? spec.pattern) input.pattern = spec.Pattern ?? spec.pattern;
  input.autocomplete = autocompleteFor(spec.Name || spec.name);
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
    const name = spec.Name || spec.name;
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

  // FieldKind values arrive as integers per Go encoding; the prompt
  // envelope's state_ref MUST round-trip exactly. Spread the prompt's
  // declared values into a {state_ref, values} envelope per
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
  // The OP rewrites the orchestrator's terminal 302 into this
  // envelope so the SPA can navigate at the document level
  // (cross-origin fetch cannot follow the RP-callback redirect).
  if (next && next.type === "redirect" && next.location) {
    window.location.href = next.location;
    return;
  }
  if (next && next.type) {
    renderPrompt(next);
    return;
  }
  fail("Unexpected server response.");
}

function inputTypeFor(kind) {
  // FieldKind iota: 0=text, 1=password, 2=otp, 3=email, 4=hidden.
  switch (kind) {
    case 1: return "password";
    case 2: return "text";
    case 3: return "email";
    case 4: return "hidden";
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
// §L.2 priority chain (PreferredLocaleStore → ui_locales → cookie →
// Accept-Language → default) before [Driver.Render]; the SPA never
// re-runs the chain. Embedders that want to override the OP's pick
// consult prompt.ui_locales_hint (the RP's raw list) instead.
function applyLocale(prompt) {
  const locale = prompt && prompt.locale;
  if (typeof locale === "string" && locale !== "") {
    document.documentElement.lang = locale;
  }
}
