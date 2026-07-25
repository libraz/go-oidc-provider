//go:build example

package main

// The pages are deliberately built for a hard Content-Security-Policy:
// default-src 'none' with style-src 'self'. No script, no web font, no
// image can load, so the whole visual language has to come out of one
// same-origin stylesheet and the system's own typefaces.
//
// That constraint sets the register rather than fighting it. This is
// credential infrastructure read mostly by engineers, so the pages are
// drawn like an instrument panel: monospaced throughout, hairline rules,
// square corners, a measured label column, and a single signal colour that
// marks rather than decorates. Nothing is centred in a card, nothing is
// rounded, and the only motion is one staggered reveal on load.

// promptTemplates renders the OP's prompts. Two templates cover the three
// prompt types the application handles: credential factors share one form
// because the orchestrator already describes their fields, while consent
// needs the scope list.
//
// html/template escapes every interpolated value, which matters most on
// the consent screen: the client name and scope descriptions arrive from
// client registration and are attacker-influenced under dynamic
// registration.
//
// The consent screen offers approval per scope rather than the all-or-
// nothing hidden field the bundled driver emits — granular consent is one
// of the reasons to own the UI at all. It has no Deny button: cancelling an
// interaction is a DELETE on the interaction URL, which a page under
// default-src 'none' cannot issue without script. A member who does not
// want to approve leaves the page, and the interaction expires.
const promptTemplates = `
{{define "head"}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<header class="bar"><span class="mark">go-oidc-provider</span><span class="rule"></span></header>
<main class="sheet">
<h1 class="title">{{.Heading}}</h1>
{{end}}

{{define "foot"}}
</main>
</body>
</html>
{{end}}

{{define "form"}}{{template "head" .}}
{{if .Lead}}<p class="lead">{{.Lead}}</p>{{end}}
<form method="post" autocomplete="on" class="stack">
<input type="hidden" name="state_ref" value="{{.StateRef}}">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
{{range .Fields}}
<div class="field">
  <label for="f-{{.Name}}">{{.Label}}</label>
  <input id="f-{{.Name}}" type="{{.InputType}}" name="{{.Name}}"
         {{if .AutoComplete}}autocomplete="{{.AutoComplete}}"{{end}}
         {{if .Required}}required{{end}}>
</div>
{{end}}
<div class="row"><button type="submit">Continue</button></div>
</form>
{{template "foot" .}}{{end}}

{{define "consent"}}{{template "head" .}}
<p class="lead"><span class="party">{{.Client}}</span> is requesting access to your account.</p>
<form method="post" class="stack">
<input type="hidden" name="state_ref" value="{{.StateRef}}">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<ul class="grants">
{{range .Scopes}}
<li>
  <label class="grant-row">
    <input type="checkbox" name="scope" value="{{.Name}}" checked{{if .Required}} disabled{{end}}>
    <span class="grant-text">
      <span class="grant">{{.Name}}</span>
      {{if .Description}}<span class="grant-note">{{.Description}}</span>{{end}}
      {{if .Required}}<span class="grant-note">Required by this application.</span>{{end}}
    </span>
  </label>
  {{if .Required}}<input type="hidden" name="scope" value="{{.Name}}">{{end}}
</li>
{{end}}
</ul>
<div class="row"><button type="submit">Allow</button></div>
</form>
{{template "foot" .}}{{end}}
`

// appTemplates renders the application's own pages: the ones outside the
// OP's interaction flow, where the application authenticates the member
// against its own session cookie rather than through the orchestrator.
//
// Each page opens and closes with the shared chrome. Template names are
// global in html/template, so one "layout" delegating to a per-page "body"
// would need a separate parse tree per page; two partial calls cost less
// than that indirection.
const appTemplates = `
{{define "open"}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<header class="bar"><span class="mark">go-oidc-provider</span><span class="rule"></span></header>
<main class="sheet">
<h1 class="title">{{.Title}}</h1>
{{if .Error}}<p class="flag flag-bad">{{.Error}}</p>{{end}}
{{if .Notice}}<p class="flag flag-ok">{{.Notice}}</p>{{end}}
{{end}}

{{define "close"}}
</main>
</body>
</html>
{{end}}

{{define "home"}}{{template "open" .}}
<p class="lead">An OpenID Connect Provider whose accounts belong to the
application, not to the library. Sign up here, then let the relying party
sign you in.</p>
{{if .Member}}
<dl class="spec">
  <dt>signed in</dt><dd>{{.Member.Email}}</dd>
</dl>
<nav class="links">
  <a href="/account">Account</a>
  <a href="{{.RPURL}}">Relying party</a>
</nav>
<form method="post" action="/signout" class="stack">
  <div class="row"><button type="submit" class="ghost">Sign out</button></div>
</form>
{{else}}
<nav class="links">
  <a href="/signup">Create an account</a>
  <a href="{{.RPURL}}">Relying party</a>
</nav>
{{end}}
{{template "close" .}}{{end}}

{{define "signup"}}{{template "open" .}}
<form method="post" action="/signup" autocomplete="on" class="stack">
<div class="field">
  <label for="s-email">Email address</label>
  <input id="s-email" type="email" name="email" autocomplete="username" value="{{.Form.Email}}" required>
</div>
<div class="field">
  <label for="s-name">Display name</label>
  <input id="s-name" type="text" name="display_name" autocomplete="name" value="{{.Form.DisplayName}}" required>
</div>
<div class="field">
  <label for="s-pass">Password</label>
  <input id="s-pass" type="password" name="password" autocomplete="new-password" minlength="8" required>
  <p class="hint">At least 8 characters.</p>
</div>
<div class="row"><button type="submit">Create account</button></div>
</form>
{{template "close" .}}{{end}}

{{define "account"}}{{template "open" .}}
<dl class="spec">
  <dt>email</dt><dd>{{.Member.Email}}</dd>
  <dt>display name</dt><dd>{{.Member.DisplayName}}</dd>
  <dt>subject</dt><dd class="mono-wrap">{{.Member.ID}}</dd>
  <dt>two-factor</dt>
  <dd>{{if .Member.TOTPEnabled}}<span class="on">enabled</span>{{else}}<span class="off">not set up</span>{{end}}</dd>
</dl>
{{if not .Member.TOTPEnabled}}
<nav class="links"><a href="/account/totp">Set up an authenticator app</a></nav>
{{end}}
<h2 class="subtitle">Change password</h2>
<form method="post" action="/account/password" class="stack">
<div class="field">
  <label for="a-pass">New password</label>
  <input id="a-pass" type="password" name="password" autocomplete="new-password" minlength="8" required>
</div>
<div class="row"><button type="submit">Update password</button></div>
</form>
{{template "close" .}}{{end}}

{{define "enrol"}}{{template "open" .}}
<p class="lead">Add this secret to your authenticator app, then confirm the
current code. Nothing is saved until the code checks out.</p>
<dl class="spec">
  <dt>secret</dt><dd class="mono-wrap">{{.Secret}}</dd>
  <dt>otpauth uri</dt><dd><pre class="blob">{{.OTPAuthURI}}</pre></dd>
</dl>
<form method="post" action="/account/totp" class="stack">
<div class="field">
  <label for="t-code">Six-digit code</label>
  <input id="t-code" type="text" name="code" inputmode="numeric" autocomplete="one-time-code"
         pattern="[0-9]{6}" maxlength="6" required>
</div>
<div class="row"><button type="submit">Confirm</button></div>
</form>
{{template "close" .}}{{end}}
`

// appCSS is served at /assets/app.css. It is a stylesheet rather than an
// inline <style> block so the policy can stay at style-src 'self' instead
// of admitting 'unsafe-inline'.
const appCSS = `
:root {
  color-scheme: dark light;

  --ink:        #0b0c0e;
  --ink-raised: #131519;
  --line:       #23262c;
  --text:       #e4e6ea;
  --text-dim:   #838a96;
  --signal:     #b8f135;
  --bad:        #ff6b5a;

  --measure: 34rem;
  --gutter: clamp(1.25rem, 5vw, 3.5rem);
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
          "Liberation Mono", monospace;
}

@media (prefers-color-scheme: light) {
  :root {
    --ink:        #f4f4f2;
    --ink-raised: #ffffff;
    --line:       #d5d6d2;
    --text:       #14161a;
    --text-dim:   #63676f;
    --signal:     #4d7a00;
    --bad:        #b3261e;
  }
}

*, *::before, *::after { box-sizing: border-box; }

body {
  margin: 0;
  padding: 0 var(--gutter) 5rem;
  background-color: var(--ink);
  /* A hairline grid drawn in CSS: atmosphere without an image request,
     which the policy would block anyway. */
  background-image:
    repeating-linear-gradient(to right,  var(--line) 0 1px, transparent 1px 6.25rem),
    repeating-linear-gradient(to bottom, var(--line) 0 1px, transparent 1px 6.25rem);
  background-position: calc(var(--gutter) * -1) 0;
  color: var(--text);
  font-family: var(--mono);
  font-size: 15px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}

/* Masthead: a wordmark and a rule that runs to the edge of the viewport,
   so the page reads as anchored rather than floated. */
.bar {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 1.75rem 0 0;
  margin-bottom: 4rem;
}
.mark {
  font-size: 0.7rem;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  color: var(--text-dim);
  white-space: nowrap;
}
.rule { flex: 1; height: 1px; background: var(--line); }

/* Content sits on a measured column at the left of the grid, not centred
   in a card. The width is capped for readability, not for symmetry. */
.sheet { max-width: var(--measure); }

.title {
  margin: 0 0 1.5rem;
  font-size: 1.5rem;
  font-weight: 500;
  letter-spacing: -0.02em;
  line-height: 1.25;
}
.subtitle {
  margin: 3rem 0 1.25rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--line);
  font-size: 0.7rem;
  font-weight: 500;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  color: var(--text-dim);
}
.lead { margin: 0 0 2.25rem; color: var(--text-dim); }
.party { color: var(--text); }

/* Forms ------------------------------------------------------------- */

.stack { margin: 0; }
.field { margin-bottom: 1.5rem; }

label {
  display: block;
  margin-bottom: 0.5rem;
  font-size: 0.7rem;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--text-dim);
}

input[type=text], input[type=email], input[type=password] {
  display: block;
  width: 100%;
  padding: 0.7rem 0.85rem;
  font: inherit;
  color: var(--text);
  background: var(--ink-raised);
  border: 1px solid var(--line);
  border-radius: 0;
}
input::placeholder { color: var(--text-dim); }
input:hover { border-color: var(--text-dim); }
input:focus-visible {
  outline: none;
  border-color: var(--signal);
  box-shadow: inset 2px 0 0 var(--signal);
}
/* Square corners are what make a single-side marker legitimate here; on a
   rounded field the straight edge would fight the curve. */

.hint { margin: 0.5rem 0 0; font-size: 0.8rem; color: var(--text-dim); }

.row { display: flex; margin-top: 2rem; }

button {
  padding: 0.7rem 1.4rem;
  font: inherit;
  font-size: 0.8rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--ink);
  background: var(--signal);
  border: 1px solid var(--signal);
  border-radius: 0;
  cursor: pointer;
  transition: background-color 120ms ease, color 120ms ease;
}
button:hover { background: transparent; color: var(--signal); }
button:focus-visible { outline: 2px solid var(--signal); outline-offset: 2px; }

button.ghost {
  color: var(--text-dim);
  background: transparent;
  border-color: var(--line);
}
button.ghost:hover { color: var(--text); border-color: var(--text-dim); }

/* Consent ------------------------------------------------------------ */

.grants { margin: 0 0 2.25rem; padding: 0; list-style: none; }
.grants li {
  padding: 0.85rem 0 0.85rem 1rem;
  border-top: 1px solid var(--line);
  border-left: 2px solid var(--signal);
}
.grants li:last-child { border-bottom: 1px solid var(--line); }

/* The scope row is a label wrapping its own checkbox, so the whole row is
   the hit target. It overrides the uppercase-caption label rule, which is
   for field captions rather than for a line of readable text. */
.grant-row {
  display: flex;
  gap: 0.75rem;
  margin: 0;
  font-size: inherit;
  letter-spacing: normal;
  text-transform: none;
  color: var(--text);
  cursor: pointer;
}
.grant-row input[type=checkbox] {
  flex: none;
  margin: 0.4rem 0 0;
  accent-color: var(--signal);
}
.grant-row:has(input:disabled) { cursor: default; color: var(--text-dim); }
.grant-text { display: block; }
.grant { display: block; }
.grant-note { display: block; margin-top: 0.15rem; font-size: 0.85rem; color: var(--text-dim); }

/* Description lists read as a spec sheet: a narrow label column against a
   value column, aligned on the same baseline grid as everything else. */

.spec { display: grid; grid-template-columns: 9rem 1fr; gap: 0.75rem 1.5rem; margin: 0 0 2.25rem; }
dt {
  font-size: 0.7rem;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--text-dim);
  padding-top: 0.2rem;
}
dd { margin: 0; overflow-wrap: anywhere; }
.mono-wrap { color: var(--signal); overflow-wrap: anywhere; }
.on { color: var(--signal); }
.off { color: var(--text-dim); }

.blob {
  margin: 0;
  padding: 0.75rem 0.85rem;
  overflow-x: auto;
  font: inherit;
  font-size: 0.8rem;
  background: var(--ink-raised);
  border: 1px solid var(--line);
}

/* Messages: a full border plus a tint, never a lone side stripe. */
.flag {
  margin: 0 0 2rem;
  padding: 0.7rem 0.85rem;
  font-size: 0.85rem;
  border: 1px solid;
}
.flag-ok  { color: var(--signal); border-color: color-mix(in srgb, var(--signal) 40%, transparent);
            background: color-mix(in srgb, var(--signal) 8%, transparent); }
.flag-bad { color: var(--bad); border-color: color-mix(in srgb, var(--bad) 40%, transparent);
            background: color-mix(in srgb, var(--bad) 8%, transparent); }

.links { display: flex; flex-wrap: wrap; gap: 1.5rem; margin-bottom: 2rem; }
a {
  color: var(--text);
  text-decoration: none;
  border-bottom: 1px solid var(--signal);
  padding-bottom: 2px;
}
a:hover { color: var(--signal); }
a:focus-visible { outline: 2px solid var(--signal); outline-offset: 3px; }

/* One staggered reveal on load; the page is short enough that scattering
   micro-interactions through it would only add noise. */
.bar, .title, .lead, .flag, .spec, .grants, .stack, .links, .subtitle {
  animation: rise 380ms cubic-bezier(0.22, 0.61, 0.36, 1) backwards;
}
.title    { animation-delay: 40ms; }
.lead,
.flag     { animation-delay: 80ms; }
.spec,
.grants   { animation-delay: 120ms; }
.stack,
.links    { animation-delay: 160ms; }
.subtitle { animation-delay: 200ms; }

@keyframes rise {
  from { opacity: 0; transform: translateY(6px); }
  to   { opacity: 1; transform: none; }
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 1ms !important;
    animation-delay: 0ms !important;
    transition-duration: 1ms !important;
  }
}
`
