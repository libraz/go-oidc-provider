// Browser half of the registration ceremony.
//
// Two requests with navigator.credentials.create() in between. The
// server hands back PublicKeyCredentialCreationOptions as JSON, which
// has to be turned back into the ArrayBuffers the WebAuthn API expects —
// JSON has no byte-string type, so every buffer travels as base64url and
// is decoded here.

const form = document.querySelector("#enrol-form");
const statusEl = document.querySelector("#status");

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  try {
    await register(new FormData(form));
  } catch (err) {
    report(err.message || String(err), true);
  } finally {
    button.disabled = false;
  }
});

async function register(data) {
  report("Requesting a challenge…");

  const begun = await postJSON("/account/register/begin", {
    username: data.get("username"),
    password: data.get("password"),
  });

  // The server returns the object the API expects under "publicKey",
  // so the only work here is the base64url → ArrayBuffer decoding.
  const publicKey = decodeCreationOptions(begun.publicKey);

  report("Waiting for your authenticator…");
  const credential = await navigator.credentials.create({ publicKey });
  if (!credential) {
    throw new Error("The browser returned no credential.");
  }

  report("Storing the credential…");
  const stored = await postJSON("/account/register/finish", credentialToJSON(credential));
  report(`Registered. Credential id: ${stored.credential_id}`);
}

// decodeCreationOptions converts the byte-carrying members of the
// creation options from base64url strings to ArrayBuffers. Only three
// members are buffers; everything else is passed through untouched so a
// future addition on the server side does not need a change here.
function decodeCreationOptions(options) {
  const out = { ...options };
  out.challenge = b64urlToBytes(options.challenge);
  out.user = { ...options.user, id: b64urlToBytes(options.user.id) };
  if (Array.isArray(options.excludeCredentials)) {
    out.excludeCredentials = options.excludeCredentials.map((c) => ({
      ...c,
      id: b64urlToBytes(c.id),
    }));
  }
  return out;
}

// credentialToJSON renders the created credential the way the WebAuthn
// Level 3 toJSON() method does. It is written out rather than called
// because toJSON is recent enough that a browser new enough to have
// passkeys may still lack it, and the shape is four fields.
function credentialToJSON(credential) {
  return {
    id: credential.id,
    rawId: bytesToB64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bytesToB64url(credential.response.clientDataJSON),
      attestationObject: bytesToB64url(credential.response.attestationObject),
      transports: credential.response.getTransports
        ? credential.response.getTransports()
        : [],
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

async function postJSON(url, body) {
  return readResponse(
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body),
    }),
  );
}

async function readResponse(r) {
  const payload = await r.json().catch(() => ({}));
  if (!r.ok) {
    throw new Error(payload.error || `Request failed (HTTP ${r.status}).`);
  }
  return payload;
}

function b64urlToBytes(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(padded);
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

function report(message, isError = false) {
  statusEl.textContent = message;
  if (isError) {
    statusEl.dataset.error = "1";
  } else {
    statusEl.removeAttribute("data-error");
  }
}
