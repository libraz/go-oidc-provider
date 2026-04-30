from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from http.cookiejar import CookieJar

from . import ofcs
from .paths import ISSUER, RENDER_DIR


@dataclass
class DriveOptions:
    user: str = "demo"
    password: str = "demo"
    runner_id: str | None = None
    cookies: CookieJar | None = None
    reject: bool = False
    double_visit: bool = False


_OFCS_CALLBACK_RE = re.compile(r"^https://localhost\.emobix\.co\.uk:8443/")


def _extract_field(html: bytes, name: str) -> str:
    pat = rf'name="{re.escape(name)}" value="([^"]*)"'
    m = re.search(pat.encode("ascii"), html)
    return m.group(1).decode("utf-8") if m else ""


def _save_render_html(runner_id: str, kind: str, body: bytes) -> None:
    if not body:
        return
    RENDER_DIR.mkdir(parents=True, exist_ok=True)
    n = 1
    while (RENDER_DIR / f"{runner_id}-{kind}-{n}.html").exists():
        n += 1
    (RENDER_DIR / f"{runner_id}-{kind}-{n}.html").write_bytes(body)


def _forward_implicit_bridge(redirect: str, callback_html: bytes | None) -> None:
    if callback_html is None:
        sys.stdout.write(f"[drive forward] GET {redirect}\n")
        sys.stdout.flush()
        _, _, callback_html = ofcs.get_with_redirects(redirect)
    if not callback_html:
        sys.stdout.write("[drive forward] callback page empty\n")
        return
    m = re.search(rb"implicit\\?/[A-Za-z0-9]+", callback_html)
    if not m:
        sys.stdout.write("[drive forward] callback page has no implicit-bridge URL\n")
        return
    impl = m.group(0).decode("ascii").replace("\\", "")
    alias_base = re.sub(r"/callback\?.*$", "", redirect)
    if (
        "?code=" in redirect
        or "&code=" in redirect
        or "?error=" in redirect
        or "&error=" in redirect
    ):
        # Empty values for code/state without a leading "?". OFCS parses
        # the body as a raw query string so a leading "?" would corrupt
        # the first key. FAPI 2.0 conditions require callback_params.code
        # to be a string (not JsonNull); explicit empty strings keep
        # RejectAuthCodeInUrlFragment happy.
        query = "code=&state="
    else:
        query = re.sub(r"^[^?]*\?", "", redirect)
    url = f"{alias_base}/{impl}"
    sys.stdout.write(f"[drive forward] POST {url}\n")
    status, _, _ = ofcs.request(
        "POST",
        url,
        body=query,
        headers={"Content-Type": "text/plain"},
    )
    sys.stdout.write(f"[drive forward] implicit_post={status}\n")


def drive(auth_url: str, opts: DriveOptions) -> None:
    """Walk one OFCS authorize URL through op-demo's SSR interaction."""
    # NB: empty CookieJar is falsy (its __len__ returns 0), so `or
    # CookieJar()` would silently mint a fresh jar on the first drive
    # and lose every cookie set during it. Identity check is required.
    cookies = opts.cookies if opts.cookies is not None else CookieJar()

    if opts.double_visit and opts.runner_id:
        sys.stdout.write("[drive pre] register two browser visits for reuse-before-auth\n")
        for n in (1, 2):
            status = ofcs.browser_visit(opts.runner_id, auth_url)
            sys.stdout.write(f"[drive pre] visit#{n}={status}\n")

    sys.stdout.write(f"[drive 1/3] GET {auth_url}\n")
    _, final_url, body = ofcs.get_with_redirects(auth_url, cookies=cookies)

    if opts.runner_id:
        _save_render_html(opts.runner_id, "login", body)

    if _OFCS_CALLBACK_RE.match(final_url):
        # Direct OP -> OFCS callback redirect, no SSR prompt to walk.
        # Covers both error responses (response_type missing) and
        # success responses where the OP recognised an existing session
        # (prompt=none, prompt=login on a re-authenticated cookie).
        sys.stdout.write("[drive 1/3] /authorize landed on OFCS callback (no prompt)\n")
        _forward_implicit_bridge(final_url, body)
        return

    if b'"error":' in body:
        sys.stdout.write("[drive 1/3] /authorize returned a JSON error envelope; OFCS will rule via REVIEW\n")
        return

    state_ref = _extract_field(body, "state_ref")
    csrf = _extract_field(body, "csrf_token")
    if not state_ref or not csrf or not final_url:
        sys.stdout.write("[drive] failed to parse interaction state from initial prompt\n")
        return
    interaction_url = final_url
    sys.stdout.write(f"[drive 1/3] interaction_url={interaction_url}\n")

    if opts.reject:
        sys.stdout.write(f"[drive reject] DELETE {interaction_url}\n")
        status, hdrs, _ = ofcs.request(
            "DELETE",
            interaction_url,
            cookies=cookies,
            headers={"Origin": ISSUER},
            follow_redirects=False,
        )
        loc = hdrs.get("Location") or ""
        sys.stdout.write(f"[drive reject] response={status} {loc}\n")
        if not loc or not _OFCS_CALLBACK_RE.match(loc):
            sys.stdout.write("[drive reject] no OFCS callback redirect; aborting\n")
            return
        _forward_implicit_bridge(loc, None)
        return

    sys.stdout.write(f"[drive 2/3] POST credentials (user={opts.user})\n")
    _, pwd_location, pwd_body = ofcs.post_form(
        interaction_url,
        fields={
            "state_ref": state_ref,
            "csrf_token": csrf,
            "username": opts.user,
            "password": opts.password,
        },
        headers={"Origin": ISSUER},
        cookies=cookies,
    )
    if pwd_location and _OFCS_CALLBACK_RE.match(pwd_location):
        sys.stdout.write(f"[drive 2/3] OP skipped consent (silent approval) — redirect={pwd_location}\n")
        _forward_implicit_bridge(pwd_location, None)
        return

    if opts.runner_id:
        _save_render_html(opts.runner_id, "consent", pwd_body)

    state_ref2 = _extract_field(pwd_body, "state_ref")
    csrf2 = _extract_field(pwd_body, "csrf_token")
    approved = _extract_field(pwd_body, "approved_scopes")
    if not state_ref2:
        sys.stdout.write("[drive] login failed; consent prompt missing state_ref\n")
        sys.stdout.write(pwd_body[:2000].decode("utf-8", "replace") + "\n")
        return

    sys.stdout.write(f"[drive 3/3] POST consent (approved_scopes={approved})\n")
    final_status, final_location, _ = ofcs.post_form(
        interaction_url,
        fields={
            "state_ref": state_ref2,
            "csrf_token": csrf2,
            "approved_scopes": approved,
        },
        headers={"Origin": ISSUER},
        cookies=cookies,
    )
    sys.stdout.write(f"[drive 3/3] response={final_status} {final_location or ''}\n")
    if not final_location or not _OFCS_CALLBACK_RE.match(final_location):
        sys.stdout.write("[drive] no OFCS callback redirect; aborting\n")
        return
    _forward_implicit_bridge(final_location, None)


def cmd_drive(auth_url: str) -> int:
    """Standalone `drive <url>` entry — used for ad-hoc invocations."""
    opts = DriveOptions(
        user=os.environ.get("OFCS_DEMO_USER", "demo"),
        password=os.environ.get("OFCS_DEMO_PASS", "demo"),
        runner_id=os.environ.get("OFCS_RUNNER_ID") or None,
        reject=os.environ.get("OFCS_DRIVE_REJECT", "0") == "1",
        double_visit=os.environ.get("OFCS_DRIVE_DOUBLE_VISIT", "0") == "1",
    )
    drive(auth_url, opts)
    return 0
