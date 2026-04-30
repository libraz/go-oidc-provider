from __future__ import annotations

import base64
import http.client
import json
import socket
import ssl
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from typing import Any

from .paths import OFCS_API


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


_SSL = _ssl_context()

# host:port -> (resolved_host, resolved_port). Mirrors curl --resolve so
# host.docker.internal:9443 (the issuer Docker uses internally) still
# reaches 127.0.0.1:9443 on the host without rewriting the URL — cookie
# scoping and SNI both rely on the original hostname being preserved.
_RESOLVE: dict[str, tuple[str, int]] = {
    "host.docker.internal:9443": ("127.0.0.1", 9443),
}


class _ResolvingHTTPSConnection(http.client.HTTPSConnection):
    def connect(self) -> None:  # type: ignore[override]
        target = f"{self.host}:{self.port}"
        if target in _RESOLVE:
            host, port = _RESOLVE[target]
            sock = socket.create_connection((host, port), self.timeout)
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        else:
            super().connect()


class _ResolvingHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req: urllib.request.Request):  # type: ignore[override]
        return self.do_open(_ResolvingHTTPSConnection, req, context=self._context)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        return None


def request(
    method: str,
    path: str,
    *,
    body: bytes | str | None = None,
    headers: dict[str, str] | None = None,
    base: str = OFCS_API,
    timeout: float = 30.0,
    cookies: CookieJar | None = None,
    follow_redirects: bool = True,
) -> tuple[int, dict[str, str], bytes]:
    """Issue an HTTP request and return (status, headers, body_bytes).

    Header keys are normalised to the casing urllib reports; callers should
    use `.get("Location")` etc. With follow_redirects=False, 3xx responses
    return as-is so callers can inspect the Location header.
    """
    url = path if path.startswith("http") else base.rstrip("/") + path
    data: bytes | None
    if isinstance(body, str):
        data = body.encode("utf-8")
    else:
        data = body
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    handlers: list[urllib.request.BaseHandler] = [_ResolvingHTTPSHandler(context=_SSL)]
    if not follow_redirects:
        handlers.append(_NoRedirect())
    if cookies is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(cookies))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers.items()), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items() if e.headers else {}), e.read() or b""


def request_json(method: str, path: str, **kw: Any) -> Any:
    status, _, body = request(method, path, **kw)
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def post_form(
    url: str,
    *,
    fields: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    cookies: CookieJar | None = None,
    timeout: float = 30.0,
    follow_redirects: bool = False,
) -> tuple[int, str | None, bytes]:
    """POST application/x-www-form-urlencoded fields, returning Location."""
    body = urllib.parse.urlencode(fields or {})
    merged = {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})}
    status, hdrs, resp_body = request(
        "POST",
        url,
        body=body,
        headers=merged,
        cookies=cookies,
        timeout=timeout,
        follow_redirects=follow_redirects,
    )
    return status, hdrs.get("Location"), resp_body


def get_with_redirects(
    url: str,
    *,
    cookies: CookieJar | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> tuple[int, str, bytes]:
    """GET following redirects, returning (status, final_url, body_bytes)."""
    req = urllib.request.Request(url, method="GET")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    handlers: list[urllib.request.BaseHandler] = [_ResolvingHTTPSHandler(context=_SSL)]
    if cookies is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(cookies))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.geturl(), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, getattr(e, "url", url), e.read() or b""


# ─── high-level OFCS endpoints ────────────────────────────────────────


def create_runner(test: str, plan: str, variant: str) -> dict[str, Any] | None:
    qs = urllib.parse.urlencode({"test": test, "plan": plan, "variant": variant}, safe="%")
    return request_json("POST", f"/api/runner?{qs}", headers={"Content-Type": "application/json"})


def create_plan(plan_name: str, variant: str, body: bytes) -> dict[str, Any] | None:
    qs = f"planName={urllib.parse.quote(plan_name)}&variant={variant}"
    return request_json(
        "POST",
        f"/api/plan?{qs}",
        body=body,
        headers={"Content-Type": "application/json"},
    )


def info(runner_id: str) -> dict[str, Any]:
    return request_json("GET", f"/api/info/{runner_id}") or {}


def log(runner_id: str) -> list[dict[str, Any]]:
    out = request_json("GET", f"/api/log/{runner_id}")
    return out if isinstance(out, list) else []


def runner_state(runner_id: str) -> dict[str, Any]:
    return request_json("GET", f"/api/runner/{runner_id}") or {}


def plan_modules(plan_id: str) -> list[str]:
    out = request_json("GET", f"/api/plan/{plan_id}") or {}
    mods: list[str] = []
    for entry in out.get("modules", []) or []:
        name = entry.get("testModule") or entry.get("name") or ""
        if name:
            mods.append(name)
    return mods


def browser_visit(runner_id: str, url: str) -> int:
    body = urllib.parse.urlencode({"url": url})
    status, _, _ = request(
        "POST",
        f"/api/runner/browser/{runner_id}/visit",
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return status


def upload_image(runner_id: str, placeholder: str, png_bytes: bytes) -> int:
    payload = b"data:image/png;base64," + base64.b64encode(png_bytes)
    status, _, _ = request(
        "POST",
        f"/api/log/{runner_id}/images/{placeholder}",
        body=payload,
        headers={"Content-Type": "text/plain"},
    )
    return status
