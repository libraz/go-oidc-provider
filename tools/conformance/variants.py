from __future__ import annotations

import json
import os
import urllib.parse

from . import ofcs

_DEFAULT = {
    "client_auth_type": "client_secret_basic",
    "response_type": "code",
    "response_mode": "default",
}

_CLIENT_SECRET_POST = {
    "client_auth_type": "client_secret_post",
    "response_type": "code",
    "response_mode": "default",
}

_FAPI2_BASELINE = {
    "client_auth_type": "private_key_jwt",
    "sender_constrain": "dpop",
    "fapi_profile": "plain_fapi",
    "openid": "openid_connect",
    "fapi_request_method": "unsigned",
    "fapi_response_mode": "plain_response",
}

# Per-process cache of plan_id -> {module: variant_dict}. The plan
# module list is immutable once seeded so a single fetch suffices for
# the lifetime of a baseline run.
_PLAN_VARIANT_CACHE: dict[str, dict[str, dict[str, str]]] = {}


def _encode(variant: dict[str, str]) -> str:
    return urllib.parse.quote(json.dumps(variant, separators=(",", ":")))


def select(module: str, plan_id: str | None = None) -> str:
    """Return the urlencoded JSON variant string for the module.

    When plan_id is given, OFCS's per-module pre-populated variant is
    used verbatim. That keeps the runner in sync with whatever
    variants the plan hardcodes (form_post, dynamic_client, signed
    request objects, etc.) without static per-plan tables.

    BATCH_VARIANT and the legacy module-name heuristics remain as
    fallbacks for the bash driver and for callers that have no
    plan_id (e.g. ad-hoc `batch` invocations).
    """
    override = os.environ.get("BATCH_VARIANT")
    if override:
        return override
    if plan_id:
        cache = _PLAN_VARIANT_CACHE.get(plan_id)
        if cache is None:
            cache = ofcs.plan_module_variants(plan_id)
            _PLAN_VARIANT_CACHE[plan_id] = cache
        v = cache.get(module)
        if v:
            return _encode(v)
    if module.startswith("fapi2-security-profile-id2-") or module.startswith(
        "fapi2-message-signing-id1-"
    ):
        return _encode(_FAPI2_BASELINE)
    if module == "oidcc-server-client-secret-post":
        return _encode(_CLIENT_SECRET_POST)
    return _encode(_DEFAULT)
