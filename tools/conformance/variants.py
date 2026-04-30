from __future__ import annotations

import json
import os
import urllib.parse

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


def select(module: str) -> str:
    """Return the urlencoded JSON variant string for the module.

    Honours BATCH_VARIANT for ad-hoc overrides (kept for parity with
    the bash driver), otherwise picks per-module heuristics.
    """
    override = os.environ.get("BATCH_VARIANT")
    if override:
        return override
    if module.startswith("fapi2-security-profile-id2-") or module.startswith(
        "fapi2-message-signing-id1-"
    ):
        return urllib.parse.quote(json.dumps(_FAPI2_BASELINE, separators=(",", ":")))
    if module == "oidcc-server-client-secret-post":
        return urllib.parse.quote(json.dumps(_CLIENT_SECRET_POST, separators=(",", ":")))
    return urllib.parse.quote(json.dumps(_DEFAULT, separators=(",", ":")))
