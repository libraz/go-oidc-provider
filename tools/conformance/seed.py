from __future__ import annotations

import json
import sys
import urllib.parse
from typing import Any

from . import ofcs
from .paths import CERTS, PLAN_IDS_FILE, PLANS_DIR

# Plan name strings are the OFCS internal "test plan" identifier the
# /plan REST endpoint expects in the planName= query parameter. The
# names below are the canonical IDs the OFCS UI exposes when a user
# selects the plan by hand. If a name ever drifts (OFCS renames a
# plan in a release bump), seed-plans surfaces the failure as
# "[seed] failed for <file>: ..." and the operator updates this list.
_PLANS = [
    ("oidcc-basic.json", "oidcc-basic-certification-test-plan"),
    ("oidcc-config.json", "oidcc-config-certification-test-plan"),
    ("oidcc-formpost.json", "oidcc-formpost-basic-certification-test-plan"),
    ("oidcc-rp-initiated-logout.json", "oidcc-rp-initiated-logout-certification-test-plan"),
    ("oidcc-back-channel-logout.json", "oidcc-back-channel-rp-initiated-logout-certification-test-plan"),
    ("fapi2-baseline.json", "fapi2-security-profile-id2-test-plan"),
    ("fapi2-message-signing.json", "fapi2-message-signing-id1-test-plan"),
    ("fapi-ciba.json", "fapi-ciba-id1-test-plan"),
]


def _massage_plan(plan_key: str, cfg: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """Apply per-plan rewrites and return (body, variant_dict)."""
    variant = cfg.pop("variant", None) or {}
    if plan_key.startswith("fapi2-"):
        for slot, base in (("mtls", "fapi-client"), ("mtls2", "fapi-client-2")):
            cert_p = CERTS / f"{base}.cert.pem"
            key_p = CERTS / f"{base}.key.pem"
            if cert_p.exists() and key_p.exists():
                cfg[slot] = {"cert": cert_p.read_text(), "key": key_p.read_text()}
        # The Baseline plan hardcodes fapi_request_method=unsigned and
        # fapi_response_mode=plain_response — passing them at plan
        # creation is rejected with "Variant '...' has been set by user
        # but test plan already has them set". Message Signing instead
        # requires both at plan-level (signed_non_repudiation + jarm) so
        # the modules apply the right shape. Filter for Baseline only.
        if plan_key == "fapi2-baseline.json":
            for drop in ("fapi_request_method", "fapi_response_mode"):
                variant.pop(drop, None)
    elif plan_key == "oidcc-basic.json" and not variant:
        # The oidcc-basic plan refuses creation without server_metadata
        # and client_registration variant. The seed JSON omits them
        # because the OFCS UI fills them in interactively; supply the
        # defaults here.
        variant = {
            "server_metadata": "discovery",
            "client_registration": "static_client",
        }
    return cfg, variant


def cmd_seed_plans() -> int:
    plan_ids: dict[str, dict[str, str]] = {}
    for plan_key, plan_name in _PLANS:
        plan_file = PLANS_DIR / plan_key
        if not plan_file.exists():
            sys.stdout.write(f"[seed] missing {plan_file}; skipping\n")
            continue
        cfg = json.loads(plan_file.read_text())
        alias = cfg.get("alias", "")
        body, variant = _massage_plan(plan_key, cfg)
        encoded_variant = urllib.parse.quote(json.dumps(variant))
        resp = ofcs.create_plan(plan_name, encoded_variant, json.dumps(body).encode())
        if not resp or not resp.get("id"):
            sys.stderr.write(f"[seed] failed for {plan_key}: {str(resp)[:200]}\n")
            continue
        plan_id = resp["id"]
        sys.stdout.write(f"[seed] {plan_name} -> plan_id={plan_id} (alias={alias})\n")
        plan_ids[plan_name] = {"id": plan_id, "alias": alias, "planFile": plan_key}
    PLAN_IDS_FILE.write_text(json.dumps(plan_ids, indent=2, sort_keys=True) + "\n")
    sys.stdout.write(f"[seed] plan IDs written to {PLAN_IDS_FILE}\n")
    return 0
