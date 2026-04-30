from __future__ import annotations

import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

from . import ofcs, runner
from .paths import BASELINES_DIR, PLAN_IDS_FILE, ROOT

# Each OFCS test plan demands a different OP security profile (PAR,
# JARM, alg constraints). The OP runs one profile per process, so the
# baseline driver restarts it between plans rather than chasing a
# single-config compromise that fails 2/3 plans by construction.
_PLAN_PROFILE: dict[str, str] = {
    "oidcc-basic-certification-test-plan": "basic",
    "fapi2-security-profile-id2-test-plan": "fapi2-baseline",
    "fapi2-message-signing-id1-test-plan": "fapi2-message-signing",
}

_DISCOVERY_URL = "https://127.0.0.1:9443/.well-known/openid-configuration"


def _git(*args: str) -> str:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(ROOT), *args],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return out.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return "unknown"


def _wait_discovery(timeout: float = 30.0) -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(_DISCOVERY_URL, method="GET")
            with urllib.request.urlopen(req, timeout=2.0, context=ctx) as resp:
                if resp.status == 200:
                    return True
        except Exception:  # pragma: no cover - network race; just retry
            pass
        time.sleep(1)
    return False


def _restart_op(profile: str) -> None:
    """Stop the OP and bring it up again under the given profile.

    Profiles are mapped in _PLAN_PROFILE; an empty string drops back to
    OIDC Core (no PAR / JARM). Discovery is polled to make sure the new
    listener is serving before the plan resumes.
    """
    sys.stdout.write(f"[baseline] restarting OP with profile={profile or 'basic'}\n")
    script = str(ROOT / "scripts" / "conformance.sh")
    subprocess.run(["bash", script, "op-down"], check=False)
    env = {**os.environ, "OP_PROFILE": profile}
    subprocess.run(["bash", script, "op-up"], check=True, env=env)
    if not _wait_discovery():
        raise RuntimeError("OP discovery did not become reachable after restart")


def cmd_baseline(label: str = "snapshot") -> int:
    if not PLAN_IDS_FILE.exists():
        sys.stderr.write(
            f"[baseline] {PLAN_IDS_FILE} not found — run "
            f"`scripts/conformance.sh seed-plans` first\n"
        )
        return 1
    BASELINES_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y-%m-%dT%H-%M-%SZ", time.gmtime())
    out_file = BASELINES_DIR / f"{stamp}-{label}.json"
    sha = _git("rev-parse", "HEAD")
    branch = _git("rev-parse", "--abbrev-ref", "HEAD")
    snapshot: dict[str, Any] = {
        "schema": "go-oidc-provider/baseline/v1",
        "label": label,
        "captured_at": stamp,
        "git": {"sha": sha, "branch": branch},
        "plans": {},
    }
    plan_filter = os.environ.get("BASELINE_PLAN_FILTER", "")
    module_filter = os.environ.get("BASELINE_FILTER", "")
    skip_restart = os.environ.get("BASELINE_NO_RESTART", "0") == "1"
    plan_ids = json.loads(PLAN_IDS_FILE.read_text())
    for plan_name in sorted(plan_ids.keys()):
        if plan_filter and not re.search(plan_filter, plan_name):
            continue
        plan_id = plan_ids[plan_name]["id"]
        sys.stdout.write(f"\n==== plan {plan_name} (id={plan_id}) ====\n")
        if not skip_restart:
            profile = _PLAN_PROFILE.get(plan_name, "")
            _restart_op(profile)
        modules = ofcs.plan_modules(plan_id)
        if module_filter:
            modules = [m for m in modules if re.search(module_filter, m)]
        if not modules:
            sys.stdout.write(f"[baseline] no modules returned for plan {plan_name}; skipping\n")
            continue
        plan_entry: dict[str, Any] = {"plan_id": plan_id, "modules": {}}
        snapshot["plans"][plan_name] = plan_entry
        for m in modules:
            sys.stdout.write(f"---- {m} ----\n")
            out = runner.run_one(plan_id, m)
            sys.stdout.write(f"result={out.status}/{out.result} ({out.elapsed_ms}ms)\n")
            plan_entry["modules"][m] = {
                "status": out.status,
                "result": out.result,
                "runner_id": out.runner_id,
                "elapsed_ms": out.elapsed_ms,
            }
            # Persist incrementally so a Ctrl-C mid-run leaves a
            # partial baseline rather than an empty file.
            out_file.write_text(
                json.dumps(snapshot, indent=2, sort_keys=True) + "\n"
            )
    out_file.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
    sys.stdout.write(f"\n[baseline] snapshot written to {out_file}\n")
    _print_totals(snapshot)
    return 0


def _print_totals(snapshot: dict[str, Any]) -> None:
    passed = failed = other = 0
    for plan in snapshot["plans"].values():
        for mod in plan["modules"].values():
            r = mod.get("result") or ""
            if r == "PASSED":
                passed += 1
            elif r in ("FAILED", "WARNING") and mod.get("status") == "FINISHED":
                failed += 1
            else:
                other += 1
    sys.stdout.write(
        f"[baseline] totals: pass={passed} fail={failed} other={other}\n"
    )


def _index(snapshot: dict[str, Any]) -> dict[tuple[str, str], str]:
    out: dict[tuple[str, str], str] = {}
    for plan, body in (snapshot.get("plans") or {}).items():
        for m, info in (body.get("modules") or {}).items():
            out[(plan, m)] = info.get("result") or ""
    return out


def cmd_baseline_diff(old_path: str, new_path: str) -> int:
    old = json.loads(Path(old_path).read_text())
    new = json.loads(Path(new_path).read_text())
    old_idx = _index(old)
    new_idx = _index(new)
    keys = sorted(set(old_idx) | set(new_idx))
    regressions: list[tuple[tuple[str, str], str, str]] = []
    fixes: list[tuple[tuple[str, str], str, str]] = []
    new_only: list[tuple[tuple[str, str], str]] = []
    dropped: list[tuple[tuple[str, str], str]] = []
    churn: list[tuple[tuple[str, str], str, str]] = []
    for k in keys:
        o = old_idx.get(k)
        n = new_idx.get(k)
        if o == n:
            continue
        if o == "PASSED" and n != "PASSED":
            regressions.append((k, o, n or ""))
        elif o != "PASSED" and n == "PASSED":
            fixes.append((k, o or "", n))
        elif o is None:
            new_only.append((k, n or ""))
        elif n is None:
            dropped.append((k, o))
        else:
            churn.append((k, o, n))

    def fmt(k: tuple[str, str], *vals: str) -> str:
        plan, m = k
        return f"  [{plan}] {m}: " + " -> ".join(v or "(absent)" for v in vals)

    sys.stdout.write(f"old: {old_path}  ({old.get('captured_at','?')})\n")
    sys.stdout.write(f"new: {new_path}  ({new.get('captured_at','?')})\n\n")
    sys.stdout.write(f"regressions: {len(regressions)}\n")
    for k, o, n in regressions:
        sys.stdout.write(fmt(k, o, n) + "\n")
    sys.stdout.write(f"fixes: {len(fixes)}\n")
    for k, o, n in fixes:
        sys.stdout.write(fmt(k, o, n) + "\n")
    if churn:
        sys.stdout.write(f"non-pass churn: {len(churn)}\n")
        for k, o, n in churn:
            sys.stdout.write(fmt(k, o, n) + "\n")
    if new_only or dropped:
        sys.stdout.write(
            f"catalog drift: added={len(new_only)} removed={len(dropped)}\n"
        )
    return 1 if regressions else 0
