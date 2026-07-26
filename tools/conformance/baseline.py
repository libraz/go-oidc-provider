from __future__ import annotations

import fnmatch
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.request
from datetime import date
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
    "oidcc-config-certification-test-plan": "basic",
    "oidcc-dynamic-certification-test-plan": "basic",
    "oidcc-formpost-basic-certification-test-plan": "basic",
    "oidcc-rp-initiated-logout-certification-test-plan": "basic",
    "oidcc-backchannel-rp-initiated-logout-certification-test-plan": "basic",
    "fapi2-security-profile-id2-test-plan": "fapi2-baseline",
    "fapi2-message-signing-id1-test-plan": "fapi2-message-signing",
    "fapi-ciba-id1-test-plan": "fapi-ciba",
}

_DISCOVERY_URL = "https://127.0.0.1:9443/.well-known/openid-configuration"
_BASELINE_SCHEMA = "go-oidc-provider/baseline/v1"
_EXCLUSIONS_SCHEMA = "go-oidc-provider/conformance-exclusions/v2"

# The results a class-level accepted-outcome rule may cover. FAILED is
# excluded on purpose: a failing module is a specific claim about this
# OP and deserves a specific, individually-owned justification. REVIEW
# and SKIPPED are properties of how the suite is driven — "a human must
# look at this screen", "this module does not apply to the advertised
# configuration" — and they arrive in families of a dozen at a time, so
# a per-module entry for each is boilerplate that rots rather than
# documentation anyone reads. An empty result is covered by neither: a
# module the harness could not drive to a verdict is a gap in the
# harness, and no amount of prose makes it a known-good outcome.
_RULE_RESULTS = ("REVIEW", "SKIPPED")
_DEFAULT_EXCLUSIONS_FILE = ROOT / "conformance" / "release-exclusions.json"


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


class _ReleaseInputError(ValueError):
    """A release-verifier input is malformed or not an approved artifact."""


def _read_json(path: Path, kind: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except OSError as exc:
        raise _ReleaseInputError(f"cannot read {kind} {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise _ReleaseInputError(f"invalid JSON in {kind} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise _ReleaseInputError(f"{kind} {path} must contain a JSON object")
    return value


def _release_index(
    snapshot: dict[str, Any], source: str
) -> dict[tuple[str, str], tuple[str, str]]:
    if snapshot.get("schema") != _BASELINE_SCHEMA:
        raise _ReleaseInputError(f"{source} schema must be {_BASELINE_SCHEMA!r}")
    plans = snapshot.get("plans")
    if not isinstance(plans, dict) or not plans:
        raise _ReleaseInputError(f"{source} has no plans")
    indexed: dict[tuple[str, str], tuple[str, str]] = {}
    for plan_name, plan in plans.items():
        if not isinstance(plan_name, str) or not plan_name:
            raise _ReleaseInputError(f"{source} contains an empty plan name")
        if not isinstance(plan, dict):
            raise _ReleaseInputError(f"{source} plan {plan_name!r} must be an object")
        modules = plan.get("modules")
        if not isinstance(modules, dict) or not modules:
            raise _ReleaseInputError(f"{source} plan {plan_name!r} has no modules")
        for module_name, result in modules.items():
            if not isinstance(module_name, str) or not module_name:
                raise _ReleaseInputError(
                    f"{source} plan {plan_name!r} contains an empty module name"
                )
            if not isinstance(result, dict):
                raise _ReleaseInputError(
                    f"{source} module {plan_name}/{module_name} must be an object"
                )
            status = result.get("status")
            outcome = result.get("result")
            if status is None:
                status = ""
            if outcome is None:
                outcome = ""
            if not isinstance(status, str) or not isinstance(outcome, str):
                raise _ReleaseInputError(
                    f"{source} module {plan_name}/{module_name} has a "
                    "non-string status or result"
                )
            indexed[(plan_name, module_name)] = (status, outcome)
    if not indexed:
        raise _ReleaseInputError(f"{source} has no modules")
    return indexed


def _load_exclusions(
    manifest: dict[str, Any], source: str, as_of: date
) -> tuple[dict[tuple[str, str], tuple[str, str]], list[str]]:
    if manifest.get("schema") != _EXCLUSIONS_SCHEMA:
        raise _ReleaseInputError(
            f"{source} schema must be {_EXCLUSIONS_SCHEMA!r}"
        )
    raw_exclusions = manifest.get("exclusions")
    if not isinstance(raw_exclusions, list):
        raise _ReleaseInputError(f"{source} exclusions must be an array")

    exclusions: dict[tuple[str, str], tuple[str, str]] = {}
    issues: list[str] = []
    required = ("plan", "module", "status", "result", "reason", "owner", "expires")
    for index, exclusion in enumerate(raw_exclusions):
        label = f"{source} exclusions[{index}]"
        if not isinstance(exclusion, dict):
            raise _ReleaseInputError(f"{label} must be an object")
        missing = [field for field in required if field not in exclusion]
        if missing:
            raise _ReleaseInputError(f"{label} is missing {', '.join(missing)}")
        for field in required:
            if not isinstance(exclusion[field], str) or not exclusion[field].strip():
                raise _ReleaseInputError(f"{label}.{field} must be a non-empty string")

        key = (exclusion["plan"], exclusion["module"])
        if key in exclusions:
            raise _ReleaseInputError(
                f"{source} has duplicate exclusion {key[0]}/{key[1]}"
            )
        if exclusion["result"] == "PASSED":
            raise _ReleaseInputError(
                f"{label} cannot exclude a PASSED module"
            )
        try:
            expires = date.fromisoformat(exclusion["expires"])
        except ValueError as exc:
            raise _ReleaseInputError(
                f"{label}.expires must use YYYY-MM-DD"
            ) from exc
        if as_of >= expires:
            issues.append(
                f"expired exclusion [{key[0]}] {key[1]} "
                f"(expired {expires.isoformat()}, owner={exclusion['owner']})"
            )
        exclusions[key] = (exclusion["status"], exclusion["result"])
    return exclusions, issues


class _AcceptedOutcome:
    """One class-level rule admitting a REVIEW / SKIPPED family."""

    __slots__ = ("result", "plan", "module", "owner", "reason")

    def __init__(self, rule: dict[str, Any]) -> None:
        self.result: str = rule["result"]
        self.plan: str = rule.get("plan", "*")
        self.module: str = rule.get("module", "*")
        self.owner: str = rule["owner"]
        self.reason: str = rule["reason"]

    def matches(self, plan: str, module: str, result: str) -> bool:
        return (
            result == self.result
            and fnmatch.fnmatchcase(plan, self.plan)
            and fnmatch.fnmatchcase(module, self.module)
        )

    def label(self) -> str:
        return f"{self.result} [{self.plan}] {self.module}"


def _load_accepted_outcomes(
    manifest: dict[str, Any], source: str, as_of: date
) -> tuple[list[_AcceptedOutcome], list[str]]:
    raw = manifest.get("accepted_outcomes", [])
    if not isinstance(raw, list):
        raise _ReleaseInputError(f"{source} accepted_outcomes must be an array")

    rules: list[_AcceptedOutcome] = []
    issues: list[str] = []
    required = ("result", "reason", "owner", "expires")
    for index, rule in enumerate(raw):
        label = f"{source} accepted_outcomes[{index}]"
        if not isinstance(rule, dict):
            raise _ReleaseInputError(f"{label} must be an object")
        missing = [field for field in required if field not in rule]
        if missing:
            raise _ReleaseInputError(f"{label} is missing {', '.join(missing)}")
        for field in (*required, *(k for k in ("plan", "module") if k in rule)):
            if not isinstance(rule[field], str) or not rule[field].strip():
                raise _ReleaseInputError(f"{label}.{field} must be a non-empty string")
        if rule["result"] not in _RULE_RESULTS:
            raise _ReleaseInputError(
                f"{label}.result must be one of {', '.join(_RULE_RESULTS)}; "
                f"got {rule['result']!r}"
            )
        try:
            expires = date.fromisoformat(rule["expires"])
        except ValueError as exc:
            raise _ReleaseInputError(f"{label}.expires must use YYYY-MM-DD") from exc
        if as_of >= expires:
            issues.append(
                f"expired accepted outcome {rule['result']} "
                f"[{rule.get('plan', '*')}] {rule.get('module', '*')} "
                f"(expired {expires.isoformat()}, owner={rule['owner']})"
            )
        rules.append(_AcceptedOutcome(rule))
    return rules, issues


def _ensure_checked_in(path: Path) -> None:
    try:
        resolved = path.resolve()
        relative = resolved.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise _ReleaseInputError(
            f"exclusion manifest must be inside the repository: {path}"
        ) from exc

    try:
        checked_in = subprocess.check_output(
            ["git", "-C", str(ROOT), "show", f"HEAD:{relative.as_posix()}"],
            stderr=subprocess.DEVNULL,
        )
        current = resolved.read_bytes()
    except (FileNotFoundError, subprocess.CalledProcessError):
        raise _ReleaseInputError(
            f"exclusion manifest is not checked in: {path}"
        ) from None
    except OSError as exc:
        raise _ReleaseInputError(
            f"cannot read exclusion manifest {path}: {exc}"
        ) from exc
    if current != checked_in:
        raise _ReleaseInputError(
            f"exclusion manifest differs from the checked-in HEAD version: {path}"
        )


def _load_unreachable(
    manifest: dict[str, Any], source: str, as_of: date
) -> tuple[dict[tuple[str, str], str], list[str]]:
    """Load the modules that cannot be driven to any verdict at all.

    Deliberately its own section rather than an ordinary exclusion. An
    exclusion says "this OP fails this module, and here is why that is
    acceptable" — a claim about the OP. An entry here says "nobody can
    make this module answer", which is a claim about the harness and a
    much weaker position to ship from. Keeping the two apart means the
    count of modules with no verdict is a number a reader sees rather
    than something buried among sixty rows, and the required evidence
    field forces whoever adds one to record what they actually tried.
    """
    raw = manifest.get("unreachable_verdicts", [])
    if not isinstance(raw, list):
        raise _ReleaseInputError(f"{source} unreachable_verdicts must be an array")

    entries: dict[tuple[str, str], str] = {}
    issues: list[str] = []
    required = ("plan", "module", "status", "reason", "evidence", "owner", "expires")
    for index, entry in enumerate(raw):
        label = f"{source} unreachable_verdicts[{index}]"
        if not isinstance(entry, dict):
            raise _ReleaseInputError(f"{label} must be an object")
        missing = [field for field in required if field not in entry]
        if missing:
            raise _ReleaseInputError(f"{label} is missing {', '.join(missing)}")
        for field in required:
            if not isinstance(entry[field], str) or not entry[field].strip():
                raise _ReleaseInputError(f"{label}.{field} must be a non-empty string")
        key = (entry["plan"], entry["module"])
        if key in entries:
            raise _ReleaseInputError(
                f"{source} has duplicate unreachable verdict {key[0]}/{key[1]}"
            )
        try:
            expires = date.fromisoformat(entry["expires"])
        except ValueError as exc:
            raise _ReleaseInputError(f"{label}.expires must use YYYY-MM-DD") from exc
        if as_of >= expires:
            issues.append(
                f"expired unreachable verdict [{key[0]}] {key[1]} "
                f"(expired {expires.isoformat()}, owner={entry['owner']})"
            )
        entries[key] = entry["status"]
    return entries, issues


def _strict_release_issues(
    reference: dict[tuple[str, str], tuple[str, str]],
    candidate: dict[tuple[str, str], tuple[str, str]],
    exclusions: dict[tuple[str, str], tuple[str, str]],
    accepted: list[_AcceptedOutcome] | None = None,
    unreachable: dict[tuple[str, str], str] | None = None,
) -> list[str]:
    accepted = accepted or []
    unreachable = unreachable or {}
    issues: list[str] = []
    reference_keys = set(reference)
    candidate_keys = set(candidate)
    for plan, module in sorted(candidate_keys - reference_keys):
        issues.append(f"added module [{plan}] {module}")
    for plan, module in sorted(reference_keys - candidate_keys):
        issues.append(f"dropped module [{plan}] {module}")

    matched_exclusions: set[tuple[str, str]] = set()
    matched_rules: set[int] = set()
    matched_unreachable: set[tuple[str, str]] = set()
    for key in sorted(candidate_keys):
        status, result = candidate[key]
        plan, module = key
        if not status or not result:
            expected_status = unreachable.get(key)
            if expected_status is None:
                issues.append(
                    f"no verdict [{plan}] {module}: "
                    f"status={status or '(empty)'} result={result or '(empty)'}"
                )
            elif expected_status != status:
                # The module still has no verdict but got there a
                # different way. Whatever the entry documented is no
                # longer what is happening, so it has to be re-read.
                issues.append(
                    f"unreachable verdict changed shape [{plan}] {module}: "
                    f"expected status {expected_status}, got {status or '(empty)'}"
                )
            else:
                matched_unreachable.add(key)
            continue
        if status == "FINISHED" and result == "PASSED":
            if key in exclusions:
                issues.append(f"stale exclusion for passing module [{plan}] {module}")
            continue
        expected = exclusions.get(key)
        if expected is not None:
            matched_exclusions.add(key)
            if expected != (status, result):
                issues.append(
                    f"exclusion mismatch [{plan}] {module}: "
                    f"expected {expected[0]}/{expected[1]}, got {status}/{result}"
                )
            continue
        # A per-module entry is the strongest claim and is checked
        # first. Falling through to the class rules is what keeps a
        # forty-module REVIEW family from needing forty entries.
        covering = [i for i, rule in enumerate(accepted) if rule.matches(plan, module, result)]
        if covering:
            matched_rules.update(covering)
            continue
        issues.append(f"unexcluded non-pass [{plan}] {module}: {status}/{result}")

    for plan, module in sorted(set(exclusions) - matched_exclusions):
        if (plan, module) not in candidate_keys:
            issues.append(f"exclusion names absent module [{plan}] {module}")
    # A rule that matches nothing is either a leftover from a fixed
    # module or a typo in its glob. Both read as "this family is
    # accounted for" while accounting for nothing, so both are blockers.
    for index, rule in enumerate(accepted):
        if index not in matched_rules:
            issues.append(f"accepted outcome matches no module: {rule.label()}")
    # An unreachable entry that stopped applying is the good news case:
    # the module now answers. It still blocks, because leaving the entry
    # behind would let the module go quiet again unnoticed.
    for plan, module in sorted(set(unreachable) - matched_unreachable):
        issues.append(
            f"unreachable verdict no longer applies [{plan}] {module}: "
            "the module now reaches a result, so the entry must go"
        )
    return issues


def cmd_release_verify(
    reference_path: str,
    candidate_path: str,
    exclusions_path: str | None = None,
    *,
    as_of: date | None = None,
) -> int:
    reference_file = Path(reference_path)
    candidate_file = Path(candidate_path)
    exclusions_file = (
        Path(exclusions_path) if exclusions_path else _DEFAULT_EXCLUSIONS_FILE
    )
    try:
        _ensure_checked_in(exclusions_file)
        reference = _release_index(
            _read_json(reference_file, "reference snapshot"),
            str(reference_file),
        )
        candidate = _release_index(
            _read_json(candidate_file, "candidate snapshot"),
            str(candidate_file),
        )
        manifest = _read_json(exclusions_file, "exclusion manifest")
        today = as_of or date.today()
        exclusions, issues = _load_exclusions(manifest, str(exclusions_file), today)
        accepted, rule_issues = _load_accepted_outcomes(
            manifest, str(exclusions_file), today
        )
        issues.extend(rule_issues)
        unreachable, unreachable_issues = _load_unreachable(
            manifest, str(exclusions_file), today
        )
        issues.extend(unreachable_issues)
    except _ReleaseInputError as exc:
        sys.stderr.write(f"[release-verify] input error: {exc}\n")
        return 2

    issues.extend(
        _strict_release_issues(reference, candidate, exclusions, accepted, unreachable)
    )
    sys.stdout.write(
        f"reference: {reference_file} ({len(reference)} modules)\n"
        f"candidate: {candidate_file} ({len(candidate)} modules)\n"
        f"exclusions: {exclusions_file} "
        f"({len(exclusions)} module entries, {len(accepted)} outcome rules, "
        f"{len(unreachable)} without a reachable verdict)\n"
    )
    if issues:
        sys.stdout.write(f"release blockers: {len(issues)}\n")
        for issue in issues:
            sys.stdout.write(f"  {issue}\n")
        return 1
    sys.stdout.write("release blockers: 0\n")
    sys.stdout.write("[release-verify] strict conformance gate passed\n")
    return 0
