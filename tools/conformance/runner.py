from __future__ import annotations

import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from . import drive, ofcs, review, variants
from .paths import ISSUER


@dataclass
class ModuleOutcome:
    runner_id: str = ""
    status: str = ""
    result: str = ""
    elapsed_ms: int = 0
    error: str = ""


def _drive_flags_for(module: str) -> dict[str, str]:
    flags = {
        "OFCS_DRIVE_REJECT": "1" if "user-rejects-authentication" in module else "0",
        "OFCS_DRIVE_DOUBLE_VISIT": "1"
        if "reused-request-uri-prior-to-auth-completion" in module
        else "0",
    }
    return flags


def _ciba_mode_for(module: str) -> str:
    """Pick the op-demo CIBA test-mode override for a fapi-ciba module.

    Most modules drive the happy-flow shape (auto-approve after the
    short delay). Two modules need device-side outcomes op-demo cannot
    derive from the request itself:

    * user-rejects-authentication — operator denies on the device, the
      OP must surface access_denied at the next /token poll.
    * multiple-call-to-token-endpoint — OFCS asserts on several
      authorization_pending polls before approval; the default 15 s
      delay is too short, so the wrapper switches to a longer one.

    Anything else returns "approve" so a stale "reject" left over from
    a previous module cannot leak into the next one.
    """
    if "fapi-ciba" not in module:
        return ""
    if "user-rejects-authentication" in module:
        return "reject"
    if "multiple-call-to-token-endpoint" in module:
        return "slow"
    return "approve"


# _CIBA_MODE_URL is the absolute URL the op-demo CIBA test-mode
# handler is mounted at. The runner.py process runs on the host (the
# OFCS server is the Docker side of this setup), so we hit the OP via
# 127.0.0.1 rather than the host.docker.internal alias the plan files
# use — host.docker.internal is a Docker Desktop convenience and is
# not guaranteed to resolve from a plain host shell.
#
# OFCS_OP_PORT lets a custom -listen flag on op-demo override the
# default 9443; ISSUER's port is parsed for the same reason so the
# values stay in sync without a second source of truth.
_CIBA_MODE_URL = (
    "https://127.0.0.1:" + ISSUER.rsplit(":", 1)[-1].rstrip("/") + "/_test/ciba-mode"
)


def _set_ciba_mode(mode: str) -> None:
    """POST mode to op-demo's /_test/ciba-mode endpoint.

    The op-demo binary terminates TLS with a self-signed cert so the
    Python client deliberately disables verification — this URL is the
    runner-side control channel, not an RP credential, and the plan
    server already pins the same listener via the trust store mounted
    into the OFCS docker container. Network failures are logged but do
    not abort the run: a stale mode means the test will fail loudly,
    which is more useful than silently skipping it.
    """
    if not mode:
        return
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        _CIBA_MODE_URL,
        data=mode.encode("ascii"),
        method="POST",
        headers={"Content-Type": "text/plain"},
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            resp.read()
    except urllib.error.URLError as e:
        sys.stdout.write(f"[runner] failed to set ciba mode {mode!r}: {e}\n")


def _make_drive_opts(runner_id: str) -> drive.DriveOptions:
    from http.cookiejar import CookieJar

    return drive.DriveOptions(
        user=os.environ.get("OFCS_DEMO_USER", "demo"),
        password=os.environ.get("OFCS_DEMO_PASS", "demo"),
        runner_id=runner_id,
        cookies=CookieJar(),
        reject=os.environ.get("OFCS_DRIVE_REJECT", "0") == "1",
        double_visit=os.environ.get("OFCS_DRIVE_DOUBLE_VISIT", "0") == "1",
    )


def run_one(plan: str, module: str) -> ModuleOutcome:
    """Drive one OFCS module to a terminal state.

    Returns ModuleOutcome with empty runner_id and `error` populated only
    when OFCS rejected the create-runner call. The poll loop is unified:
    every iteration drives any new URLs OFCS exposes AND watches for
    REVIEW placeholders / log idleness, so multi-step tests with
    embedded sleeps (par-attempt-to-use-expired-request_uri's 60s TTL,
    refresh-token's WaitFor30Seconds × 2) keep moving without bailing.
    """
    out = ModuleOutcome()
    saved_env = {k: os.environ.get(k) for k in ("OFCS_DRIVE_REJECT", "OFCS_DRIVE_DOUBLE_VISIT")}
    os.environ.update(_drive_flags_for(module))
    _set_ciba_mode(_ciba_mode_for(module))
    try:
        variant = variants.select(module, plan)
        start_ms = int(time.time() * 1000)
        resp = ofcs.create_runner(module, plan, variant)
        rid = (resp or {}).get("id", "")
        if not rid:
            out.status = "ERROR"
            out.result = (str(resp) or "")[:200]
            out.error = "create_runner returned no id"
            return out
        out.runner_id = rid
        opts = _make_drive_opts(rid)
        driven: set[str] = set()
        resolved: set[str] = set()
        prev_log = 0
        info: dict[str, object] = {}
        # Per-test wall-clock budget. WaitFor30Seconds × 2 = 60s,
        # request_uri TTL = 60s, plus driver overhead -- 240s is generous.
        # The bound is wall-clock (not iteration count) so that a slow
        # drive HTTP call or a stuck OFCS WAITING state cannot eat into
        # the next test's budget and cascade INTERRUPTED across the plan.
        deadline_ms = start_ms + 240_000
        idle_break_ms = 90_000
        last_progress_ms = start_ms
        while True:
            now_ms = int(time.time() * 1000)
            if now_ms >= deadline_ms:
                sys.stdout.write("  [runner] wall-clock deadline reached; abandoning test\n")
                break
            info = ofcs.info(rid)
            status = str(info.get("status") or "")
            if status in ("FINISHED", "INTERRUPTED"):
                break

            # Drive any URLs OFCS has exposed since the last tick.
            state = ofcs.runner_state(rid)
            urls = (state.get("browser") or {}).get("urls") or []
            for url in urls:
                if url in driven:
                    continue
                sys.stdout.write("  -> driving step URL\n")
                try:
                    drive.drive(url, opts)
                except Exception as e:  # pragma: no cover - drive is best-effort
                    sys.stdout.write(f"  drive error: {e}\n")
                driven.add(url)

            # Resolve any REVIEW placeholders we haven't uploaded for yet.
            # Some tests (par-attempt-to-use-expired-request_uri, refresh-
            # token's WaitFor30Seconds) emit the placeholder long after
            # creation, so we check every tick instead of gating on a
            # one-shot idle threshold.
            log = ofcs.log(rid)
            if status == "WAITING":
                pending_new = [
                    e.get("upload")
                    for e in log
                    if e.get("result") == "REVIEW"
                    and e.get("upload")
                    and e.get("upload") not in resolved
                ]
                if pending_new:
                    review.resolve(rid)
                    for placeholder in pending_new:
                        resolved.add(placeholder)
                    last_progress_ms = int(time.time() * 1000)

            cur_log = len(log)
            if cur_log != prev_log:
                prev_log = cur_log
                last_progress_ms = int(time.time() * 1000)
            elif int(time.time() * 1000) - last_progress_ms >= idle_break_ms:
                # 90s of wall-clock idleness means the test really is
                # stuck -- typically waiting for a manual UI step the
                # driver cannot satisfy. Bail rather than burn the rest
                # of the 240s budget waiting for nothing.
                sys.stdout.write(
                    f"  [runner] idle {idle_break_ms // 1000}s with no log progress; abandoning\n"
                )
                break
            time.sleep(1)
        out.status = str(info.get("status") or "")
        out.result = str(info.get("result") or "")
        out.elapsed_ms = int(time.time() * 1000) - start_ms
        return out
    finally:
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def cmd_batch(plan: str, modules: list[str]) -> int:
    pass_n = fail_n = skip_n = err_n = stuck_n = 0
    stuck: list[str] = []
    for m in modules:
        sys.stdout.write(f"\n==== {m} ====\n")
        out = run_one(plan, m)
        if out.error:
            sys.stdout.write(f"[batch] could not start {m}: {out.result}\n")
            err_n += 1
            continue
        sys.stdout.write(f"id={out.runner_id}\n")
        sys.stdout.write(f"result={out.status}/{out.result}\n")
        key = f"{out.status}/{out.result}"
        if key.endswith("/PASSED"):
            pass_n += 1
        elif not out.result:
            # The module never reached a verdict: the runner abandoned it
            # on the idle or wall-clock bound. Counting these as skips
            # reads as "not applicable", which is exactly wrong — a
            # module the harness could not drive is a gap in the harness,
            # and it has to be visible to be fixed.
            stuck_n += 1
            stuck.append(f"{m} ({out.status or 'no status'})")
        elif key.endswith("/SKIPPED") or key.endswith("/REVIEW") or key.endswith("/WARNING"):
            skip_n += 1
        else:
            fail_n += 1
    sys.stdout.write(
        f"\n==== summary: pass={pass_n} skip={skip_n} fail={fail_n} "
        f"stuck={stuck_n} err={err_n} ====\n"
    )
    for m in stuck:
        sys.stdout.write(f"  stuck (no verdict): {m}\n")
    return 0
