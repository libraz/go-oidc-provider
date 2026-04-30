from __future__ import annotations

import os
import sys

from . import ofcs, render
from .paths import RENDER_DIR


def _pending_placeholders(runner_id: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for entry in ofcs.log(runner_id):
        placeholder = entry.get("upload") or ""
        if entry.get("result") == "REVIEW" and placeholder:
            out.append((placeholder, entry.get("src", "")))
    return out


def resolve(runner_id: str) -> None:
    """Resolve every pending REVIEW placeholder for a runner.

    Renders the most recently saved login HTML for the runner via
    headless Chrome and uploads the PNG as evidence. With no Chrome
    available, falls back to a synthetic flat-color PNG so the upload
    still completes and OFCS transitions WAITING/REVIEW → FINISHED.
    Set OFCS_REVIEW_SKIP=1 to leave placeholders untouched.
    """
    if os.environ.get("OFCS_REVIEW_SKIP", "0") == "1":
        return
    pending = _pending_placeholders(runner_id)
    if not pending:
        return
    candidates = sorted(
        RENDER_DIR.glob(f"{runner_id}-*.html"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    html = candidates[0] if candidates else None
    for idx, (placeholder, src) in enumerate(pending, start=1):
        png = RENDER_DIR / f"{runner_id}-review-{idx}.png"
        if html and render.render_html_to_png(html, png):
            sys.stdout.write(
                f"[review] rendered {html.name} -> {png.name} "
                f"(placeholder={placeholder} src={src})\n"
            )
        else:
            render.synth_placeholder_png(png)
            reason = "no Chrome" if not render.detect_chrome() else "no HTML"
            sys.stdout.write(
                f"[review] {reason}; uploaded synthetic notice "
                f"(placeholder={placeholder} src={src})\n"
            )
        status = ofcs.upload_image(runner_id, placeholder, png.read_bytes())
        sys.stdout.write(f"[review] upload placeholder={placeholder} http={status}\n")
