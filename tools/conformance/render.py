from __future__ import annotations

import os
import pathlib
import shutil
import struct
import subprocess
import zlib

_CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
]


def detect_chrome() -> str | None:
    """Return a usable Chrome/Chromium binary path, or None."""
    explicit = os.environ.get("CHROME_BIN")
    if explicit and os.access(explicit, os.X_OK):
        return explicit
    for cand in _CHROME_CANDIDATES:
        if os.access(cand, os.X_OK):
            return cand
    for name in ("google-chrome", "chromium", "chromium-browser"):
        path = shutil.which(name)
        if path:
            return path
    return None


def render_html_to_png(html: pathlib.Path, png: pathlib.Path) -> bool:
    """Drive headless Chrome to rasterise <html> into <png>.

    Uses file:// so the render is offline and reflects the literal bytes
    the OP returned. Returns False if no Chrome binary was found or the
    invocation failed.
    """
    chrome = detect_chrome()
    if not chrome:
        return False
    cmd = [
        chrome,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--hide-scrollbars",
        "--window-size=1024,768",
        f"--screenshot={png}",
        f"file://{html}",
    ]
    try:
        subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return False
    return png.is_file() and png.stat().st_size > 0


def synth_placeholder_png(png: pathlib.Path, width: int = 640, height: int = 200) -> None:
    """Write a flat light-gray PNG when no Chrome is available.

    Pure stdlib, no PIL — the operator notice surfaces in the OFCS log
    text alongside the image, so we do not bake glyphs into the bytes.
    """

    def _chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data)
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw = b""
    for _ in range(height):
        raw += b"\x00" + bytes((236, 236, 236)) * width
    idat = zlib.compress(raw)
    png.write_bytes(sig + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b""))
