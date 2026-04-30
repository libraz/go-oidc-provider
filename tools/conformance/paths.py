from __future__ import annotations

import os
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONF = ROOT / "conformance"
CERTS = CONF / "certs"
PLANS_DIR = CONF / "plans"
KEYS_DIR = CONF / "keys"
RENDER_DIR = CONF / "render"
BASELINES_DIR = CONF / "baselines"
PLAN_IDS_FILE = CONF / ".plan-ids.json"

OFCS_API = os.environ.get("OFCS_API", "https://localhost:8443")
ISSUER = "https://host.docker.internal:9443"
