"""CISA Known Exploited Vulnerabilities (KEV) catalog loader.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""
from __future__ import annotations

import json
import time

from ..config import CACHE_DIR
from .http import get_json

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE = CACHE_DIR / "kev.json"


def load_kev(max_age_hours: float = 24.0, offline: bool = False) -> dict[str, dict]:
    """Return {cve_id: kev_entry}. Uses a local cache to avoid repeat downloads."""
    fresh = KEV_CACHE.exists() and (time.time() - KEV_CACHE.stat().st_mtime) < max_age_hours * 3600
    if not fresh and not offline:
        data = get_json(KEV_URL)
        KEV_CACHE.parent.mkdir(parents=True, exist_ok=True)
        KEV_CACHE.write_text(json.dumps(data))
    if not KEV_CACHE.exists():
        raise FileNotFoundError("KEV cache missing; run without offline=True once.")
    data = json.loads(KEV_CACHE.read_text())
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}
