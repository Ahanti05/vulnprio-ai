"""NVD CVE API 2.0 client and record parser.

Docs: https://nvd.nist.gov/developers/vulnerabilities
Without an API key NVD allows about 5 requests per 30 seconds, so we wait
6.5 s between calls. Set the NVD_API_KEY environment variable to go faster.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta
from typing import Iterator

from .http import get_json

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _headers() -> dict:
    key = os.getenv("NVD_API_KEY")
    return {"apiKey": key} if key else {}


def _delay() -> float:
    return 0.8 if os.getenv("NVD_API_KEY") else 6.5


def fetch_cve(cve_id: str) -> dict | None:
    """Fetch one CVE record (raw NVD 'cve' object) or None if not found."""
    data = get_json(NVD_URL, params={"cveId": cve_id}, headers=_headers())
    vulns = data.get("vulnerabilities", [])
    time.sleep(_delay())
    return vulns[0]["cve"] if vulns else None


def fetch_window(start: datetime, end: datetime, page_size: int = 2000) -> Iterator[dict]:
    """Yield raw CVE objects published in [start, end] (max 120-day window)."""
    start_index = 0
    while True:
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": page_size,
            "startIndex": start_index,
        }
        data = get_json(NVD_URL, params=params, headers=_headers())
        for item in data.get("vulnerabilities", []):
            yield item["cve"]
        total = data.get("totalResults", 0)
        start_index += page_size
        time.sleep(_delay())
        if start_index >= total:
            break


def date_windows(start: datetime, end: datetime, days: int = 119) -> Iterator[tuple]:
    """Split a long date range into NVD-compatible windows."""
    cur = start
    while cur < end:
        nxt = min(cur + timedelta(days=days), end)
        yield cur, nxt
        cur = nxt + timedelta(seconds=1)


def parse_cve(cve: dict) -> dict:
    """Flatten a raw NVD CVE object into the fields this project uses."""
    metrics = cve.get("metrics", {})
    out = {
        "cve_id": cve.get("id"),
        "published": (cve.get("published") or "")[:10],
        "vuln_status": cve.get("vulnStatus"),
        "description": next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
        ),
        "cvss_version": None, "cvss_score": None, "cvss_vector": None,
        "attack_vector": None, "attack_complexity": None,
        "privileges_required": None, "user_interaction": None, "scope": None,
        "conf_impact": None, "integ_impact": None, "avail_impact": None,
    }

    # Prefer CVSS v3.1 (most common in NVD), then v3.0, v4.0, and finally v2.
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        entries = metrics.get(key) or []
        if entries:
            entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            c = entry["cvssData"]
            out.update(
                cvss_version=c.get("version"), cvss_score=c.get("baseScore"),
                cvss_vector=c.get("vectorString"), attack_vector=c.get("attackVector"),
                attack_complexity=c.get("attackComplexity"),
                privileges_required=c.get("privilegesRequired"),
                user_interaction=c.get("userInteraction"), scope=c.get("scope"),
                conf_impact=c.get("confidentialityImpact") or c.get("vulnConfidentialityImpact"),
                integ_impact=c.get("integrityImpact") or c.get("vulnIntegrityImpact"),
                avail_impact=c.get("availabilityImpact") or c.get("vulnAvailabilityImpact"),
            )
            break
    else:
        entries = metrics.get("cvssMetricV2") or []
        if entries:
            c = entries[0]["cvssData"]
            out.update(
                cvss_version="2.0", cvss_score=c.get("baseScore"),
                cvss_vector=c.get("vectorString"), attack_vector=c.get("accessVector"),
                attack_complexity=c.get("accessComplexity"),
            )

    cwes = sorted({
        d["value"] for w in cve.get("weaknesses", [])
        for d in w.get("description", []) if str(d.get("value", "")).startswith("CWE-")
    })
    out["cwe"] = cwes[0] if cwes else "unknown"

    vendor = product = None
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) > 4 and match.get("vulnerable", True):
                    vendor, product = parts[3], parts[4]
                    break
            if vendor:
                break
        if vendor:
            break
    out["vendor"] = vendor or "unknown"
    out["product"] = product or "unknown"
    return out
