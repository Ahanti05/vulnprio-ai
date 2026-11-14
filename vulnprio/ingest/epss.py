"""FIRST EPSS API client. Docs: https://www.first.org/epss/api"""
from __future__ import annotations

from .http import get_json

EPSS_URL = "https://api.first.org/data/v1/epss"


def fetch_epss(cve_ids: list[str], batch: int = 80) -> dict[str, dict]:
    """Return {cve_id: {"epss": float, "percentile": float, "date": str}}."""
    result: dict[str, dict] = {}
    ids = sorted(set(cve_ids))
    for i in range(0, len(ids), batch):
        chunk = ids[i:i + batch]
        data = get_json(EPSS_URL, params={"cve": ",".join(chunk)})
        for row in data.get("data", []):
            result[row["cve"]] = {
                "epss": float(row["epss"]),
                "percentile": float(row["percentile"]),
                "date": row.get("date"),
            }
    return result
