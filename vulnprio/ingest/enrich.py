"""Build a vulnerability-intelligence snapshot (NVD + EPSS + KEV) for a list of CVEs.

The snapshot is saved as CSV so the dashboard runs offline and results are
reproducible (the snapshot date is stored with every row).
"""
from __future__ import annotations

from datetime import date
from pathlib import Path

import pandas as pd

from .epss import fetch_epss
from .kev import load_kev
from .nvd import fetch_cve, parse_cve


def build_snapshot(cve_ids: list[str], out_path: Path, refresh: bool = False,
                   nvd_lookup: dict[str, dict] | None = None) -> pd.DataFrame:
    """Fetch metadata for CVEs not yet in the snapshot and save it.

    nvd_lookup: optional {cve_id: parsed_record} (e.g. from the ML dataset)
    used before calling the NVD API, to save requests.
    """
    existing = pd.read_csv(out_path) if out_path.exists() and not refresh else pd.DataFrame()
    have = set(existing["cve_id"]) if not existing.empty else set()
    missing = sorted(set(cve_ids) - have)

    rows = []
    for cve_id in missing:
        rec = (nvd_lookup or {}).get(cve_id)
        if rec is None:
            raw = fetch_cve(cve_id)
            rec = parse_cve(raw) if raw else {"cve_id": cve_id}
        rows.append(rec)
        print(f"  NVD {cve_id}: CVSS {rec.get('cvss_score')} {rec.get('attack_vector')}")

    df = pd.concat([existing, pd.DataFrame(rows)], ignore_index=True) if rows else existing
    all_ids = df["cve_id"].tolist()

    epss = fetch_epss(all_ids)
    kev = load_kev()
    df["epss"] = df["cve_id"].map(lambda c: epss.get(c, {}).get("epss"))
    df["epss_percentile"] = df["cve_id"].map(lambda c: epss.get(c, {}).get("percentile"))
    df["in_kev"] = df["cve_id"].isin(kev)
    df["kev_date_added"] = df["cve_id"].map(lambda c: kev.get(c, {}).get("dateAdded"))
    df["kev_ransomware"] = df["cve_id"].map(
        lambda c: kev.get(c, {}).get("knownRansomwareCampaignUse"))
    df["snapshot_date"] = date.today().isoformat()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)
    return df
