"""Refresh the NVD/EPSS/KEV snapshot for every CVE in a findings file.

Usage:
    python scripts/fetch_intel.py                      # sample data
    python scripts/fetch_intel.py --data data/mydata   # your own data folder
    python scripts/fetch_intel.py --refresh            # re-download everything
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vulnprio.config import ML_DATA_DIR, SAMPLE_DIR  # noqa: E402
from vulnprio.ingest.enrich import build_snapshot  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(SAMPLE_DIR))
    ap.add_argument("--refresh", action="store_true")
    args = ap.parse_args()

    data_dir = Path(args.data)
    cves = pd.read_csv(data_dir / "findings.csv")["cve_id"].dropna().unique().tolist()

    # Reuse records already downloaded for the ML dataset, if present.
    lookup = {}
    parts = sorted((ML_DATA_DIR / "parts").glob("*.csv.gz"))
    if parts:
        ml = pd.concat([pd.read_csv(p) for p in parts], ignore_index=True)
        ml = ml[ml["cve_id"].isin(cves)]
        lookup = {r["cve_id"]: r for r in ml.to_dict("records")}

    df = build_snapshot(cves, data_dir / "cve_intel.csv", refresh=args.refresh, nvd_lookup=lookup)
    print(f"Saved {len(df)} CVE records, {int(df['in_kev'].sum())} in KEV -> {data_dir / 'cve_intel.csv'}")


if __name__ == "__main__":
    main()
