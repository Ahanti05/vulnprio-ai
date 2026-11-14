"""Download NVD CVEs for a date range and label them with CISA KEV.

Label = 1 if the CVE is in the KEV catalog (known exploited), else 0.
Each 120-day window is saved separately so the download can resume.

Usage:
    python scripts/build_ml_dataset.py --start 2019-01-01 --end 2023-12-31
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vulnprio.config import ML_DATA_DIR  # noqa: E402
from vulnprio.ingest.kev import load_kev  # noqa: E402
from vulnprio.ingest.nvd import date_windows, fetch_window, parse_cve  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", default="2019-01-01")
    ap.add_argument("--end", default="2023-12-31")
    args = ap.parse_args()

    parts_dir = ML_DATA_DIR / "parts"
    parts_dir.mkdir(parents=True, exist_ok=True)
    start = datetime.fromisoformat(args.start)
    end = datetime.fromisoformat(args.end).replace(hour=23, minute=59, second=59)

    for w_start, w_end in date_windows(start, end):
        part = parts_dir / f"nvd_{w_start:%Y%m%d}_{w_end:%Y%m%d}.csv.gz"
        if part.exists():
            print(f"skip {part.name} (already downloaded)")
            continue
        rows = [parse_cve(c) for c in fetch_window(w_start, w_end)]
        pd.DataFrame(rows).to_csv(part, index=False)
        print(f"saved {part.name}: {len(rows)} CVEs", flush=True)

    kev = load_kev()
    df = pd.concat([pd.read_csv(p) for p in sorted(parts_dir.glob("*.csv.gz"))], ignore_index=True)
    df = df.drop_duplicates("cve_id")
    # Rejected CVEs carry no useful signal
    df = df[~df["vuln_status"].fillna("").str.contains("Reject", case=False)]
    df = df[~df["description"].fillna("").str.startswith("** REJECT")]
    df["label_kev"] = df["cve_id"].isin(kev).astype(int)
    out = ML_DATA_DIR / "nvd_kev_dataset.csv.gz"
    df.to_csv(out, index=False)
    print(f"dataset: {len(df)} CVEs, {df['label_kev'].sum()} in KEV -> {out}")


if __name__ == "__main__":
    main()
