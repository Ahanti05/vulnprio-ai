"""Train the exploit-likelihood model on the NVD + KEV dataset.

Usage:
    python scripts/build_ml_dataset.py   # once, downloads the data
    python scripts/train_model.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vulnprio.config import ML_DATA_DIR, MODELS_DIR  # noqa: E402
from vulnprio.ml.model import ExploitModel  # noqa: E402


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="2021-01-01",
                    help="train on CVEs published before this date, test on/after")
    args = ap.parse_args()
    data = pd.read_csv(ML_DATA_DIR / "nvd_kev_dataset.csv.gz")
    print(f"Loaded {len(data)} CVEs ({data['label_kev'].sum()} known exploited)")
    model = ExploitModel.train(data, split_date=args.split)
    model.save()
    (MODELS_DIR / "metrics.json").write_text(json.dumps(
        {"metrics": model.metrics, "top_features": model.top_features}, indent=2))
    print(json.dumps(model.metrics, indent=2))


if __name__ == "__main__":
    main()
