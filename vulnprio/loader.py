"""Load and validate the input dataset (assets, network edges, findings, CVE intel)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from .config import CRITICALITY, ENTRY_NODE, EXPOSURE


@dataclass
class Dataset:
    assets: pd.DataFrame
    edges: pd.DataFrame
    findings: pd.DataFrame          # findings merged with CVE intelligence
    issues: list = field(default_factory=list)   # data-quality report


def _to_bool(s: pd.Series) -> pd.Series:
    return s.astype(str).str.strip().str.lower().isin({"true", "1", "yes", "y"})


def load_dataset(data_dir: Path) -> Dataset:
    data_dir = Path(data_dir)
    assets = pd.read_csv(data_dir / "assets.csv")
    edges = pd.read_csv(data_dir / "edges.csv")
    findings = pd.read_csv(data_dir / "findings.csv")
    intel_path = data_dir / "cve_intel.csv"
    intel = pd.read_csv(intel_path) if intel_path.exists() else pd.DataFrame(columns=["cve_id"])
    return prepare_dataset(assets, edges, findings, intel)


def prepare_dataset(assets: pd.DataFrame, edges: pd.DataFrame, findings: pd.DataFrame,
                    intel: pd.DataFrame) -> Dataset:
    """Normalise, deduplicate and validate the raw tables."""
    issues: list[str] = []
    assets = assets.copy()
    edges = edges.copy()
    findings = findings.copy()

    # --- assets -------------------------------------------------------------
    assets["asset_id"] = assets["asset_id"].astype(str).str.strip()
    assets["criticality"] = assets["criticality"].astype(str).str.lower().str.strip()
    assets["exposure"] = assets["exposure"].astype(str).str.lower().str.strip()
    bad_crit = ~assets["criticality"].isin(CRITICALITY)
    if bad_crit.any():
        issues.append(f"{bad_crit.sum()} asset(s) with unknown criticality -> treated as 'medium'")
        assets.loc[bad_crit, "criticality"] = "medium"
    bad_exp = ~assets["exposure"].isin(EXPOSURE)
    if bad_exp.any():
        issues.append(f"{bad_exp.sum()} asset(s) with unknown exposure -> treated as 'internal'")
        assets.loc[bad_exp, "exposure"] = "internal"
    if "crown_jewel" in assets:
        assets["crown_jewel"] = _to_bool(assets["crown_jewel"])
    else:
        assets["crown_jewel"] = assets["criticality"].eq("critical")
    if assets["asset_id"].duplicated().any():
        issues.append("Duplicate asset IDs found -> kept first occurrence")
        assets = assets.drop_duplicates("asset_id")
    known = set(assets["asset_id"])

    # --- edges --------------------------------------------------------------
    edges["source"] = edges["source"].astype(str).str.strip()
    edges["target"] = edges["target"].astype(str).str.strip()
    bad_edges = ~(edges["source"].isin(known | {ENTRY_NODE}) & edges["target"].isin(known))
    if bad_edges.any():
        issues.append(f"{bad_edges.sum()} edge(s) reference unknown assets -> ignored")
        edges = edges[~bad_edges]
    internet_facing = set(edges.loc[edges["source"] == ENTRY_NODE, "target"])
    mismatch = assets[(assets["exposure"] == "internet") != assets["asset_id"].isin(internet_facing)]
    for _, row in mismatch.iterrows():
        issues.append(
            f"Exposure check: {row['asset_id']} is marked '{row['exposure']}' but "
            f"{'has' if row['asset_id'] in internet_facing else 'has no'} edge from {ENTRY_NODE}")

    # --- findings -----------------------------------------------------------
    findings["cve_id"] = findings["cve_id"].astype(str).str.strip().str.upper()
    findings["asset_id"] = findings["asset_id"].astype(str).str.strip()
    before = len(findings)
    findings = findings.drop_duplicates(subset=["asset_id", "cve_id"], keep="first")
    if len(findings) < before:
        issues.append(f"Removed {before - len(findings)} duplicate finding(s) (same asset + CVE)")
    orphan = ~findings["asset_id"].isin(known)
    if orphan.any():
        issues.append(f"{orphan.sum()} finding(s) on unknown assets -> ignored")
        findings = findings[~orphan]
    bad_ids = ~findings["cve_id"].str.match(r"^CVE-\d{4}-\d{4,}$")
    if bad_ids.any():
        issues.append(f"{bad_ids.sum()} finding(s) with malformed CVE IDs -> ignored")
        findings = findings[~bad_ids]

    # --- merge CVE intelligence --------------------------------------------
    findings = findings.merge(intel, on="cve_id", how="left", suffixes=("", "_intel"))
    for col, default in [("cvss_score", None), ("attack_vector", None), ("epss", None),
                         ("epss_percentile", None), ("in_kev", False), ("description", "")]:
        if col not in findings:
            findings[col] = default
    findings["in_kev"] = _to_bool(findings["in_kev"].fillna(False))
    no_cvss = findings["cvss_score"].isna().sum()
    if no_cvss:
        issues.append(f"{no_cvss} finding(s) without CVSS data -> severity marked 'unknown'")
    no_epss = findings["epss"].isna().sum()
    if no_epss:
        issues.append(f"{no_epss} finding(s) without EPSS data -> EPSS marked 'unknown'")

    findings = findings.merge(
        assets[["asset_id", "hostname", "criticality", "exposure", "crown_jewel", "zone"]],
        on="asset_id", how="left")
    return Dataset(assets=assets.reset_index(drop=True), edges=edges.reset_index(drop=True),
                   findings=findings.reset_index(drop=True), issues=issues)
